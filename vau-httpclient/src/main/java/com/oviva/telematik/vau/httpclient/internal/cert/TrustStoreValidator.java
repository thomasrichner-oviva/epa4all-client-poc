package com.oviva.telematik.vau.httpclient.internal.cert;

import com.oviva.telematik.vau.httpclient.VauClientException;
import de.gematik.vau.lib.exceptions.VauException;
import de.gematik.vau.lib.exceptions.VauProtocolException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustStoreValidator implements TrustValidator {

  private static final String JCE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
  private static final String TRUSTSTORE_PASSWORD = "1234";
  private static final Logger log = LoggerFactory.getLogger(TrustStoreValidator.class);

  private final KeyStore rootCertificates;

  public TrustStoreValidator(KeyStore rootCertificates) {
    this.rootCertificates = rootCertificates;
  }

  @Override
  public boolean validate(
      X509Certificate vauInstanceCertificate,
      X509Certificate vauIssuerCertificate,
      List<X509Certificate> certificateChain,
      byte[] ocspResponseDer) {

    try {
      var intermediates = new CollectionCertStoreParameters(certificateChain);

      var target = new X509CertSelector();
      target.setCertificate(vauInstanceCertificate);

      var params = new PKIXBuilderParameters(rootCertificates, target);
      params.addCertStore(CertStore.getInstance("Collection", intermediates));

      // TODO?
      //      params.setRevocationEnabled(false);

      /* TODO: CRLs?
          CertStoreParameters revoked = new CollectionCertStoreParameters(crls);
      params.addCertStore(CertStore.getInstance("Collection", revoked));
           */
      try {
        var builder = CertPathBuilder.getInstance("PKIX", JCE_PROVIDER);

        // TODO
        var revocationChecker = (PKIXRevocationChecker) builder.getRevocationChecker();
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
        revocationChecker.setOcspResponses(Map.of(vauInstanceCertificate, ocspResponseDer));

        var result = (PKIXCertPathBuilderResult) builder.build(params);
        log.atDebug().log(
            "certificate '{}' verified with trust anchor: '{}'",
            vauInstanceCertificate.getSubjectX500Principal().getName(),
            result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName());
      } catch (CertPathBuilderException e) {
        throw new VauClientException("failed to validate VAU server certificate", e);
      } catch (NoSuchProviderException e) {
        throw new VauException(
            "unable to find %s java.security provider, needed for certificate validation"
                .formatted(JCE_PROVIDER),
            e);
      }

    } catch (NoSuchAlgorithmException | KeyStoreException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
    return true;
  }

  private KeyStore loadTrustStore(String name) {

    try {
      var trustStore = KeyStore.getInstance("PKCS12", JCE_PROVIDER);
      trustStore.load(this.getClass().getResourceAsStream(name), TRUSTSTORE_PASSWORD.toCharArray());
      if (trustStore.size() == 0) {
        throw new VauProtocolException("no truststore found at %s".formatted(name));
      }
      return trustStore;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new RuntimeException("failed to load trust store", e);
    } catch (NoSuchProviderException e) {
      throw new VauException("missing JCE provider %s".formatted(JCE_PROVIDER), e);
    }
  }

  private List<X509Certificate> readAllCertificatesFromTrustStore(KeyStore trustStore) {

    try {
      var certificates = new ArrayList<X509Certificate>();
      var aliases = trustStore.aliases();
      while (aliases.hasMoreElements()) {
        var alias = aliases.nextElement();
        certificates.add((X509Certificate) trustStore.getCertificate(alias));
      }
      return certificates;
    } catch (KeyStoreException e) {
      throw new IllegalStateException("failed to read trust-store certificate", e);
    }
  }
}
