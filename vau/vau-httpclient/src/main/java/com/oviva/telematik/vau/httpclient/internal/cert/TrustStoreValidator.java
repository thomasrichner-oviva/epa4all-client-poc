package com.oviva.telematik.vau.httpclient.internal.cert;

import static org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_admission;
import static org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;

import de.gematik.vau.lib.exceptions.VauException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TrustStoreValidator implements TrustValidator {

  private static final String JCE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
  private static final Logger log = LoggerFactory.getLogger(TrustStoreValidator.class);

  private static final ASN1ObjectIdentifier OID_EPA_VAU =
      new ASN1ObjectIdentifier("1.2.276.0.76.4.209");

  // for test/mock purposed
  static Clock clock;

  // A_24624-01/1
  private static final Duration ocspResponseAge = Duration.ofHours(24);

  private final KeyStore rootCertificates;

  public TrustStoreValidator(KeyStore rootCertificates) {
    this.rootCertificates = rootCertificates;
  }

  @Override
  public ValidationResult validate(
      X509Certificate vauInstanceCertificate,
      X509Certificate vauIssuerCertificate,
      List<X509Certificate> certificateChain,
      byte[] ocspResponseDer) {

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24624-01
    try {

      verifyEndUserCertificate(vauInstanceCertificate, vauIssuerCertificate, certificateChain);
      verifyOcspResponse(
          vauInstanceCertificate, vauIssuerCertificate, certificateChain, ocspResponseDer);
      verifyRole(vauInstanceCertificate);

    } catch (ValidationException e) {
      return new ValidationResult(false, e.getMessage(), e);
    }
    return new ValidationResult(true, null, null);
  }

  private void verifyEndUserCertificate(
      X509Certificate vauInstanceCertificate,
      X509Certificate vauIssuerCertificate,
      List<X509Certificate> certificateChain)
      throws ValidationException {
    var instanceIntermediates =
        Stream.concat(Stream.of(vauIssuerCertificate), certificateChain.stream()).toList();
    verifyTrustChainAgainstRoot(vauInstanceCertificate, instanceIntermediates);
  }

  private void verifyRole(X509Certificate endUserCertificate) throws ValidationException {
    try {
      var asn1Admission =
          new X509CertificateHolder(endUserCertificate.getEncoded())
              .getExtensions()
              .getExtensionParsedValue(id_isismtt_at_admission);

      var admissionInstance = AdmissionSyntax.getInstance(asn1Admission);

      var contents = admissionInstance.getContentsOfAdmissions();
      if (contents.length != 1) {
        throw new ValidationException(
            "expected exactly one admission content, got %d".formatted(contents.length));
      }

      var content = contents[0];
      var profInfos = content.getProfessionInfos();
      if (profInfos.length != 1) {
        throw new ValidationException(
            "expected exactly one profession info, got %d".formatted(profInfos.length));
      }

      var profInfo = profInfos[0];

      var oids = profInfo.getProfessionOIDs();
      if (oids.length != 1) {
        throw new ValidationException(
            "expected exactly one profession oid, got %d".formatted(oids.length));
      }

      var oid = oids[0];

      if (!oid.equals(OID_EPA_VAU)) {
        throw new ValidationException("expected OID %s, got %s".formatted(OID_EPA_VAU, oid));
      }

    } catch (IOException | CertificateEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  private void verifyTrustChainAgainstRoot(
      X509Certificate endUserCertificate, List<X509Certificate> certificateChain)
      throws ValidationException {

    try {
      var intermediates = new CollectionCertStoreParameters(certificateChain);

      var target = new X509CertSelector();
      target.setCertificate(endUserCertificate);

      var params = new PKIXBuilderParameters(rootCertificates, target);
      params.addCertStore(CertStore.getInstance("Collection", intermediates));

      // we'll check the OCSP/CRL response separately
      params.setRevocationEnabled(false);

      try {
        var builder = CertPathBuilder.getInstance("PKIX", JCE_PROVIDER);

        var result = (PKIXCertPathBuilderResult) builder.build(params);
        log.atDebug().log(
            "certificate '{}' verified with trust anchor: '{}'",
            endUserCertificate.getSubjectX500Principal().getName(),
            result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName());
      } catch (CertPathBuilderException e) {
        var name = endUserCertificate.getSubjectX500Principal().getName();
        throw new ValidationException(
            "failed to validate VAU server certificate, bad certificate: " + name, e);
      }

    } catch (NoSuchProviderException
        | NoSuchAlgorithmException
        | KeyStoreException
        | InvalidAlgorithmParameterException e) {
      throw new VauException("unexpected crypto exception", e);
    }
  }

  private void verifyOcspResponse(
      X509Certificate vauInstanceCertificate,
      X509Certificate vauIssuerCertificate,
      List<X509Certificate> certificateChain,
      byte[] ocspResponseDer)
      throws ValidationException {

    if (ocspResponseDer == null || ocspResponseDer.length == 0) {
      throw new ValidationException("empty OCSP response");
    }

    // can we trust the issuer of the OCSP response?
    verifyTrustChainAgainstRoot(vauIssuerCertificate, certificateChain);

    var ocspResp = toOcspResponse(ocspResponseDer);
    if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
      throw new ValidationException(
          "invalid OCSP response status: %d".formatted(ocspResp.getStatus()), null);
    }

    var basicOcspResp = getBasicOcspResp(ocspResp);

    // is the OCSP response valid?
    verifyOcspResponseSignature(vauIssuerCertificate, basicOcspResp);
    verifyOcspResponseAge(basicOcspResp);

    // has exactly one response?
    var responses = basicOcspResp.getResponses();
    if (responses.length != 1) {
      throw new ValidationException("expected 1 OCSP response, got %d".formatted(responses.length));
    }
    var response = responses[0];

    // status for our cert good?
    if (response.getCertStatus() != CertificateStatus.GOOD) {
      throw new ValidationException(
          "invalid OCSP response certificate status: %s".formatted(response.getCertStatus()));
    }

    verifyCertHash(vauInstanceCertificate, response);
  }

  void verifyOcspResponseAge(BasicOCSPResp ocspResponse) throws ValidationException {
    var now = clock.instant();

    var producedAt = ocspResponse.getProducedAt().toInstant();

    if (Duration.between(producedAt, now).compareTo(ocspResponseAge) > 0) {
      throw new ValidationException("OCSP response too old");
    }
  }

  /** Verifies teh cert hash of the parameterized OCSP Response against the certificate. */
  private void verifyCertHash(X509Certificate endUserCertificate, SingleResp ocspResponseEntry)
      throws ValidationException {
    try {
      var singleOcspRespAsn1 =
          ocspResponseEntry.getExtension(id_isismtt_at_certHash).getParsedValue();
      var ocspCertHashBytes = CertHash.getInstance(singleOcspRespAsn1).getCertificateHash();
      var eeCertHashBytes = sha256(endUserCertificate.getEncoded());

      if (!MessageDigest.isEqual(ocspCertHashBytes, eeCertHashBytes)) {
        throw new ValidationException("ocsp cert hash does not match end user cert hash");
      }
    } catch (CertificateEncodingException e) {
      throw new ValidationException("invalid end user certificate", e);
    }
  }

  private static byte[] sha256(byte[] bytes) {
    try {
      var md = MessageDigest.getInstance("SHA-256");
      return md.digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new VauException("SHA-256 not supported", e);
    }
  }

  protected void verifyOcspResponseSignature(
      X509Certificate vauIssuerCertificate, BasicOCSPResp ocspResponse) throws ValidationException {
    try {
      var cvp =
          new JcaContentVerifierProviderBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(vauIssuerCertificate.getPublicKey());
      if (!ocspResponse.isSignatureValid(cvp)) {
        throw new ValidationException("invalid OCSP response signature");
      }
    } catch (final OCSPException | OperatorCreationException e) {
      throw new ValidationException("error validating OCSP response", e);
    }
  }

  public static OCSPResp toOcspResponse(byte[] ocspResponseDer) {
    try {
      return new OCSPResp(ocspResponseDer);
    } catch (IOException e) {
      throw new RuntimeException("failed to decode OCSP response", e);
    }
  }

  public static BasicOCSPResp getBasicOcspResp(OCSPResp ocspResponse) {
    try {
      return (BasicOCSPResp) ocspResponse.getResponseObject();
    } catch (OCSPException e) {
      throw new RuntimeException("failed to decode OCSP response", e);
    }
  }

  private static class ValidationException extends Exception {
    public ValidationException(String message) {
      super(message);
    }

    public ValidationException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
