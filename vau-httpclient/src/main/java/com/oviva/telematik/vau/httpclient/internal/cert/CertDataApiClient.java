package com.oviva.telematik.vau.httpclient.internal.cert;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.oviva.telematik.vau.httpclient.HttpClient;
import com.oviva.telematik.vau.httpclient.VauClientException;
import de.gematik.vau.lib.exceptions.VauProtocolException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertDataApiClient {

  private static final Logger log = LoggerFactory.getLogger(CertDataApiClient.class);

  private final TrustValidator trustValidator;
  private final CBORMapper mapper = new CBORMapper();
  private final HttpClient outerHttpClient;

  public CertDataApiClient(HttpClient outerHttpClient, TrustValidator trustValidator) {
    this.trustValidator = trustValidator;
    this.outerHttpClient = outerHttpClient;
  }

  public boolean isTrusted(URI endpoint, byte[] certHash, int cdv, byte[] ocspResponseDer) {

    // https://download.tsl.ti-dienste.de/

    var data = fetch(endpoint, certHash, cdv);

    // https://download-test.tsl.ti-dienste.de/
    // https://download.tsl.ti-dienste.de/
    var ca = parseDerCertificate(data.ca());
    var cert = parseDerCertificate(data.cert());
    var chain = data.rcaChain().stream().map(CertDataApiClient::parseDerCertificate).toList();

    dumpOcsp(ocspResponseDer);

    // TODO remove
    if (log.isDebugEnabled()) {
      dumpAsPEM(data);
    }

    var r = trustValidator.validate(cert, ca, chain, ocspResponseDer);
    if (!r.trusted()) {
      log.atDebug().log("VAU certificate untrusted: {}", r.message());
    }
    return r.trusted();
  }

  private void dumpOcsp(byte[] ocspResponseDer) {
    try {
      Files.write(Path.of("ocsp.der"), ocspResponseDer);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private void dumpAsPEM(CertData data) {
    writeCertificatesToFile("ca.pem", List.of(data.ca()));
    writeCertificatesToFile("cert.pem", List.of(data.cert()));
    writeCertificatesToFile("chain.pem", data.rcaChain());
  }

  private void writeCertificatesToFile(String name, List<byte[]> certificates) {

    try (var fout = Files.newBufferedWriter(Path.of(name));
        var w = new PemWriter(fout)) {
      for (byte[] cert : certificates) {
        var pemObject = new PemObject("CERTIFICATE", cert);
        w.writeObject(pemObject);
      }

    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public CertData fetch(URI endpoint, byte[] certHash, int cdv) {
    var hex = HexFormat.of();
    var certIdentifier = "%s-%d".formatted(hex.formatHex(certHash), cdv);
    var certEndpoint = endpoint.resolve("/CertData.%s".formatted(certIdentifier));
    var res = outerHttpClient.call(new HttpClient.Request(certEndpoint, "GET", List.of(), null));
    if (res.status() != 200) {
      throw new VauClientException(
          "invalid code %d, expected 200: GET %s".formatted(res.status(), certEndpoint));
    }
    try {
      return mapper.readValue(res.body(), CertData.class);
    } catch (IOException e) {
      throw new VauClientException("invalid response body: GET %s".formatted(certEndpoint), e);
    }
  }

  private static X509Certificate parseDerCertificate(byte[] certBytes) {
    try (var certInputStream = new ByteArrayInputStream(certBytes)) {
      var certFactory = CertificateFactory.getInstance("X.509");
      var cert = certFactory.generateCertificate(certInputStream);
      if (cert instanceof X509Certificate x509Cert) {
        return x509Cert;
      }
      throw new VauProtocolException(
          "VAU channel certificate is not an X.509 certificate, got: %s".formatted(cert.getType()));
    } catch (IOException | CertificateException e) {
      throw new VauProtocolException("failed to parse VAU channel certificate", e);
    }
  }
}
