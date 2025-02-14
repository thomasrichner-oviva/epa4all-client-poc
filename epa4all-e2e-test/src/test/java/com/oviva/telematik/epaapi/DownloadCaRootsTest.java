package com.oviva.telematik.epaapi;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;

class DownloadCaRootsTest {

  // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#5.1
  private static final String ROOTS_URL_TEST = "https://download-test.tsl.ti-dienste.de/ROOT-CA/";
  private static final String ROOTS_URL_PU = "https://download.tsl.ti-dienste.de/ROOT-CA/";

  @Test
  void downloadTrustedCertificatesTEST() {

    var trustStorePath = Path.of("root-ca-test.p12");
    updateKeystore(trustStorePath, ROOTS_URL_TEST);
  }

  @Test
  void downloadTrustedCertificatesPU() {

    var trustStorePath = Path.of("root-ca-pu.p12");
    updateKeystore(trustStorePath, ROOTS_URL_PU);
  }

  private void updateKeystore(Path trustStorePath, String url) {

    var certificates =
        scrapeRootCertificateUrls(url).stream()
            .map(DownloadCaRootsTest::downloadCertificate)
            .toList();

    var ts = createTruststore(certificates);
    saveTruststore(trustStorePath, ts);
  }

  private static X509Certificate downloadCertificate(CertUrl certUrl) {
    return parseCertificate(downloadBytes(certUrl.url()));
  }

  private List<CertUrl> scrapeRootCertificateUrls(String directoryUrl) {

    try {
      var doc = Jsoup.connect(directoryUrl).get();
      return doc.body().select("a").stream()
          .filter(e -> !e.text().isBlank())
          .filter(e -> e.text().endsWith(".der"))
          .map(e -> new CertUrl(e.text(), e.attr("abs:href")))
          .toList();
    } catch (IOException e) {
      throw new RuntimeException("failed to scrape certificates", e);
    }
  }

  private static X509Certificate parseCertificate(byte[] rawDer) {

    try {
      var certificateFactory = CertificateFactory.getInstance("X.509");
      return (X509Certificate)
          certificateFactory.generateCertificate(new ByteArrayInputStream(rawDer));
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  private void saveTruststore(Path trustStorePath, KeyStore trustStore) {
    try (var fout = Files.newOutputStream(trustStorePath)) {
      trustStore.store(fout, "1234".toCharArray());
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
      throw new RuntimeException("failed to save truststore", e);
    }
  }

  private KeyStore createTruststore(List<X509Certificate> certificates) {
    try {
      var trustStore = KeyStore.getInstance("PKCS12");
      trustStore.load(null, null);

      for (X509Certificate certificate : certificates) {
        trustStore.setCertificateEntry(
            certificate.getSubjectX500Principal().getName(), certificate);
      }

      return trustStore;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] downloadBytes(String url) {
    try (var client = HttpClient.newHttpClient()) {
      var res =
          client.send(
              HttpRequest.newBuilder(URI.create(url)).build(),
              HttpResponse.BodyHandlers.ofByteArray());
      assertEquals(200, res.statusCode());
      return res.body();
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    return new byte[0];
  }

  record CertUrl(String name, String url) {}
}
