package com.oviva.telematik.vau.httpclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import com.oviva.telematik.vau.httpclient.internal.ConnectionFactory;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("e2e")
class ConnectionFactoryTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void establishVauTunnel() {

    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    //    var vauUri = URI.create("http://localhost:8081/VAU");

    TrustValidator naiveValidator =
        (X509Certificate a, X509Certificate b, List<X509Certificate> c, byte[] d) ->
            new TrustValidator.ValidationResult(true, null, null);

    var tvf = mock(ConnectionFactory.SignedPublicKeysTrustValidatorFactory.class);

    var cf =
        new ConnectionFactory(JavaHttpClient.from(HttpClient.newHttpClient()), "Test/0.0.1", tvf);
    var httpClient = cf.connect(vauUri);

    var res =
        httpClient.call(
            new com.oviva.telematik.vau.httpclient.HttpClient.Request(
                URI.create("/epa/authz/v1/getNonce"),
                "GET",
                List.of(
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "host", "e4a-rt15931.deine-epa.de"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "accept", "application/json"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "x-insurantid", "Z987654321"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "x-useragent", "Oviva/0.0.1")),
                null));
    assertEquals(200, res.status());
  }
}
