package com.oviva.telematik.vau.httpclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
import java.net.URI;
import java.security.Security;
import java.time.Duration;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

class VauHttpClientBuilderTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void testStatus() {

    //    var vauUri = URI.create("http://localhost:8081/VAU");
    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    //    var vauUri = URI.create("https://epa-as-2.dev.epa4all.de/VAU"); // Bitmarck RU

    // connect VAU tunnel (unauthenticated)
    var client =
        VauClientFactoryBuilder.newBuilder()
            .xUserAgent("TEST/1.0.0-12")
            .outerClient(
                JavaHttpClient.from(
                    java.net.http.HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(5))
                        .build()))
            .trustValidator(
                (certificate, issuerCa, certificateChain, ocspResponseDer) ->
                    new TrustValidator.ValidationResult(true, null, null))
            .isPu(false)
            .build();

    var conn = client.connect(vauUri);

    // get status
    var statusRes = conn.call(new HttpClient.Request(URI.create("/VAU-Status"), "GET", null, null));
    assertEquals(200, statusRes.status());

    // authenticate VAU tunnel
    // spec: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.37.0/#7.3

    var nonceRes =
        conn.call(
            new HttpClient.Request(
                URI.create("/epa/authz/v1/getNonce"),
                "GET",
                List.of(
                    new HttpClient.Header("host", "e4a-rt15931.deine-epa.de"),
                    //                    new HttpClient.Header("x-insurantid", "Z987654321"),
                    new HttpClient.Header("accept", "application/json")),
                null));
    System.out.println(nonceRes);

    assertEquals(200, nonceRes.status());
    assertNotNull(nonceRes.body());
  }
}
