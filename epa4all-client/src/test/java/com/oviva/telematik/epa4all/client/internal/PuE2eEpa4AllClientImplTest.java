package com.oviva.telematik.epa4all.client.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetSocketAddress;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("e2e")
class PuE2eEpa4AllClientImplTest {

  private static final String KONNEKTOR_PROXY_HOST = "127.0.0.1";
  private static final int KONNEKTOR_PROXY_PORT = 3128;

  @Test
  void writeDocument() {

    System.setProperty("jdk.httpclient.HttpClient.log", "errors,requests,headers");

    try (var cf =
        Epa4AllClientFactoryBuilder.newBuilder()
            .konnektorProxyAddress(
                new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT))
            .konnektorService(ProdKonnektors.riseKonnektor_PU())
            .environment(Environment.PU)
            .useInsecureTrustManager() // Use a proper one!
            .build()) {

      // Oviva RISE FdV
      // KVNR: U387245341 Stefan Mielitz
      final var insurantId = "U903747974";

      var client = cf.newClient();

      var document = ExportFixture.buildFhirDocument(client.authorInstitution(), insurantId);
      assertDoesNotThrow(() -> client.writeDocument(insurantId, document));
    }
  }
}
