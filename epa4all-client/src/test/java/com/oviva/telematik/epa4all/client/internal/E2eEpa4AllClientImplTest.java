package com.oviva.telematik.epa4all.client.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetSocketAddress;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("e2e")
class E2eEpa4AllClientImplTest {

  private static final String KONNEKTOR_PROXY_HOST = "127.0.0.1";
  private static final int KONNEKTOR_PROXY_PORT = 3128;

  @Test
  void writeDocument() {

    System.setProperty("jdk.httpclient.HttpClient.log", "errors,requests,headers");

    try (var cf =
        Epa4AllClientFactory.newFactory(
            TestKonnektors.riseKonnektor_RU(),
            new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT),
            false)) {

      // Oviva RISE FdV
      final var insurantId = "X110661675";

      var client = cf.newClient();

      var document = ExportFixture.buildFhirDocument(client.authorInstitution(), insurantId);
      assertDoesNotThrow(() -> client.writeDocument(insurantId, document));
    }
  }
}
