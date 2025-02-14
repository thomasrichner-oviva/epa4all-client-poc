package com.oviva.telematik.vau.epa4all.client.loc;

import org.junit.jupiter.api.Test;

class EndpointLocalizationTest {

  @Test
  void t() {
    var sut = new EndpointLocalization(Environment.RU2, Enabler.BITMARCK);
    var uri = sut.baseUriInformationService().resolve("/.well-known/openid-configuration");
    System.out.println(uri);

    var epaConf = "/.well-known/epa-configuration.json";
    uri = sut.baseUriInformationService().resolve(epaConf);
    System.out.println(uri);
  }
}
