package com.oviva.telematik.vau.epa4all.client.loc;

import java.net.URI;

public class EndpointLocalization {

  private final Environment environment;
  private final Enabler enabler;

  public EndpointLocalization(Environment environment, Enabler enabler) {
    this.environment = environment;
    this.enabler = enabler;
  }

  public URI baseUriInformationService() {

    // A_24592-02
    return URI.create(
        "https://epa-as-%s.%s.epa4all.de"
            .formatted(enabler.number(), environment.thirdLevelDomain()));
  }

  public URI baseUriInformationServiceAccounts() {

    // A_24592-02
    return URI.create(
        "https://epa-asisa-%s.%s.epa4all.de"
            .formatted(enabler.number(), environment.thirdLevelDomain()));
  }
}
