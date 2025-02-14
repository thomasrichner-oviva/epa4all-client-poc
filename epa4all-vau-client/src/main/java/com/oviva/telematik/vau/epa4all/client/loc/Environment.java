package com.oviva.telematik.vau.epa4all.client.loc;

public enum Environment {
  RU1("ref"),
  RU2("dev"),
  TEST("test"),
  PROD("prod");
  private final String thirdLevelDomain;

  Environment(String thirdLevelDomain) {
    this.thirdLevelDomain = thirdLevelDomain;
  }

  public String thirdLevelDomain() {
    return thirdLevelDomain;
  }
}
