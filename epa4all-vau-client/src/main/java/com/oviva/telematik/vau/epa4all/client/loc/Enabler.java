package com.oviva.telematik.vau.epa4all.client.loc;

public enum Enabler {
  IBM("1"),
  BITMARCK("2");
  private final String number;

  Enabler(String number) {
    this.number = number;
  }

  public String number() {
    return number;
  }
}
