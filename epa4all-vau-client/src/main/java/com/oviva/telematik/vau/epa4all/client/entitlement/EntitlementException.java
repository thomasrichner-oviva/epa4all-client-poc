package com.oviva.telematik.vau.epa4all.client.entitlement;

import com.oviva.telematik.vau.epa4all.client.Epa4AllClientException;

public class EntitlementException extends Epa4AllClientException {
  public EntitlementException(String message) {
    super(message);
  }

  public EntitlementException(String message, Throwable cause) {
    super(message, cause);
  }
}
