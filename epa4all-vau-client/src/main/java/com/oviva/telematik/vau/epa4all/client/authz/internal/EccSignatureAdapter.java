package com.oviva.telematik.vau.epa4all.client.authz.internal;

import com.oviva.epa.client.KonnektorService;
import com.oviva.epa.client.model.SmcbCard;
import java.security.cert.X509Certificate;

// TODO: unused at the moment
public class EccSignatureAdapter {

  private final KonnektorService konnektorService;
  private final SmcbCard card;

  public EccSignatureAdapter(KonnektorService konnektorService, SmcbCard card) {
    this.konnektorService = konnektorService;
    this.card = card;
  }

  public X509Certificate authCertificate() {
    return card.authEccCertificate();
  }

  public byte[] authSign(byte[] bytesToSign) {
    return konnektorService.authSignEcdsa(card.handle(), bytesToSign);
  }
}
