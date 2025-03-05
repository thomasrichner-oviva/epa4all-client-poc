package com.oviva.telematik.vau.epa4all.client.internal;

import com.oviva.epa.client.KonnektorService;
import com.oviva.epa.client.model.SmcbCard;
import com.oviva.telematik.vau.epa4all.client.providers.RsaSignatureService;

// TODO
public class EccSignatureAdapter implements RsaSignatureService {

  private final KonnektorService konnektorService;

  public EccSignatureAdapter(KonnektorService konnektorService) {
    this.konnektorService = konnektorService;
  }

  @Override
  public byte[] authSign(SmcbCard card, byte[] bytesToSign) {
    return konnektorService.authSignEcdsa(card.handle(), bytesToSign);
  }
}
