package com.oviva.telematik.vau.epa4all.client.authz.internal;

import com.oviva.epa.client.KonnektorService;
import com.oviva.epa.client.model.PinStatus;
import com.oviva.epa.client.model.SmcbCard;
import com.oviva.telematik.vau.epa4all.client.Epa4AllClientException;
import com.oviva.telematik.vau.epa4all.client.authz.RsaSignatureService;

public class RsaSignatureAdapter implements RsaSignatureService {

  private final KonnektorService konnektorService;

  public RsaSignatureAdapter(KonnektorService konnektorService) {
    this.konnektorService = konnektorService;
  }

  @Override
  public byte[] authSign(SmcbCard card, byte[] bytesToSign) {
    if (konnektorService.verifySmcPin(card.handle()) != PinStatus.VERIFIED) {
      throw new Epa4AllClientException(
          "PIN not verified: %s (%s)".formatted(card.holderName(), card.handle()));
    }
    return konnektorService.authSignRsaPss(card.handle(), bytesToSign);
  }
}
