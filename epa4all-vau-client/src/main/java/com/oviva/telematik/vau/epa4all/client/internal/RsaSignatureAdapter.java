package com.oviva.telematik.vau.epa4all.client.internal;

import com.oviva.epa.client.KonnektorService;
import com.oviva.epa.client.model.PinStatus;
import com.oviva.telematik.vau.epa4all.client.providers.RsaSignatureService;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;

public class RsaSignatureAdapter implements RsaSignatureService {

  private final KonnektorService konnektorService;

  public RsaSignatureAdapter(KonnektorService konnektorService) {
    this.konnektorService = konnektorService;
  }

  @Override
  public List<Card> getCards() {
    return konnektorService.getCardsInfo().stream()
        .filter(ci -> ci.type() == com.oviva.epa.client.model.Card.CardType.SMC_B)
        .map(
            ci -> {
              var status = konnektorService.verifySmcPin(ci.handle());
              var cert = konnektorService.readAuthenticationCertificateForCard(ci.handle());
              return new Card(ci.handle(), cert, status == PinStatus.VERIFIED);
            })
        .toList();
  }

  @Override
  public byte[] authSign(@NonNull String cardHandle, byte[] bytesToSign) {
    return konnektorService.authSignRsaPss(cardHandle, bytesToSign);
  }
}
