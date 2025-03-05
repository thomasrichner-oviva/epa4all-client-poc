package com.oviva.telematik.vau.epa4all.client.providers;

import com.oviva.epa.client.model.SmcbCard;

public interface RsaSignatureService {

  byte[] authSign(SmcbCard card, byte[] bytesToSign);
}
