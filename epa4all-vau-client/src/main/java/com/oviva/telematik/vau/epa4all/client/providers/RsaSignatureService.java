package com.oviva.telematik.vau.epa4all.client.providers;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.cert.X509Certificate;
import java.util.List;

public interface RsaSignatureService {

  List<Card> getCards();

  byte[] authSign(@NonNull String cardHandle, byte[] bytesToSign);

  record Card(String handle, X509Certificate certificate, boolean pinVerified) {}
}
