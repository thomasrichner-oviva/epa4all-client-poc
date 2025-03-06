package com.oviva.telematik.vau.epa4all.client.authz.internal;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.util.Set;
import java.util.stream.Collectors;

public class SmcBSigner implements JWSSigner {

  private final Signer signer;

  public SmcBSigner(Signer signer) {
    this.signer = signer;
  }

  @Override
  public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {

    var alg = header.getAlgorithm();
    var supported = supportedJWSAlgorithms();
    if (!supported.contains(alg)) {
      throw new JOSEException(
          "unsupported alg '%s', supported: %s"
              .formatted(
                  alg,
                  supported.stream().map(JWSAlgorithm::getName).collect(Collectors.joining(" "))));
    }

    var signed = signer.sign(header, signingInput);
    return Base64URL.encode(signed);
  }

  @Override
  public Set<JWSAlgorithm> supportedJWSAlgorithms() {
    // For clientAttest could use "ES256" with actual "BS256R1" algo!
    // still is VERY wrong, but is what is 'intended'
    return Set.of(JWSAlgorithm.PS256);
  }

  @Override
  public JCAContext getJCAContext() {
    throw new UnsupportedOperationException();
  }

  public interface Signer {
    byte[] sign(JWSHeader header, byte[] signingInput);
  }
}
