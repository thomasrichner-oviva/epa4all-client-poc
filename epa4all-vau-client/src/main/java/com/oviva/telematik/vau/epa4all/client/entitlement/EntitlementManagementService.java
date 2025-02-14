package com.oviva.telematik.vau.epa4all.client.entitlement;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.oviva.telematik.vau.epa4all.client.internal.SmcBSigner;
import com.oviva.telematik.vau.epa4all.client.providers.RsaSignatureService;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class EntitlementManagementService {

  private final RsaSignatureService rsaSignatureService;

  public EntitlementManagementService(RsaSignatureService rsaSignatureService) {
    this.rsaSignatureService = rsaSignatureService;
  }

  public void registerEntitlement(String insurantId) {

    /**
     * Content for PS originated entitlements: protected_header contains: "typ": "JWT" "alg":
     * "ES256" or "PS256" "x5c": signature certificate (C.HCI.AUT from smc-b of requestor) payload
     * claims: "iat": issued at timestamp "exp": expiry timestamp (always iat + 20min)
     * "auditEvidence": proof-of-audit received from VSDM Service ('Prüfziffer des VSDM
     * Prüfungsnachweises') signature contains token signature
     */
  }

  private JWT createEntitlement() {

    var iat = Instant.now();
    var validity = Duration.ofMinutes(20);
    var exp = iat.plus(validity);

    var claims =
        new JWTClaimsSet.Builder()
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("auditEvidence", "1234567890") // TODO?
            .build();

    var card = rsaSignatureService.getCards().get(0);

    try {
      var x5c = Base64.encode(card.certificate().getEncoded());
      var header =
          // TODO: use ES256 but with the brainpoolP256r curve
          // this is not according to the official RFC, this is the intended way for this use-case
          // though ¯\_(ツ)_/¯
          new JWSHeader.Builder(JWSAlgorithm.PS256)
              .type(JOSEObjectType.JWT)
              .x509CertChain(List.of(x5c))
              .build();

      var jwt = new SignedJWT(header, claims);

      var signer = signerForCard(card.handle());

      jwt.sign(signer);

      return jwt;
    } catch (CertificateEncodingException | JOSEException e) {
      throw new EntitlementException("failed to sign entitlement", e);
    }
  }

  private JWSSigner signerForCard(String cardHandle) {
    return new SmcBSigner(
        (h, c) -> {
          if (JWSAlgorithm.PS256.equals(h.getAlgorithm())) {
            return rsaSignatureService.authSign(cardHandle, c);
          }

          // we don't support ECC yet
          throw new UnsupportedOperationException(
              "unsupperted algorithm %s for signing with SMC-B".formatted(h.getAlgorithm()));
        });
  }
}
