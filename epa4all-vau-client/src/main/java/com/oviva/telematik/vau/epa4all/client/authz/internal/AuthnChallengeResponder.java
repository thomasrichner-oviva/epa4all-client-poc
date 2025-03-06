package com.oviva.telematik.vau.epa4all.client.authz.internal;

import com.nimbusds.jose.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.oviva.telematik.vau.epa4all.client.authz.AuthorizationException;
import com.oviva.telematik.vau.epa4all.client.authz.RsaSignatureService;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.net.URI;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthnChallengeResponder {

  private final RsaSignatureService rsaSignatureService;
  private final Logger log = LoggerFactory.getLogger(AuthnChallengeResponder.class);

  public AuthnChallengeResponder(RsaSignatureService rsaSignatureService) {
    this.rsaSignatureService = rsaSignatureService;
  }

  public record Response(URI issuer, String response) {}

  public Response challengeResponse(String challenge) {

    // A_20663-01
    var parsedChallenge = parseAndValidateChallenge(challenge);

    // A_20665-01
    var jweResponse = encryptAndSignChallenge(parsedChallenge);

    var iss = issuerUriFromChallenge(parsedChallenge);
    return new Response(iss, jweResponse.serialize());
  }

  private URI issuerUriFromChallenge(SignedJWT challenge) {
    try {
      return URI.create(challenge.getJWTClaimsSet().getIssuer());
    } catch (ParseException e) {
      throw new AuthorizationException("failed to parse challenge issuer", e);
    }
  }

  private SignedJWT parseAndValidateChallenge(String challenge) {
    // A_20663-01

    var parsedChallenge = parseChallenge(challenge);

    // TODO: validate signature of challenge A_20663-01
    try {
      var claims = parsedChallenge.getJWTClaimsSet();
      var iss = claims.getIssuer();

    } catch (ParseException e) {
      throw new AuthorizationException("failed to verify challenge signature", e);
    }

    return parsedChallenge;
  }

  private SignedJWT parseChallenge(String challenge) {
    try {
      var parsedChallenge = SignedJWT.parse(challenge);
      return validateChallengeTypeAndClaims(parsedChallenge);
    } catch (BadJOSEException | ParseException e) {
      throw new AuthorizationException("challenge is not a valid JWT", e);
    }
  }

  private SignedJWT validateChallengeTypeAndClaims(SignedJWT challenge)
      throws BadJOSEException, ParseException {

    var challengeTypeVerifier = new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT);

    var challengeClaimsVerifier =
        new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder().claim("response_type", "code").build(),
            Set.of(JWTClaimNames.ISSUED_AT, JWTClaimNames.ISSUER, JWTClaimNames.EXPIRATION_TIME));

    challengeTypeVerifier.verify(challenge.getHeader().getType(), null);
    challengeClaimsVerifier.verify(challenge.getJWTClaimsSet(), null);
    return challenge;
  }

  public JWEObject encryptAndSignChallenge(@NonNull SignedJWT challenge) {
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_Dienst/gemSpec_IDP_Dienst_V1.7.0/#7.3

    var expiry = expiryFromChallengeBody(challenge);
    var payload = signChallenge(challenge.serialize());

    try {

      // TODO: fetch from discovery
      // RU: https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration
      // PU: https://idp.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration

      // https://gemspec.gematik.de/docs/gemILF/gemILF_PS_ePA/gemILF_PS_ePA_V3.2.3/#A_20667-02
      // WTF? Brainpool curves?
      var idpEncKey =
          BP256ECKey.parse(
              """
                          {
                            "kid": "puk_idp_enc",
                            "use": "enc",
                            "kty": "EC",
                            "crv": "BP-256",
                            "x": "pkU8LlTZsoGTloO7yjIkV626aGtwpelJ2Wrx7fZtOTo",
                            "y": "VliGWQLNtyGuQFs9nXbWdE9O9PFtxb42miy4yaCkCi8"
                          }
                      """);

      // ePA deployment:
      // curl https://idp-ref.app.ti-dienste.de/.well-known/openid-configuration
      // curl https://idp-ref.app.ti-dienste.de/certs

      var pub = idpEncKey.toECPublicKey(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

      // extra hoops for BP256 signing
      var encrypter = new BP256ECDHEncrypter(pub);
      encrypter
          .getJCAContext()
          .setProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

      // https://datatracker.ietf.org/doc/html/draft-yusef-oauth-nested-jwt-03
      var jwe = nestAsJwe(payload, expiry);
      jwe.encrypt(encrypter);

      debugLogChallengeJwe(jwe);

      return jwe;
    } catch (JOSEException | ParseException e) {
      throw new AuthorizationException("TODO", e);
    }
  }

  private JWEObject nestAsJwe(@NonNull JOSEObject nested, @NonNull Instant exp) {

    var alg = JWEAlgorithm.ECDH_ES;
    var enc = EncryptionMethod.A256GCM;
    // https://datatracker.ietf.org/doc/html/draft-yusef-oauth-nested-jwt-03
    var jweHeader =
        new JWEHeader.Builder(alg, enc)
            .contentType("NJWT")
            .customParam("exp", exp.getEpochSecond())
            .build();
    var jweBody = new Payload(Map.of("njwt", nested.serialize()));
    return new JWEObject(jweHeader, jweBody);
  }

  private void debugLogChallengeJwe(JWEObject jwe) {
    if (!log.isDebugEnabled()) {
      return;
    }
    log.atDebug()
        // header was updated with ephemeral key
        .addKeyValue("header", jwe.getHeader().toString())
        .addKeyValue("payload", jwe.getPayload().toString())
        .log("encrypting nested challenge");
  }

  private Instant expiryFromChallengeBody(SignedJWT challenge) {

    try {
      var challengeClaims = challenge.getJWTClaimsSet();
      if (challengeClaims == null) {
        throw new AuthorizationException("empty challenge claims");
      }
      var challengeExp = challengeClaims.getExpirationTime();
      if (challengeExp == null) {
        throw new AuthorizationException("challenge without expiry");
      }
      return challengeExp.toInstant();
    } catch (ParseException e) {
      throw new AuthorizationException("failed to parse challenge expiry claim", e);
    }
  }

  private SignedJWT signChallenge(String challenge) {
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_Dienst/gemSpec_IDP_Dienst_V1.7.0/#7.3
    try {
      var claims = new JWTClaimsSet.Builder().claim("njwt", challenge).build();

      var cert = rsaSignatureService.authCertificate();

      var header =
          // FUTURE: use ECC instead
          new JWSHeader.Builder(JWSAlgorithm.PS256)
              .type(JOSEObjectType.JWT)
              .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
              .contentType("NJWT")
              .build();

      var jwt = new SignedJWT(header, claims);

      var signer = new SmcBSigner(rsaSignatureService);
      jwt.sign(signer);

      debugLogSignedChallenge(challenge, jwt);

      return jwt;
    } catch (JOSEException | ParseException | CertificateEncodingException e) {
      throw new AuthorizationException("failed to sign challenge", e);
    }
  }

  private void debugLogSignedChallenge(String challenge, SignedJWT jwt) throws ParseException {
    if (!log.isDebugEnabled()) {
      return;
    }

    var principal = rsaSignatureService.authCertificate().getSubjectX500Principal().getName();
    var header = jwt.getHeader().toString();
    var payload = JSONObjectUtils.toJSONString(jwt.getJWTClaimsSet().toJSONObject());
    log.atDebug()
        .addKeyValue("principal", principal)
        .addKeyValue("challenge", challenge)
        .addKeyValue("header", header)
        .addKeyValue("payload", payload)
        .addKeyValue("jwt", jwt.serialize())
        .log(
            "signed challenge\nprincipal: {}\nchallenge: {}\nheader\n===\n{}\n===\npayload\n===\n{}\n===\njwt\n===\n{}\n===\n",
            principal,
            challenge,
            header,
            payload,
            jwt.serialize());
  }
}
