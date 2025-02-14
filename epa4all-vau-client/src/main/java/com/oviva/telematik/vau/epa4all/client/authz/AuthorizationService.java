package com.oviva.telematik.vau.epa4all.client.authz;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.oviva.telematik.vau.epa4all.client.authz.internal.*;
import com.oviva.telematik.vau.epa4all.client.internal.*;
import com.oviva.telematik.vau.epa4all.client.providers.RsaSignatureService;
import com.oviva.telematik.vau.httpclient.HttpClient;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * see <a href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_FD/latest/#5.5">here</a>.
 *
 * <p>Authorization with a smartcard (SMC-B) equipped client of a health care institution and login
 * to a health record system.
 *
 * <p>This authorization method addresses the central smartcard IDP. A successful login provides an
 * ID-Token and causes an authorized epa user session for the health care institution allowing
 * access to several health records on demand.
 *
 * <p>Client Attestation The authorization flow uses client attestation to guarantee a match of IDP
 * issued ID-Token and the user's identity of the authenticated clients.
 *
 * <p>A client first retrieves a nonce value from the authorization service. The nonce is signed
 * with the clients SMC-B and becomes the client attestation. In a final sendAuthCodeSC operation
 * the client attestation is compared by the authorization service with the issued nonce value and
 * attestation telematik-id matching ID-Token telematik-id is verified.
 */
public class AuthorizationService {

  private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

  private static final JWSAlgorithm JWS_ALG_BS256R1 = new JWSAlgorithm("BP256R1");

  private final URI baseUri;
  private final HttpClient innerHttpClient;
  private final java.net.http.HttpClient outerHttpClient;
  private final RsaSignatureService rsaSignatureService;

  public AuthorizationService(
      HttpClient innerHttpClient,
      java.net.http.HttpClient outerHttpClient,
      URI baseUri,
      RsaSignatureService rsaSignatureService) {
    this.baseUri = baseUri;
    this.innerHttpClient = innerHttpClient;
    this.outerHttpClient = outerHttpClient;
    this.rsaSignatureService = rsaSignatureService;
  }

  public void authorizeVauWithSmcB(String insurantId) {

    var nonceRes = getNonce(insurantId);
    var nonce = nonceRes.nonce();

    var authRes = sendAuthorizationRequestSmcB(insurantId);

    // A_20663-01
    var parsedChallenge = parseAndValidateChallenge(authRes.challenge());

    // A_20665-01
    var cards = rsaSignatureService.getCards();

    var card =
        cards.stream().findFirst().orElseThrow(() -> new AuthorizationException("no SMC-B found"));

    if (!card.pinVerified()) {
      throw new AuthorizationException(
          "SMC-B PIN is not verified, handle: %s".formatted(card.handle()));
    }

    var encryptedSignedChallenge = encryptAndSignChallenge(card, parsedChallenge);

    URI idpBaseUri = null;
    try {
      idpBaseUri = URI.create(parsedChallenge.getJWTClaimsSet().getIssuer());
    } catch (ParseException e) {
      throw new AuthorizationException("failed to read iss claim from challenge_token", e);
    }
    var authorizationCode = exchangeEncryptedSignedChallenge(idpBaseUri, encryptedSignedChallenge);

    var signedClientAttest = attestClient(card, nonce).serialize();

    if (log.isDebugEnabled()) {
      log.atDebug().log(
          "signed nonce\nauthorizationCode\n===\n{}\n===\n\nclientAttest\n===\n{}\n===\n",
          authorizationCode,
          signedClientAttest);
    }

    sendAuthorizationCodeSmbC(authorizationCode, signedClientAttest, insurantId);
  }

  private AuthorizationRequestResponse sendAuthorizationRequestSmcB(String insurantId) {

    var path = "/epa/authz/v1/send_authorization_request_sc";
    var uri = baseUri.resolve(path);
    var method = "GET";
    var req =
        new HttpClient.Request(
            uri, method, List.of(new HttpClient.Header("x-insurantid", insurantId)), null);

    var res = innerHttpClient.call(req);
    if (res.status() != 302) {
      throw new IllegalStateException(
          "unexpected status '%s %s' %d".formatted(method, path, res.status()));
    }
    var location = parseLocationHeader(res);
    // TODO: check error in redirect URI

    return followRedirect(location);
  }

  private URI parseLocationHeader(HttpClient.Response res) {

    return res.headers().stream()
        .filter(h -> "location".equalsIgnoreCase(h.name()))
        .map(HttpClient.Header::value)
        .findFirst()
        .map(URI::create)
        .orElseThrow(() -> new AuthorizationException("missing 'Location' header"));
  }

  private String exchangeEncryptedSignedChallenge(
      URI idpBaseUri, JWEObject encryptedSignedChallenge) {

    // TODO dynamic config
    // https://idp-ref.app.ti-dienste.de/.well-known/openid-configuration
    // take 'authorization_endpoint'
    var uri = idpBaseUri.resolve("/auth");

    var body =
        "signed_challenge=%s"
            .formatted(
                URLEncoder.encode(encryptedSignedChallenge.serialize(), StandardCharsets.UTF_8));

    var req =
        HttpRequest.newBuilder(uri)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .headers("content-type", "application/x-www-form-urlencoded")
            .build();

    try {
      var res = outerHttpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (res.statusCode() != 302) {
        throw new AuthorizationException(
            "unexpected status code in authorization response: %d".formatted(res.statusCode()));
      }

      var location =
          res.headers()
              .firstValue("Location")
              .map(URI::create)
              .orElseThrow(
                  () ->
                      new AuthorizationException(
                          "missing 'Location' header in authorization response"));

      var queryParams = UriQueryUtil.parse(location);
      validateAuthCodeResponse(queryParams);

      return getCodeFromParams(queryParams)
          .orElseThrow(
              () ->
                  new AuthorizationException(
                      "authorization response has no valid 'code' parameter"));

    } catch (IOException e) {
      throw new AuthorizationException("failed to get authorization response", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }

    throw new AuthorizationException("unexpected error");
  }

  private void validateAuthCodeResponse(Map<String, String> params) {
    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    if (!params.containsKey("error")) {
      return;
    }

    throw new AuthorizationException(
        "error in authorization response 'error=%s'".formatted(params.get("error")));
  }

  private Optional<String> getCodeFromParams(Map<String, String> params) {
    return Optional.ofNullable(params.get("code"));
  }

  public NonceResponse getNonce(String insurantId) {

    var path = "/epa/authz/v1/getNonce";
    var nonceUri = baseUri.resolve(path);
    var method = "GET";
    var req1 =
        new HttpClient.Request(
            nonceUri,
            method,
            List.of(
                new HttpClient.Header("accept", "application/json"),
                new HttpClient.Header("x-insurantid", insurantId)),
            null);

    var res = innerHttpClient.call(req1);
    if (res.status() != 200) {
      throw new IllegalStateException(
          "unexpected status '%s %s' %d".formatted(method, path, res.status()));
    }

    return JsonCodec.readBytes(res.body(), NonceResponse.class);
  }

  private JWEObject encryptAndSignChallenge(
      @NonNull RsaSignatureService.Card card, @NonNull SignedJWT challenge) {
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_Dienst/gemSpec_IDP_Dienst_V1.7.0/#7.3

    var expiry = expiryFromChallengeBody(challenge);
    var payload = signChallenge(card, challenge.serialize());

    try {

      // TODO: fetch from discovery
      // https://idp-ref.zentral.idp.splitdns.ti-dienste.de/.well-known/openid-configuration

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

    // get exp from challenge
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

  private SignedJWT signChallenge(RsaSignatureService.Card card, String challenge) {
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_Dienst/gemSpec_IDP_Dienst_V1.7.0/#7.3
    try {
      var claims = new JWTClaimsSet.Builder().claim("njwt", challenge).build();

      var cert = card.certificate();

      var header =
          // FUTURE: use ECC with the "alg" BS256R1 instead
          new JWSHeader.Builder(JWSAlgorithm.PS256)
              .type(JOSEObjectType.JWT)
              .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
              .contentType("NJWT")
              .build();

      var jwt = new SignedJWT(header, claims);

      var signer = signerForCard(card.handle());
      jwt.sign(signer);

      debugLogSignedChallenge(card.handle(), challenge, jwt);

      return jwt;
    } catch (JOSEException | ParseException | CertificateEncodingException e) {
      throw new AuthorizationException("failed to sign challenge", e);
    }
  }

  private void debugLogSignedChallenge(String cardHandle, String challenge, SignedJWT jwt)
      throws ParseException {
    if (!log.isDebugEnabled()) {
      return;
    }

    var header = jwt.getHeader().toString();
    var payload = JSONObjectUtils.toJSONString(jwt.getJWTClaimsSet().toJSONObject());
    log.atDebug()
        .addKeyValue("card_handle", cardHandle)
        .addKeyValue("challenge", challenge)
        .addKeyValue("header", header)
        .addKeyValue("payload", payload)
        .addKeyValue("jwt", jwt.serialize())
        .log(
            "signed challenge\ncard_handle: {}\nchallenge: {}\nheader\n===\n{}\n===\npayload\n===\n{}\n===\njwt\n===\n{}\n===\n",
            cardHandle,
            challenge,
            header,
            payload,
            jwt.serialize());
  }

  private SignedJWT attestClient(RsaSignatureService.Card card, String nonce) {
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Aktensystem_ePAfueralle/gemSpec_Aktensystem_ePAfueralle_V1.2.0/#A_25444-01

    var iat = Instant.now();

    // A_25444-01
    var exp = iat.plus(Duration.ofMinutes(20));

    var claims =
        new JWTClaimsSet.Builder()
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)
            .build();

    var cert = card.certificate();

    //    if (!(cert.getPublicKey() instanceof ECPublicKey ecPublicKey)) {
    //      throw new AuthorizationException(
    //          "unexpected certificate type, expected ECPublicKey but got %s"
    //              .formatted(cert.getPublicKey()));
    //    }
    //
    //    // check curve
    //    if (!BrainpoolCurve.isBP256(ecPublicKey.getParams())) {
    //      throw new AuthorizationException("SMB-C has unexpected curve, expected BP-256");
    //    }

    try {
      var x5c = Base64.encode(cert.getEncoded());
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
    } catch (JOSEException | CertificateEncodingException e) {
      throw new AuthorizationException("TODO", e);
    }
  }

  private JWSSigner signerForCard(String cardHandle) {
    return new SmcBSigner(
        (h, c) -> {
          if (JWSAlgorithm.PS256.equals(h.getAlgorithm())) {
            return rsaSignatureService.authSign(cardHandle, c);
          }
          var eccAlgs = Set.of(JWSAlgorithm.ES256, JWS_ALG_BS256R1);
          if (eccAlgs.contains(h.getAlgorithm())) {
            throw new UnsupportedOperationException("ecc alg not properly supported yet");
            //        return konnektorService.authSignEcdsa(cardHandle, c);
          }

          throw new UnsupportedOperationException(
              "unsupperted algorithm %s for signing with SMC-B".formatted(h.getAlgorithm()));
        });
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

    // TODO make signletons
    var challengeTypeVerifier = new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT);
    var challengeClaimsVerifier =
        new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder().claim("response_type", "code").build(),
            Set.of(JWTClaimNames.ISSUED_AT, JWTClaimNames.ISSUER, JWTClaimNames.EXPIRATION_TIME));

    challengeTypeVerifier.verify(challenge.getHeader().getType(), null);
    challengeClaimsVerifier.verify(challenge.getJWTClaimsSet(), null);
    return challenge;
  }

  private DiscoveryDocument loadDiscoveryDocument(String challenge) {

    try {
      var parsedChallenge = JWSObject.parse(challenge);

      ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
      jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));
      //        jwtProcessor.process(parsedChallenge, null)
      //          parsedChallenge
      //                  .getPayload()
      //                  .
    } catch (ParseException e) {
      throw new AuthorizationException("challenge is not a valid JWT", e);
    }

    return null;
  }

  private DiscoveryDocument parseAndValidateDiscoveryDocument(URI discoveryDocumentUri) {

    return null;
    //    try {
    //      var parsedDiscoveryDocument = JWSObject.parse(authRes.challenge());
    //      var jsonPayload = parsedDiscoveryDocument.getPayload().toJSONObject();
    //      var pukIdpSig = jsonPayload.get("uri_puk_idp_sig");
    //      var pukIdpEnc = jsonPayload.get("uri_puk_idp_sig");
    //    } catch (ParseException e) {
    //      throw new RuntimeException(e);
    //    }
  }

  private record DiscoveryDocument(URI issuer, String jwks_uri, long iat, long exp) {}

  private AuthorizationRequestResponse followRedirect(URI idpAuthEndpoint) {
    try {
      var res =
          outerHttpClient.send(
              HttpRequest.newBuilder(idpAuthEndpoint).GET().build(),
              HttpResponse.BodyHandlers.ofByteArray());
      if (res.statusCode() != 200) {
        throw new IllegalStateException(
            "unexpected status %s %s, got: %s".formatted("GET", idpAuthEndpoint, res.statusCode()));
      }
      return JsonCodec.readBytes(res.body(), AuthorizationRequestResponse.class);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("unreachable");
    }
  }

  private void sendAuthorizationCodeSmbC(
      String authorizationCode, String clientAttest, String insurantId) {

    // A_24766

    var path = "/epa/authz/v1/send_authcode_sc";
    var uri = baseUri.resolve(path);
    var method = "POST";

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_IDP_FD/latest/#5.5
    var body = new SendAuthcodeSmbCBody(authorizationCode, clientAttest);
    var reqBody = JsonCodec.writeBytes(body);

    var req =
        new HttpClient.Request(
            uri,
            method,
            List.of(
                new HttpClient.Header("content-type", "application/json"),
                new HttpClient.Header("x-insurantid", insurantId),
                new HttpClient.Header("accept", "application/json")),
            reqBody);

    var res = innerHttpClient.call(req);
    if (res.status() != 200) {
      if (log.isDebugEnabled()) {
        log.atDebug().log(
            "received bad status code, client -> VAU request:\n{}\nVAU -> client response:\n{}",
            body,
            res.body() != null ? new String(res.body(), StandardCharsets.UTF_8) : "");
      }
      throw new IllegalStateException(
          "unexpected status '%s %s' %d".formatted(method, path, res.status()));
    }
  }

  record SendAuthcodeSmbCBody(
      @JsonProperty("authorizationCode") String authorizationCode,
      @JsonProperty("clientAttest") String clientAttest) {}
}
