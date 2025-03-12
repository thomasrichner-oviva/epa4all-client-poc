package com.oviva.telematik.epaapi;

import static com.oviva.telematik.epaapi.ExportFixture.buildFhirDocument;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import com.oviva.telematik.vau.epa4all.client.authz.AuthorizationService;
import com.oviva.telematik.vau.epa4all.client.authz.internal.RsaSignatureAdapter;
import com.oviva.telematik.vau.epa4all.client.info.InformationService;
import com.oviva.telematik.vau.httpclient.internal.DowngradeHttpClient;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.proxy.VauProxy;
import java.net.*;
import java.net.http.HttpClient;
import java.security.*;
import java.time.Duration;
import java.util.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("e2e")
class EndToEndTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String KONNEKTOR_PROXY_HOST = "127.0.0.1";
  private static final int KONNEKTOR_PROXY_PORT = 3128;

  private enum Enabler {
    EPA_DEPLOYMENT,
    RISE;
  }

  private final Enabler enabler = Enabler.RISE;
  private VauProxy app;
  private InetSocketAddress vauProxyServerListener = null;

  @BeforeEach
  void setUp() {
    var proxy = new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT);
    if (enabler == Enabler.EPA_DEPLOYMENT) {
      proxy = null;
    }
    app = new VauProxy(new VauProxy.Configuration(proxy, 0, false, "GEMOvivepa4fA1d5W8sR/0.0.1"));

    // VAU base URI is dynamic!
    var si = app.start();
    vauProxyServerListener = si.listenAddress();
  }

  @AfterEach
  void tearDown() {
    app.stop();
  }

  @Test
  void e2e_RU() throws Exception {

    System.setProperty("jdk.httpclient.HttpClient.log", "errors,requests,headers");

    var konnektorService = TestKonnektors.riseKonnektor_RU();

    // client -> jumphost proxy -> (Internet || ( RISE VPN -> Telematikinfra) )
    var outerHttpClient = buildOuterHttpClient();

    // ----
    // 1. find the enabler hosting the ePA for the given insurant (Krankenversicherten Nummber -
    // KVNR)

    //    var insurantId = "Z987654321";
    //        var insurantId = "X110467329"; // RISE
    //    final var insurantId = "X110580673"; // fBeta
    //    final var insurantId = "X229678976"; // fBeta
    // X229678976 // RISE with access from Oviva's SMB-C

    // Oviva
    // KVNR: X110467329 (unauthorized)
    // KVNR: X110485695 (unauthorized)
    // KVNR: X110406713 (unauthorized)
    // KVNR: X110661675 (authorized & FdV)
    final var insurantId = "X110661675";

    var providers =
        List.of(InformationService.EpaProvider.IBM, InformationService.EpaProvider.BITMARCK);
    var informationService =
        new InformationService(outerHttpClient, InformationService.Environment.DEV, providers);

    var endpoint =
        informationService
            .findAccountEndpoint(insurantId)
            .orElseGet(
                () -> {
                  fail("KVNR %s doesnt exist".formatted(insurantId));
                  return null;
                });

    // ----
    // 2. set-up client to proxy through the VAU tunnel

    // client -> proxy-server (vau-tunnel wrapper, forward proxy) -> jumphost proxy -> RISE VPN
    // (wireguard) -> Telematikinfra

    var vauProxyServerAddr = new InetSocketAddress("127.0.0.1", vauProxyServerListener.getPort());

    var innerVauClient = buildVauHttpClient(vauProxyServerAddr);

    var cards = konnektorService.listSmcbCards();
    assumeTrue(!cards.isEmpty(), "no cards found");
    var card = cards.get(0);

    var signer = new RsaSignatureAdapter(konnektorService, card);
    var authorizationService = new AuthorizationService(innerVauClient, outerHttpClient, signer);

    // ----
    // 3. authenticate the client-side of the VAU tunnel
    assertDoesNotThrow(() -> authorizationService.authorizeVauWithSmcB(endpoint, insurantId));

    // => tunnel is now authorized, let the fun begin

    // ----
    // 4. interact with the document management service

    // we need to downgrade the URI we got, this goes through the VAU tunnel
    var phrEndpoint = downgradeUri(endpoint).resolve("/epa/xds-document/api/I_Document_Management");

    // setup the soap client to go via VAU proxy
    var client =
        new SoapClientFactory(
            new ClientConfiguration(
                new InetSocketAddress("localhost", vauProxyServerListener.getPort())));
    var phrManagementPort = client.getIDocumentManagementPort(phrEndpoint);
    var phrService = new PhrService(phrManagementPort);

    // NOTE: as of now only FHIR seems to work, specifically PDF/A don't work
    var document = buildFhirDocument(card, insurantId);

    assertDoesNotThrow(() -> phrService.writeDocument(insurantId, document));

    System.out.println("Success!");
  }

  private com.oviva.telematik.vau.httpclient.HttpClient buildVauHttpClient(
      InetSocketAddress vauProxyServerAddr) {

    // HTTP client used to communicate inside the VAU tunnel
    var innerHttpClient =
        HttpClient.newBuilder()
            // this is the local VAU termination proxy
            .proxy(ProxySelector.of(vauProxyServerAddr))
            // no redirects, wee need to deal with redirects from authorization directly
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(7))
            // within the VAU tunnel HTTP/1.1 is preferred
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    // we need to downgrade HTTPS requests to HTTP, otherwise the proxy can't deal with the requests
    return new DowngradeHttpClient(JavaHttpClient.from(innerHttpClient));
  }

  private URI downgradeUri(URI u) {

    var port = u.getPort();
    var scheme = u.getScheme();
    if ("http".equals(scheme)) {
      return u;
    }

    if (((port == 443) || (port == -1)) && "https".equals(scheme)) {
      return URI.create("http://%s%s".formatted(u.getHost(), u.getPath()));
    }

    throw new IllegalArgumentException("failed downgrading uri=%s".formatted(u));
  }

  private HttpClient buildOuterHttpClient() {

    if (enabler == Enabler.EPA_DEPLOYMENT) {
      return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }

    SSLContext sslContext = null;
    try {
      sslContext = SSLContext.getInstance("TLSv1.3");
      sslContext.init(null, new TrustManager[] {new NaiveTrustManager()}, null);
    } catch (KeyManagementException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    return HttpClient.newBuilder()
        // TODO: use proper truststore
        .sslContext(sslContext)
        // Returned URLs actually need to be resolved via the
        // proxy, their FQDN is only resolved within the TI
        .proxy(ProxySelector.of(new InetSocketAddress(KONNEKTOR_PROXY_HOST, KONNEKTOR_PROXY_PORT)))
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }
}
