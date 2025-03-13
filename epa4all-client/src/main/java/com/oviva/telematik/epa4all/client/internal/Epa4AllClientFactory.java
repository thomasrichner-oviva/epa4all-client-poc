package com.oviva.telematik.epa4all.client.internal;

import com.oviva.epa.client.KonnektorService;
import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import com.oviva.epa.client.model.SmcbCard;
import com.oviva.telematik.epa4all.client.Epa4AllClient;
import com.oviva.telematik.epaapi.ClientConfiguration;
import com.oviva.telematik.epaapi.SoapClientFactory;
import com.oviva.telematik.vau.epa4all.client.Epa4AllClientException;
import com.oviva.telematik.vau.epa4all.client.authz.AuthorizationService;
import com.oviva.telematik.vau.epa4all.client.authz.internal.RsaSignatureAdapter;
import com.oviva.telematik.vau.epa4all.client.info.InformationService;
import com.oviva.telematik.vau.httpclient.internal.DowngradeHttpClient;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.proxy.VauProxy;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.security.*;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Epa4AllClientFactory implements AutoCloseable {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String LOCALHOST = "127.0.0.1";

  private static Logger log = LoggerFactory.getLogger(Epa4AllClientFactory.class);
  private final VauProxy proxyServer;
  private final SoapClientFactory client;
  private final AuthorizationService authorizationService;
  private final InformationService informationService;
  private final SmcbCard card;

  public Epa4AllClientFactory(
      VauProxy proxyServer,
      SoapClientFactory client,
      AuthorizationService authorizationService,
      InformationService informationService,
      SmcbCard card) {
    this.proxyServer = proxyServer;
    this.client = client;
    this.authorizationService = authorizationService;
    this.informationService = informationService;
    this.card = card;
  }

  public static Epa4AllClientFactory create(
      KonnektorService konnektorService,
      InetSocketAddress konnektorProxyAddress,
      Environment environment,
      List<TrustManager> trustManagers) {

    var outerHttpClient =
        buildOuterHttpClient(konnektorProxyAddress, buildSslContext(trustManagers));

    var informationService = buildInformationService(environment, outerHttpClient);

    var trustStore = determineTrustStore(environment == Environment.PU, null);
    var proxyServer = buildVauProxy(environment, konnektorProxyAddress, trustStore);

    var serverInfo = proxyServer.start();
    var vauProxyServerListener = serverInfo.listenAddress();
    var vauProxyServerAddr = new InetSocketAddress(LOCALHOST, vauProxyServerListener.getPort());

    // HTTP client used to communicate inside the VAU tunnel
    var innerVauClient = buildInnerHttpClient(vauProxyServerAddr);

    var card = findSmcBCard(konnektorService);

    var signer = new RsaSignatureAdapter(konnektorService, card);
    var authorizationService = new AuthorizationService(innerVauClient, outerHttpClient, signer);

    var client =
        new SoapClientFactory(
            new ClientConfiguration(
                new InetSocketAddress(LOCALHOST, vauProxyServerListener.getPort())));

    return new Epa4AllClientFactory(
        proxyServer, client, authorizationService, informationService, card);
  }

  public Epa4AllClient newClient() {
    return new Epa4AllClientImpl(informationService, authorizationService, card, client);
  }

  private static SmcbCard findSmcBCard(KonnektorService konnektorService) {
    var cards = konnektorService.listSmcbCards();
    if (cards.isEmpty()) {
      throw new Epa4AllClientException("no SMC-B cards found");
    }
    if (cards.size() > 1) {
      log.atInfo().log("more than one SMC-B card found, using first one");
    }
    return cards.get(0);
  }

  private static VauProxy buildVauProxy(
      Environment environment, InetSocketAddress konnektorProxyAddress, KeyStore trustStore) {

    var isPu = environment == Environment.PU;
    var xUserAgent = isPu ? "GEMOvivepa4fA734EBIP/0.1.0" : "GEMOvivepa4fA1d5W8sR/0.1.0";
    return new VauProxy(
        new VauProxy.Configuration(
            konnektorProxyAddress,
            0,
            isPu,
            xUserAgent,
            buildSslContext(List.of(new NaiveTrustManager())),
            trustStore));
  }

  private static KeyStore determineTrustStore(boolean isPu, KeyStore providedTrustStore) {
    if (providedTrustStore != null) {
      return providedTrustStore;
    } else if (isPu) {
      return TelematikTrustRoots.loadPuRootKeys();
    } else {
      return TelematikTrustRoots.loadRuRootKeys();
    }
  }

  private static InformationService buildInformationService(
      Environment environment, HttpClient outerHttpClient) {

    var providers =
        List.of(InformationService.EpaProvider.IBM, InformationService.EpaProvider.BITMARCK);

    var informationServiceEnvironment =
        switch (environment) {
          case PU -> InformationService.Environment.PU;
          case RU -> InformationService.Environment.DEV;
        };

    return new InformationService(outerHttpClient, informationServiceEnvironment, providers);
  }

  private static com.oviva.telematik.vau.httpclient.HttpClient buildInnerHttpClient(
      InetSocketAddress vauProxyServerAddress) {

    // HTTP client used to communicate inside the VAU tunnel
    var innerHttpClient =
        HttpClient.newBuilder()
            // this is the local VAU termination proxy
            .proxy(ProxySelector.of(vauProxyServerAddress))
            // no redirects, wee need to deal with redirects from authorization directly
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(7))
            // within the VAU tunnel HTTP/1.1 is preferred
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    // we need to downgrade HTTPS requests to HTTP, otherwise the proxy can't deal with the requests
    return new DowngradeHttpClient(JavaHttpClient.from(innerHttpClient));
  }

  private static HttpClient buildOuterHttpClient(
      InetSocketAddress konnektorProxyAddress, SSLContext sslContext) {

    return HttpClient.newBuilder()
        .sslContext(sslContext)
        // Returned URLs actually need to be resolved via the
        // proxy, their FQDN is only resolved within the TI
        .proxy(ProxySelector.of(konnektorProxyAddress))
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }

  private static SSLContext buildSslContext(List<TrustManager> tms) {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
      sslContext.init(null, tms.toArray(tms.toArray(new TrustManager[0])), null);
      return sslContext;
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new IllegalStateException("failed to initialise ssl context", e);
    }
  }

  @Override
  public void close() {
    proxyServer.stop();
  }
}
