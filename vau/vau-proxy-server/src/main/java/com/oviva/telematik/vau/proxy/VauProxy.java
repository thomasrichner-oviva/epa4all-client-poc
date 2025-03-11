package com.oviva.telematik.vau.proxy;

import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import com.oviva.telematik.vau.httpclient.HttpClient;
import com.oviva.telematik.vau.httpclient.VauClientFactoryBuilder;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.LoggingHttpClient;
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.RequestDumpingHandler;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.Signal;

public class VauProxy {

  private static final Logger log = LoggerFactory.getLogger(VauProxy.class);

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private final CountDownLatch startedCount = new CountDownLatch(1);

  private Undertow proxyServer;

  private final Configuration config;

  public VauProxy(Configuration config) {
    this.config = config;
  }

  public record Configuration(
      InetSocketAddress upstreamProxy, int listenPort, boolean isPu, String xUserAgent) {}

  public record ServerInfo(InetSocketAddress listenAddress) {}

  public ServerInfo start() {

    var outerVauClientBuilder =
        java.net.http.HttpClient.newBuilder()
            // TODO: configurable
            .sslContext(trustAllContext())
            .connectTimeout(Duration.ofSeconds(10));

    if (config.upstreamProxy() != null) {
      outerVauClientBuilder.proxy(ProxySelector.of(config.upstreamProxy()));
    }

    HttpClient outerVauClient = JavaHttpClient.from(outerVauClientBuilder.build());

    if (log.isDebugEnabled()) {
      outerVauClient = new LoggingHttpClient(outerVauClient, log);
    }

    // connect VAU tunnel (unauthenticated)
    var clientFactory =
        VauClientFactoryBuilder.newBuilder()
            .xUserAgent(config.xUserAgent())
            .outerClient(outerVauClient)
            .isPu(config.isPu())
            .withInsecureTrustValidator()
            .build();

    HttpHandler handler = new VauProxyHandler(clientFactory);
    if (log.isDebugEnabled()) {
      handler = new RequestDumpingHandler(handler);
    }

    proxyServer =
        Undertow.builder()
            // TODO: configurable
            .addHttpListener(config.listenPort(), "localhost")
            .setIoThreads(2)
            .setWorkerThreads(4)
            .setHandler(handler)
            .build();

    proxyServer.start();

    var listener = proxyServer.getListenerInfo().get(0);
    var addr = (InetSocketAddress) listener.getAddress();
    log.info("VAU proxy started at {}", addr);

    Signal.handle(new Signal("INT"), signal -> startedCount.countDown());
    return new ServerInfo(addr);
  }

  public void stop() {
    if (proxyServer != null) {
      proxyServer.stop();
    }
  }

  private SSLContext trustAllContext() {
    // TODO use proper truststore!

    SSLContext sslContext = null;
    try {
      sslContext = SSLContext.getInstance("TLSv1.3");
      sslContext.init(null, new TrustManager[] {new NaiveTrustManager()}, null);
    } catch (KeyManagementException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    return sslContext;
  }
}
