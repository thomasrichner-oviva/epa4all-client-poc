package com.oviva.telematik.vau.proxy;

import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import com.oviva.telematik.vau.httpclient.VauClientFactoryBuilder;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
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

public class Main {

  private static final Logger log = LoggerFactory.getLogger(Main.class);

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) {
    var app = new Main(null);

    app.start();
    Signal.handle(new Signal("INT"), signal -> app.stop());
    waitForever();
  }

  private static void waitForever() {
    var cl = new CountDownLatch(1);
    try {
      cl.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private CountDownLatch startedCount = new CountDownLatch(1);

  private Undertow proxyServer;

  private InetSocketAddress upstreamProxy;

  // new InetSocketAddress("127.0.0.1", 3128)
  public Main(Configuration config) {
    if (config != null) {
      this.upstreamProxy = config.upstreamProxy();
    }
  }

  public record Configuration(InetSocketAddress upstreamProxy) {}

  public void start() {

    var outerVauClientBuilder =
        java.net.http.HttpClient.newBuilder()
            // TODO: configurable
            .sslContext(trustAllContext())
            .connectTimeout(Duration.ofSeconds(10));

    if (upstreamProxy != null) {
      outerVauClientBuilder.proxy(ProxySelector.of(upstreamProxy));
    }

    var outerVauClient = outerVauClientBuilder.build();

    // connect VAU tunnel (unauthenticated)
    var clientFactory =
        VauClientFactoryBuilder.builder()
            .outerClient(JavaHttpClient.from(outerVauClient))
            .isPu(false)
            .withInsecureTrustValidator()
            .build();

    HttpHandler handler = new VauProxyHandler(clientFactory);
    if (log.isDebugEnabled()) {
      handler = new RequestDumpingHandler(handler);
    }

    proxyServer =
        Undertow.builder()
            // TODO: configurable
            .addHttpListener(7777, "localhost")
            .setIoThreads(2)
            .setWorkerThreads(4)
            .setHandler(handler)
            .build();

    proxyServer.start();

    var addr = proxyServer.getListenerInfo().get(0).getAddress();
    log.info("VAU proxy started at {}", addr);

    Signal.handle(new Signal("INT"), signal -> startedCount.countDown());
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
