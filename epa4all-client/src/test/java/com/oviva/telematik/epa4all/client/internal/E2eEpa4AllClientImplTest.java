package com.oviva.telematik.epa4all.client.internal;

import com.oviva.epa.client.konn.internal.util.NaiveTrustManager;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class E2eEpa4AllClientImplTest {

  @Test
  void writeDocument() {


    var client = new Epa4AllClientImpl()


  }

  private HttpClient buildOuterHttpClient() {

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
