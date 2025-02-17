package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.ConnectionFactory;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
import java.time.Duration;

public class VauClientFactoryBuilder {

  private static final String X_USER_AGENT = "OvivaProxy/0.0.1";

  public static VauClientFactoryBuilder builder() {
    return new VauClientFactoryBuilder();
  }

  private boolean isPu = true;

  private TrustValidator trustValidator = null;

  private HttpClient outerClient =
      JavaHttpClient.from(
          java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());

  private VauClientFactoryBuilder() {}

  public VauClientFactoryBuilder outerClient(HttpClient outerClient) {
    this.outerClient = outerClient;
    return this;
  }

  public VauClientFactoryBuilder isPu(boolean isPu) {
    this.isPu = isPu;
    return this;
  }

  public VauClientFactoryBuilder trustValidator(TrustValidator trustValidator) {
    this.trustValidator = trustValidator;
    return this;
  }

  public VauClientFactoryBuilder withInsecureTrustValidator() {
    this.trustValidator = (a, b, c, d) -> new TrustValidator.ValidationResult(true, null, null);
    return this;
  }

  /**
   * Returns an HttpClient that uses the VAU transport as documented in <a
   * href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.37.0/#7">gemSpec_Krypt</a>.
   * The {@link HttpClient} directly sends requests in the HTTP protocol through the VAU tunnel.
   */
  public VauClientFactory build() {

    if (outerClient == null) {
      throw new IllegalArgumentException("outer client missing");
    }

    if (trustValidator == null) {
      throw new IllegalArgumentException("trust validator missing");
    }

    return new ConnectionFactory(outerClient, isPu, X_USER_AGENT, trustValidator);
  }
}
