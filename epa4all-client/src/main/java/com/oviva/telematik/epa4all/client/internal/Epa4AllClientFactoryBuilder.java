package com.oviva.telematik.epa4all.client.internal;

import com.oviva.epa.client.KonnektorService;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.net.InetSocketAddress;
import java.util.Objects;

/** Builder for Epa4AllClientFactory. */
public class Epa4AllClientFactoryBuilder {

  private KonnektorService konnektorService;
  private InetSocketAddress konnektorProxyAddress;

  private Environment environment;

  private Epa4AllClientFactoryBuilder() {}

  public static Epa4AllClientFactoryBuilder newBuilder() {
    return new Epa4AllClientFactoryBuilder();
  }

  @NonNull
  public Epa4AllClientFactoryBuilder konnektorService(@NonNull KonnektorService konnektorService) {
    this.konnektorService =
        Objects.requireNonNull(konnektorService, "konnektorService must not be null");
    return this;
  }

  @NonNull
  public Epa4AllClientFactoryBuilder konnektorProxyAddress(
      @NonNull InetSocketAddress konnektorProxyAddress) {
    this.konnektorProxyAddress =
        Objects.requireNonNull(konnektorProxyAddress, "konnektorProxyAddress must not be null");
    return this;
  }

  @NonNull
  public Epa4AllClientFactoryBuilder environment(Environment environment) {
    this.environment = Objects.requireNonNull(environment, "environment must not be null");
    return this;
  }

  @NonNull
  public Epa4AllClientFactory build() {
    Objects.requireNonNull(konnektorService, "konnektorService must be set");
    Objects.requireNonNull(konnektorProxyAddress, "konnektorProxyAddress must be set");
    Objects.requireNonNull(environment, "environment must be set");

    return Epa4AllClientFactory.create(konnektorService, konnektorProxyAddress, environment);
  }
}
