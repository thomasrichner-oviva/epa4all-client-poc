package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.net.URI;

public class DowngradeHttpClient implements HttpClient {

  private final HttpClient delegate;

  public DowngradeHttpClient(HttpClient httpClient) {
    this.delegate = httpClient;
  }

  @Override
  public Response call(Request req) {

    var port = req.uri().getPort();
    var scheme = req.uri().getScheme();
    if ("http".equals(scheme)) {
      return delegate.call(req);
    }

    if (((port == 443) || (port == -1)) && "https".equals(scheme)) {
      var downgradedUri =
          URI.create("http://%s%s".formatted(req.uri().getHost(), req.uri().getPath()));
      var downgraded = new Request(downgradedUri, req.method(), req.headers(), req.body());
      return delegate.call(downgraded);
    }

    throw new UnsupportedOperationException("cannot downgrade request to: %s".formatted(req.uri()));
  }
}
