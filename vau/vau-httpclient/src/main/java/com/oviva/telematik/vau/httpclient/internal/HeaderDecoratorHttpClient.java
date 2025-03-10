package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.util.ArrayList;
import java.util.List;

public class HeaderDecoratorHttpClient implements HttpClient {

  private final HttpClient delegate;
  private final List<Header> extraHeaders;

  public HeaderDecoratorHttpClient(HttpClient httpClient, List<Header> extraHeaders) {
    this.delegate = httpClient;
    this.extraHeaders = extraHeaders;
  }

  @Override
  public Response call(Request req) {

    var decorated = new ArrayList<>(extraHeaders);
    if (req.headers() != null) {
      for (Header h : req.headers()) {
        if (isExtraHeader(h)) {
          continue;
        }
        decorated.add(h);
      }
    }

    var newRequest = new Request(req.uri(), req.method(), decorated, req.body());
    return delegate.call(newRequest);
  }

  private boolean isExtraHeader(Header h) {
    return extraHeaders.stream().anyMatch(n -> n.name().equalsIgnoreCase(h.name()));
  }
}
