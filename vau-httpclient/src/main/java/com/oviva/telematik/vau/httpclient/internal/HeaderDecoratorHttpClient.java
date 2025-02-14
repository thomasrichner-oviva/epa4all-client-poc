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

    var headers = new ArrayList<>(req.headers());
    headers.addAll(extraHeaders);

    var newRequest = new Request(req.uri(), req.method(), headers, req.body());
    return delegate.call(newRequest);
  }
}
