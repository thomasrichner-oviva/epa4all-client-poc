package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.HttpCodec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Very basic interface for an HttpClient */
public interface HttpClient {

  Response call(Request req);

  record Request(URI uri, String method, List<Header> headers, byte[] body) {
    @Override
    public String toString() {
      return new String(HttpCodec.encode(this), StandardCharsets.UTF_8);
    }
  }

  record Response(int status, List<Header> headers, byte[] body) {}

  record Header(String name, String value) {}

  class HttpException extends RuntimeException {
    public HttpException(String message) {
      super(message);
    }

    public HttpException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
