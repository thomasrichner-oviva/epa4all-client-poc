package com.oviva.telematik.vau.httpclient.internal;

import static org.junit.jupiter.api.Assertions.*;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class HttpCodecTest {

  @Test
  void decode() {
    var raw =
        """
      HTTP/1.1 302 Found
      Content-Type: application/json
      Location: https://idp-ref.app.ti-dienste.de/auth?response_type=code&scope=openid+ePA-bmt-rt&nonce=WI7WY279m4GkkbnKzcaa4GvdNXRRmHum45W8jLy4qS4knnjvf5zwl8TgwR4khzw2&client_id=GEMBITMAePAe2zrxzLOR&redirect_uri=https%3A%2F%2Fe4a-rt.deine-epa.de%2F&code_challenge=Vug9LZByRxhRzk5TkCfo_n1Vzf00MvyFc-yJ7Z_bP8I&code_challenge_method=S256&state=coSyovEtvs6wROCMS9ClLIlo3QXgadFB1QzBTpyO9UiYgE1RBXsiaKcW6xT8Avn6

      """;

    var res = HttpCodec.decode(raw.getBytes(StandardCharsets.UTF_8));

    assertEquals(302, res.status());

    assertTrue(res.headers().stream().anyMatch(h -> "location".equalsIgnoreCase(h.name())));
  }

  @Test
  void encode() {
    var bodyBytes =
        """
    {
      "authorizationCode": "hello",
      "clientAttest": "world"
    }
    """
            .getBytes(StandardCharsets.UTF_8);
    var expected =
        """
    POST /epa/authz/v1/send_authcode_sc HTTP/1.1\r
    accept: application/json\r
    content-type: application/json\r
    user-agent: Java-http-client/21.0.3\r
    host: localhost:7777\r
    x-useragent: Oviva/0.0.1\r
    content-length: %d\r
    \r
    {
      "authorizationCode": "hello",
      "clientAttest": "world"
    }
    """
            .formatted(bodyBytes.length)
            .getBytes(StandardCharsets.UTF_8);

    var req =
        new HttpClient.Request(
            URI.create("http://localhost:7777/epa/authz/v1/send_authcode_sc"),
            "POST",
            List.of(
                new HttpClient.Header("accept", "application/json"),
                new HttpClient.Header("content-type", "application/json"),
                new HttpClient.Header("user-agent", "Java-http-client/21.0.3"),
                new HttpClient.Header("host", "localhost:7777"),
                new HttpClient.Header("x-useragent", "Oviva/0.0.1")),
            bodyBytes);

    var got = HttpCodec.encode(req);

    assertEquals(
        new String(expected, StandardCharsets.UTF_8), new String(got, StandardCharsets.UTF_8));
  }
}
