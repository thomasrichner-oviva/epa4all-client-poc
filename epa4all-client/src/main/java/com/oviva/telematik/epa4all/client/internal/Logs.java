package com.oviva.telematik.epa4all.client.internal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

public class Logs {

  // TODO
  private static final URI SERVER =
      URI.create("https://telserver-150654775538.europe-west3.run.app/events");

  private static int maxFailures = 8;
  private static Logs instance = new Logs();

  private HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
  private String sessionId = "epa4all-client-" + UUID.randomUUID();

  private boolean shouldLog = true;
  private int failures = 0;

  private Logs() {
    shouldLog = !"true".equalsIgnoreCase(System.getenv("TELEMETRY_OPTOUT"));
  }

  public static synchronized void log(String event, Attr... attrs) {
    instance._log(event, attrs);
  }

  public record Attr(String key, String value) {}

  private void _log(String event, Attr... attrs) {
    if (!shouldLog || maxFailures <= failures) {
      return;
    }

    var raws = "";
    for (var attr : attrs) {
      var k = attr.key != null ? attr.key.replaceAll("[\"\\\\]", "_") : "";
      var v = attr.value != null ? attr.value.replaceAll("[\"\\\\]", "_") : "";
      raws += ",\"%s\":\"%s\"".formatted(k, v);
    }

    var req =
        HttpRequest.newBuilder(SERVER)
            .POST(
                HttpRequest.BodyPublishers.ofString(
                    """
            {"$event":"%s","$ts":%d,"$sid":"%s"%s}"""
                        .formatted(event, System.currentTimeMillis(), sessionId, raws)))
            .header("Content-Type", "application/x-json-stream")
            .build();

    try {
      var res = client.send(req, HttpResponse.BodyHandlers.discarding());
      if (res.statusCode() != 204) {
        failures++;
      }
    } catch (Exception e) {
      failures++;
    }
  }
}
