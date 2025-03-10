package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class HttpCodec {

  private HttpCodec() {}

  private static final String HTTP_VERSION = "HTTP/1.1";
  private static final byte[] CRLF = "\r\n".getBytes(StandardCharsets.UTF_8);

  private static final Set<String> UNSUPPORTED_HEADERS = Set.of("transfer-coding", "TE");
  private static final Set<String> SKIP_HEADERS = Set.of("content-length");
  private static final Set<String> SUPPORTED_METHODS = Set.of("GET", "POST", "PUT", "DELETE");
  private static final Pattern HEADER_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9-_]+");

  public static HttpClient.Response decode(byte[] bytes) {

    try (var reader =
        new BufferedReader(new StringReader(new String(bytes, StandardCharsets.UTF_8)))) {

      // HTTP/1.1 404 Not Found
      var statusLine = reader.readLine();
      var status = parseStatusLine(statusLine);
      var headers = parseHeaders(reader);

      var baos = new ByteArrayOutputStream();
      try (var bodyReader = reader;
          var w = new OutputStreamWriter(baos)) {
        bodyReader.transferTo(w);
      }

      var body = baos.toByteArray();
      if (body.length != headers.contentLength()) {
        /* IMPORTANT: At least RISE connectors don't actually set the `content-length`
         * Argumentation:
         *
         * Wie Sie selbst festgestellt haben fehlt im inneren HTTP der Content-Length Header.
         * Aus unserer Sicht haben wir nicht die Möglichkeit, diesen Header in jeder Situation zu setzen,
         * weil das Aktensystem oft mit großen Datenmengen hantieren muss. Die Content-Length hier vorab zu
         * bestimmen wäre zu speicherintensiv.
         *
         * Clients müssen somit aus unserer Sicht jedenfalls mit der Situation eines fehlenden Content-Length
         * Headers umgehen können. Sie nennen selbst die bestehenden Möglichkeiten für einen Server, wie er in diesem
         * Fall den Clients ermöglichen muss, den Response trotzdem erfolgreich zu parsen.
         *
         * Keine dieser Möglichkeiten ist aus unserer Sicht auf das spezielle Design des inneren HTTP anwendbar.
         * Allerdings liefern wir das äußere HTTP von verschlüsseltem Nachrichten stets mit einem chunked
         * Transfer-Encoding aus, womit die Längeninformationen indirekt über das äußere HTTP zu Verfügung stehen.
         * Auch wenn wir damit sicherlich nicht vollständig HTTP-konform sind,
         * ist dies aus unserer Sicht ausreichend, damit Clients die verschlüsselten Nachrichten
         * trotzdem erfolgreich parsen können.
         */
        //        throw new HttpClient.HttpException(
        //            "content-length '%d' != actual length '%d'"
        //                .formatted(headers.contentLength(), body.length));
      }

      return new HttpClient.Response(status, headers.all(), body);

    } catch (IOException e) {
      throw new HttpClient.HttpException("failed to decode response", e);
    }
  }

  private static ResponseHeaders parseHeaders(BufferedReader reader) {

    var headers = new ArrayList<HttpClient.Header>();
    var contentLength = -1;

    try {
      var line = reader.readLine();
      while (line != null) {
        if (line.isEmpty()) {
          contentLength = contentLength == -1 ? 0 : contentLength;
          return new ResponseHeaders(headers, contentLength);
        }

        var h = parseHeader(line);
        if ("content-length".equals(h.name())) {

          // we've already set the content-length!
          if (contentLength >= 0) {
            throw new HttpClient.HttpException("content-length set more than once!");
          }

          try {
            var maybeContentLength = Integer.parseInt(h.value());
            if (maybeContentLength >= 0) {
              contentLength = maybeContentLength;
            } else {
              throw new HttpClient.HttpException(
                  "invalid content-length: '%d'".formatted(maybeContentLength));
            }
          } catch (NumberFormatException e) {
            throw new HttpClient.HttpException("invalid content-length: '%s'".formatted(h.value()));
          }
        }

        headers.add(h);
        line = reader.readLine();
      }
    } catch (IOException e) {
      throw new HttpClient.HttpException("failed to parse headers", e);
    }

    throw new IllegalStateException("unreachable");
  }

  private static HttpClient.Header parseHeader(String line) {
    var splits = line.split(":", 2);
    if (splits.length != 2) {
      throw new HttpClient.HttpException("invalid header line: '%s'".formatted(line));
    }

    var name = canonicalizeHeaderName(splits[0].trim());
    var value = splits[1].trim();
    validateHeader(name, value);
    return new HttpClient.Header(name, value);
  }

  private record ResponseHeaders(List<HttpClient.Header> all, int contentLength) {}

  private static int parseStatusLine(String statusLine) {
    var splits = statusLine.split(" ", 3);
    if (splits.length != 3) {
      throw new HttpClient.HttpException("invalid status line: '%s'".formatted(statusLine));
    }

    try {
      return Integer.parseInt(splits[1]);
    } catch (NumberFormatException e) {
      throw new HttpClient.HttpException(
          "invalid status line, failed to parse status code: '%s'".formatted(statusLine));
    }
  }

  public static byte[] encode(HttpClient.Request req) {

    validateRequest(req);

    var baos = new ByteArrayOutputStream(1024);

    addRequestLine(baos, req.uri(), req.method());
    writeHeaders(baos, req);
    writeBody(baos, req.body());

    return baos.toByteArray();
  }

  private static void writeBody(ByteArrayOutputStream buf, byte[] body) {
    if (body == null || body.length == 0) {
      return;
    }
    buf.writeBytes(body);
  }

  private static void writeHeaders(ByteArrayOutputStream buf, HttpClient.Request req) {
    addHeaders(buf, req.headers());
    addContentLength(buf, req.body() != null ? req.body().length : 0);

    buf.writeBytes(CRLF);
  }

  private static void addRequestLine(ByteArrayOutputStream buf, URI uri, String method) {

    // e.g. "GET /here/is/my/path HTTP/1.1\r\n"
    buf.writeBytes(asUtf8(method));
    buf.write((byte) ' ');
    buf.writeBytes(asUtf8(uri.getPath()));
    buf.write((byte) ' ');
    buf.writeBytes(asUtf8(HTTP_VERSION));
    buf.writeBytes(CRLF);
  }

  private static void addContentLength(ByteArrayOutputStream buf, int length) {
    if (length <= 0) {
      return;
    }

    buf.writeBytes(asUtf8("content-length: "));
    buf.writeBytes(asUtf8(Integer.toString(length)));
    buf.writeBytes(CRLF);
  }

  private static void addHeaders(ByteArrayOutputStream buf, List<HttpClient.Header> headers) {
    if (headers == null) {
      return;
    }

    for (HttpClient.Header h : headers) {
      var name = canonicalizeHeaderName(h.name());
      if (SKIP_HEADERS.contains(name)) {
        continue;
      }
      buf.writeBytes(asUtf8(name));
      buf.writeBytes(asUtf8(": "));
      buf.writeBytes(asUtf8(h.value()));
      buf.writeBytes(CRLF);
    }
  }

  private static void validateRequest(HttpClient.Request req) {
    if (req == null) {
      throw new HttpClient.HttpException("invalid request: 'null'");
    }
    validateMethod(req.method());

    if (req.uri() == null) {
      throw new HttpClient.HttpException("invalid uri: 'null'");
    }

    if (req.headers() != null) {
      for (HttpClient.Header h : req.headers()) {
        validateHeader(h.name(), h.value());
      }
    }
  }

  private static void validateMethod(String method) {
    if (method == null || (!SUPPORTED_METHODS.contains(method))) {
      throw new HttpClient.HttpException("unsupported method: '%s'".formatted(method));
    }
  }

  private static void validateHeader(String name, String value) {
    name = canonicalizeHeaderName(name);
    if (UNSUPPORTED_HEADERS.contains(name)) {
      throw new HttpClient.HttpException("unsupported header: '%s'".formatted(name));
    }
    if (!HEADER_NAME_PATTERN.matcher(name).matches()) {
      throw new HttpClient.HttpException("invalid header name: '%s'".formatted(name));
    }

    // we don't validate the header value further
  }

  private static String canonicalizeHeaderName(String name) {
    // https://www.rfc-editor.org/rfc/rfc9110.html#name-header-fields
    return name.toLowerCase(Locale.US);
  }

  private static byte[] asUtf8(String s) {
    if (s == null) {
      return new byte[0];
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }
}
