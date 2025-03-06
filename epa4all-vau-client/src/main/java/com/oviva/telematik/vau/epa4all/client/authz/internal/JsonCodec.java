package com.oviva.telematik.vau.epa4all.client.authz.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class JsonCodec {

  private JsonCodec() {}

  static ObjectMapper mapper =
      new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  public static <T> T readBytes(byte[] data, Class<T> clazz) {
    try {
      return mapper.readValue(data, clazz);
    } catch (IOException e) {
      throw new IllegalArgumentException("invalid JSON", e);
    }
  }

  public static <T> byte[] writeBytes(T o) {
    try {
      return mapper.writeValueAsBytes(o);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("failed to write json", e);
    }
  }
}
