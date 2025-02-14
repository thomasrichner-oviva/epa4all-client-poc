package com.oviva.telematik.vau.epa4all.client.entitlement.internal;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PostEntitlementRequest(@JsonProperty("jwt") String jwt) {}
