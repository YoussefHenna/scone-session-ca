package com.youssefhenna.cas.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;

import java.util.Map;


public record ReadSessionValuesResult(Map<String, SessionValue> values) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SessionValue(String kind, @Nullable String expires, String value){}
}