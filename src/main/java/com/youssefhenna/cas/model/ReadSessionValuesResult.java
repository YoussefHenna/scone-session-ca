package com.youssefhenna.cas.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.annotation.Nullable;

import java.util.ArrayList;


public record ReadSessionValuesResult(ArrayList<SessionValue> values) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SessionValue(String kind, @Nullable String expires, String value){}
}
