package com.youssefhenna.model;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;

import java.util.ArrayList;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SessionContents(String name, ArrayList<SessionSecret> secrets) {
    public record SessionSecret(
        String name,
        String kind,
        @JsonProperty("private_key")
        @Nullable
        String privateKey,
        @JsonProperty("export_public")
        @Nullable
        Boolean exportPublic,
        @Nullable
        ArrayList<SessionDefinition> export,
        @Nullable
        String value,
        @Nullable
        String issuer,
        @Nullable
        Boolean migrate
    ){}
    public record SessionDefinition(
        String session,
        @JsonProperty("session_hash")
        @Nullable
        String sessionHash
    ){}

}
