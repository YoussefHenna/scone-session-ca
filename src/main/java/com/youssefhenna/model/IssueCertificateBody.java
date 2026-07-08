package com.youssefhenna.model;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;

public record IssueCertificateBody(
    @NotBlank String casAddress,
    @NotBlank String challengeSession,
    @NotBlank String verifySession,
    @Nullable String verifySessionHash,
    @NotBlank String pemEncodedCSR
) {}
