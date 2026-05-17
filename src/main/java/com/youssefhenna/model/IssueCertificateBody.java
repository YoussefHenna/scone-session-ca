package com.youssefhenna.model;

import jakarta.validation.constraints.NotBlank;

public record IssueCertificateBody(
    @NotBlank String casAddress,
    @NotBlank String challengeSession,
    @NotBlank String verifySession,
    @NotBlank String pemEncodedCSR
) {}
