package com.youssefhenna.model;

public record IssueCertificateBody(String casAddress, String challengeSession, String verifySession, String pemEncodedCSR) {
}
