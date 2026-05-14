package com.youssefhenna.cas;

import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.cas.model.ReadSessionValuesResult;
import jakarta.annotation.Nullable;

import java.io.IOException;

public abstract class CASClient {
    protected final String casAddress;
    protected final String casPort;
    protected final String casKeyHash;
    protected final String casSoftwareKeyHash;

    public CASClient(String casAddress, String casPort, String casKeyHash, String casSoftwareKeyHash) {
        this.casAddress = casAddress;
        this.casPort = casPort;
        this.casKeyHash = casKeyHash;
        this.casSoftwareKeyHash = casSoftwareKeyHash;
    }

    public abstract ReadSessionResult readSession(String name) throws IOException, InterruptedException, CASClientException;
    public abstract void attestCas(@Nullable String attestationFlags) throws IOException, InterruptedException, CASClientException;
    public abstract ReadSessionValuesResult readSessionValues(String name, String hash) throws IOException, InterruptedException, CASClientException;

    public enum CASExceptionSource {
        CLI,
        HTTP,
    }

    public static class CASClientException extends Exception {
        private final int statusCode;
        private final CASExceptionSource exceptionSource;

        public CASClientException(CASExceptionSource source, int statusCode, String body) {
            super("CAS " + source + " request failed with status " + statusCode + ": " + body);
            this.statusCode = statusCode;
            this.exceptionSource = source;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public CASExceptionSource getExceptionSource() {
            return exceptionSource;
        }
    }
}