package com.youssefhenna.cas;


import com.youssefhenna.cas.model.ReadSessionResult;

import java.io.IOException;

public interface CASClient {

    ReadSessionResult readSession(String name) throws IOException, InterruptedException, CASClientException;
    void attestCas() throws IOException, InterruptedException, CASClientException;

    enum CASExceptionSource {
        CLI,
        HTTP,
    }

    class CASClientException extends Exception {
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
        public CASExceptionSource getExceptionSource(){
            return exceptionSource;
        }
    }
}
