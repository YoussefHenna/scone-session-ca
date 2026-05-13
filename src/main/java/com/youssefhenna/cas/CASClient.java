package com.youssefhenna.cas;


import java.io.IOException;

public interface CASClient {

    String readSession(String name) throws IOException, InterruptedException, CASClientException;


    class CASClientException extends Exception {
        private final int statusCode;

        public CASClientException(int statusCode, String body) {
            super("CAS request failed with status " + statusCode + ": " + body);
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}
