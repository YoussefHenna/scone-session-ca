package com.youssefhenna.cas;

import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.cas.model.ReadSessionValuesResult;

import java.io.IOException;

public class MockCASClient extends CASClient {

    @FunctionalInterface
    public interface ReadSessionFn {
        ReadSessionResult apply(String name) throws IOException, InterruptedException, CASClient.CASClientException;
    }

    @FunctionalInterface
    public interface AttestFn {
        void apply(String flags) throws IOException, InterruptedException, CASClient.CASClientException;
    }

    @FunctionalInterface
    public interface ReadValuesFn {
        ReadSessionValuesResult apply(String name, String hash) throws IOException, InterruptedException, CASClient.CASClientException;
    }

    private ReadSessionFn readSessionFn = name -> {
        throw new RuntimeException("readSession not configured");
    };

    private AttestFn attestFn = flags -> {
        // default: succeed silently
    };

    private ReadValuesFn readValuesFn = (n, h) -> {
        throw new RuntimeException("readSessionValues not configured");
    };

    public MockCASClient() {
        super("mock", "0", "mock-key-hash", "mock-sw-key-hash");
    }

    public void setReadSession(ReadSessionFn fn) {
        this.readSessionFn = fn;
    }

    public void setAttest(AttestFn fn) {
        this.attestFn = fn;
    }

    public void setReadValues(ReadValuesFn fn) {
        this.readValuesFn = fn;
    }

    @Override
    public ReadSessionResult readSession(String name) throws IOException, InterruptedException, CASClient.CASClientException {
        return readSessionFn.apply(name);
    }

    @Override
    public void attestCas(String flags) throws IOException, InterruptedException, CASClient.CASClientException {
        attestFn.apply(flags);
    }

    @Override
    public ReadSessionValuesResult readSessionValues(String name, String hash) throws IOException, InterruptedException, CASClient.CASClientException {
        return readValuesFn.apply(name, hash);
    }
}