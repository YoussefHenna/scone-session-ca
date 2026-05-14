package com.youssefhenna;

import io.quarkus.tls.runtime.TrustAllOptions;
import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.http.HttpServerOptions;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class MTLSTrustAllCustomizer implements HttpServerOptionsCustomizer {

    @Override
    public void customizeHttpsServer(HttpServerOptions options) {
        // Trust all client certificates at the TLS layer.
        // Actual cert matching is done in the handler.
        options.setTrustOptions(TrustAllOptions.INSTANCE);
    }
}