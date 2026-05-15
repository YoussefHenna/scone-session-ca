package com.youssefhenna.client_cert;

import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@RequestScoped
public class ClientCertificateExtractorImpl implements ClientCertificateExtractor {

    @Inject
    RoutingContext routingContext;

    @Override
    public X509Certificate extract() {
        SSLSession sslSession = routingContext.request().sslSession();
        if (sslSession == null) {
            throw new WebApplicationException("Connection is not over TLS", Response.Status.FORBIDDEN);
        }
        try {
            Certificate[] certs = sslSession.getPeerCertificates();
            return (X509Certificate) certs[0];
        } catch (SSLPeerUnverifiedException e) {
            throw new WebApplicationException("No client certificate provided", Response.Status.FORBIDDEN);
        }
    }
}