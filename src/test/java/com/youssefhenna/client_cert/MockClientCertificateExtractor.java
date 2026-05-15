package com.youssefhenna.client_cert;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import java.security.cert.X509Certificate;

@Alternative
@Priority(1)
@ApplicationScoped
public class MockClientCertificateExtractor implements ClientCertificateExtractor {

    private X509Certificate cert;

    public void setCert(X509Certificate cert) {
        this.cert = cert;
    }

    @Override
    public X509Certificate extract() {
        if (cert == null) {
            throw new WebApplicationException("No client certificate provided", Response.Status.FORBIDDEN);
        }
        return cert;
    }
}