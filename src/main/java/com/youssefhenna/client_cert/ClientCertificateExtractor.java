package com.youssefhenna.client_cert;

import java.security.cert.X509Certificate;

public interface ClientCertificateExtractor {
    X509Certificate extract();
}