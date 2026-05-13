package com.youssefhenna.cas;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.youssefhenna.cas.model.ReadSessionResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;


public class HttpCASClient implements CASClient {
    private final String casAddress;
    private final int casPort;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public HttpCASClient(String casAddress, int casPort) {
        this.casAddress = casAddress;
        this.casPort = casPort;
        this.httpClient = HttpClient.newBuilder()
                .sslContext(trustAllSslContext())
                .build();
        this.objectMapper = new ObjectMapper();
    }

    //TODO: Going to shell to cli istead
    // -c $CAS_KEY_HASH \
    // -s $CAS_SOFTWARE_KEY_HASH
    // these args verify correct CAS and pinned in CA deployment
    // also accept a general attestion flags env so that anyone can set anything

    // CAS's use self-signed certificates and are implicitly SSL trusted
    // Attestation step establishes trust in enclave state
    private static SSLContext trustAllSslContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Failed to create trust-all SSL context", e);
        }
    }

    private <T> T get(String path, Class<T> responseType) throws IOException, InterruptedException, CASClientException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + casAddress + ":" + casPort + path))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new CASClientException(response.statusCode(), response.body());
        }
        return objectMapper.readValue(response.body(), responseType);
    }

    private <T> T put(String path, Object body, Class<T> responseType) throws IOException, InterruptedException, CASClientException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + casAddress + ":" + casPort + path))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new CASClientException(response.statusCode(), response.body());
        }
        return objectMapper.readValue(response.body(), responseType);
    }

    @Override
    public ReadSessionResponse readSession(String name) throws IOException, InterruptedException, CASClientException {
        return this.get("/v1/sessions" + name, ReadSessionResponse.class);
    }


}
