package com.youssefhenna.cas;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.cas.model.ReadSessionValuesResult;
import jakarta.annotation.Nullable;

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
import java.util.ArrayList;
import java.util.List;

public class CASClientImpl extends CASClient {
    private final HttpClient httpClient;
    private final ObjectMapper jsonMapper;

    public CASClientImpl(String casAddress, String casPort, String casKeyHash, String casSoftwareKeyHash) {
        super(casAddress, casPort, casKeyHash, casSoftwareKeyHash);
        this.httpClient = HttpClient.newBuilder()
            .sslContext(trustAllSslContext())
            .build();
        this.jsonMapper = new ObjectMapper();
    }



    // CAS has self-signed cert
    private static SSLContext trustAllSslContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Failed to create trust-all SSL context", e);
        }
    }


    private <T> T httpGet(String path, Class<T> responseType) throws IOException, InterruptedException, CASClientException {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://" + casAddress + ":" + casPort + path))
            .GET()
            .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new CASClientException(CASExceptionSource.HTTP, response.statusCode(), response.body());
        }
        return jsonMapper.readValue(response.body(), responseType);
    }

    private String cli(String... args) throws IOException, InterruptedException, CASClientException {
        Process process = new ProcessBuilder(args)
            .redirectErrorStream(false)
            .start();

        String stdout = new String(process.getInputStream().readAllBytes());
        String stderr = new String(process.getErrorStream().readAllBytes());
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new CASClientException(CASExceptionSource.CLI, exitCode, stderr.isBlank() ? stdout : stderr);
        }

        return stdout;
    }

    @Override
    public ReadSessionResult readSession(String name) throws IOException, InterruptedException, CASClientException {
        return this.httpGet("/v1/sessions" + name, ReadSessionResult.class);
    }


    @Override
    public ReadSessionValuesResult readSessionValues(String name, String hash) throws IOException, InterruptedException, CASClientException {
        return this.httpGet("/v1/values/session=" + name + ",session_hash=" + hash, ReadSessionValuesResult.class);
    }

    @Override
    public void attestCas(@Nullable String attestationFlags) throws IOException, InterruptedException, CASClientException {
        String[] extraFlags = {};

        if (attestationFlags != null) {
            if (attestationFlags.contains("-s") || attestationFlags.contains("-c")) {
                throw new CASClientException(CASExceptionSource.CLI, 1, "Cannot include '-s' or '-c' flags in attestation flags");
            }
            extraFlags = attestationFlags.split(" ");
        }

        List<String> args = new ArrayList<>(List.of(
            "scone",
            "attest",
            "cas",
            casAddress + ":" + casPort,
            "-c",
            casKeyHash,
            "-s",
            casSoftwareKeyHash
        ));

        args.addAll(List.of(extraFlags));
        cli(args.toArray(new String[0]));
    }
}