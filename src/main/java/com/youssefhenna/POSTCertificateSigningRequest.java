package com.youssefhenna;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.youssefhenna.cas.CASClient;
import com.youssefhenna.cas.CASClientImpl;
import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.model.IssueCertificateBody;
import com.youssefhenna.model.IssueCertificateResponse;
import com.youssefhenna.model.SessionContents;
import com.youssefhenna.model.TrustedCASConfig;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

@Path("/issue-certificate")
public class POSTCertificateSigningRequest {

    @Inject
    RoutingContext routingContext;

    private TrustedCASConfig trustedCASConfig;

    @PostConstruct
    void init() {
        try {
            String configFile = Utils.requireEnv("TRUSTED_CAS_CONFIG_FILE");
            trustedCASConfig = new ObjectMapper().readValue(new File(configFile), TrustedCASConfig.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load trusted CAS config file", e);
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public IssueCertificateResponse issueCertificate(IssueCertificateBody body) {
        X509Certificate clientCertificate = getClientCertificate();

        TrustedCASConfig.TrustedCAS trustedCAS = findTrustedCAS(body.casAddress());
        CASClient casClient = new CASClientImpl(trustedCAS.casAddress(), trustedCAS.casPort(), trustedCAS.casKeyHash(), trustedCAS.casSoftwareKeyHash());
        attestCAS(casClient);

        String challengeCertificatePEM = validateChallengeSessionReturningCert(casClient, body.challengeSession(), body.verifySession());
        verifyClientCertMatchesChallenge(clientCertificate, challengeCertificatePEM);

        return CertificateSigner.sign(body.pemEncodedCSR(), trustedCAS, body.verifySession());
    }

    private TrustedCASConfig.TrustedCAS findTrustedCAS(String casAddress) {
        String[] parts = casAddress.split(":", 2);
        String host = parts[0];
        String port = parts.length > 1 ? parts[1] : null;

        return trustedCASConfig.trustedCasList().stream()
            .filter(cas -> cas.casAddress().equals(host) && (port == null || cas.casPort().equals(port)))
            .findFirst()
            .orElseThrow(() -> new WebApplicationException("CAS address not known: " + casAddress, Response.Status.FORBIDDEN));
    }

    private void attestCAS(CASClient casClient) {
        try {
            casClient.attestCas(System.getenv("CAS_ATTESTION_FLAGS"));
        } catch (CASClient.CASClientException e) {
            throw new WebApplicationException("CAS attestation failed: " + e.getMessage(), Response.Status.FORBIDDEN);
        } catch (IOException | InterruptedException e) {
            throw new WebApplicationException("CAS attestation error: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private String validateChallengeSessionReturningCert(CASClient casClient, String challengeSession, String verifySession) {
        SessionContents contents;
        String sessionHash;
        try {
            ReadSessionResult result = casClient.readSession(challengeSession);
            String sessionYaml = result.session();
            contents = new ObjectMapper(new YAMLFactory()).readValue(sessionYaml, SessionContents.class);
            sessionHash = result.hash();
        } catch (CASClient.CASClientException e) {
            throw new WebApplicationException("Failed to read challenge session: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (IOException | InterruptedException e) {
            throw new WebApplicationException("Challenge session read error: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }

        SessionContents.SessionSecret privateKeySecret = contents.secrets().stream()
            .filter(s ->
                s.kind().equals("private-key")
                    && s.export() != null
                    && s.export().size() == 1
                    && s.export().getFirst().session().equals(verifySession)
                    && s.value() == null
                    && (s.migrate() == null || s.migrate().equals(Boolean.FALSE))
            )
            .findFirst()
            .orElseThrow(() -> new WebApplicationException(
                "Challenge session must have a non-migratable private-key secret exported to exactly the verify session with no explicit value", Response.Status.BAD_REQUEST));

        contents.secrets().stream()
            .filter(s ->
                s.kind().equals("x509")
                    && s.exportPublic() != null
                    && s.exportPublic().equals(Boolean.TRUE)
                    && s.privateKey() != null
                    && s.privateKey().equals(privateKeySecret.name())
                    && s.issuer() == null
                    && s.value() == null
            )
            .findFirst()
            .orElseThrow(() -> new WebApplicationException(
                "Challenge session must have an x509 secret with export_public=true referencing the private-key secret, no issuer, and no explicit value", Response.Status.BAD_REQUEST));

        return readChallengeCertificate(casClient, challengeSession, sessionHash);
    }

    private String readChallengeCertificate(CASClient casClient, String session, String sessionHash) {
        try {
            var result = casClient.readSessionValues(session, sessionHash);

            var cert = result.values().stream()
                .filter(v -> v.kind().equals("x509"))
                .findFirst()
                .orElseThrow(() -> new WebApplicationException("No x509 value found in challenge session public values", Response.Status.BAD_REQUEST));

            if (cert.expires() != null && Instant.now().isAfter(Instant.parse(cert.expires()))) {
                throw new WebApplicationException("Challenge certificate has expired", Response.Status.BAD_REQUEST);
            }

            return cert.value();
        } catch (CASClient.CASClientException e) {
            throw new WebApplicationException("Failed to read challenge session values: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (IOException | InterruptedException e) {
            throw new WebApplicationException("Challenge session values read error: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private X509Certificate getClientCertificate() {
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

    private void verifyClientCertMatchesChallenge(X509Certificate clientCert, String challengeCertPEM) {
        X509Certificate challengeCert;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            challengeCert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(challengeCertPEM.getBytes(StandardCharsets.UTF_8))
            );
        } catch (CertificateException e) {
            throw new WebApplicationException("Invalid challenge certificate: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
        if (!clientCert.equals(challengeCert)) {
            throw new WebApplicationException("Client certificate does not match challenge certificate", Response.Status.FORBIDDEN);
        }
    }
}