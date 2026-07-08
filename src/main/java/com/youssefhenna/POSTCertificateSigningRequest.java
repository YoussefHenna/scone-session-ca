package com.youssefhenna;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.youssefhenna.cas.CASClient;
import com.youssefhenna.cas.CASClientFactory;
import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.cas.model.ReadSessionValuesResult;
import com.youssefhenna.client_cert.ClientCertificateExtractor;
import com.youssefhenna.model.*;
import io.quarkus.logging.Log;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Nullable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;

@ApplicationScoped
@Path("/issue-certificate")
public class POSTCertificateSigningRequest {

    @Inject
    CASClientFactory casClientFactory;

    @Inject
    ClientCertificateExtractor clientCertificateExtractor;

    private TrustedCASConfig trustedCASConfig;

    @Nullable
    private StaticChallengeSessionsConfig staticChallengeSessionsConfig;

    // Called by quarkus on startup
    void onStart(@Observes StartupEvent ev) {
        CertificateSigner.init();
        try {
            String trustedCasConfigFile = Utils.requireEnv("TRUSTED_CAS_CONFIG_FILE");
            trustedCASConfig = new ObjectMapper().readValue(new File(trustedCasConfigFile), TrustedCASConfig.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load trusted CAS config file", e);
        }

        try {
            String staticChallengeSessionConfigFile = Utils.getEnv("STATIC_CHALLENGE_SESSIONS_CONFIG_FILE");
            if (staticChallengeSessionConfigFile != null) {
                staticChallengeSessionsConfig = new ObjectMapper().readValue(new File(staticChallengeSessionConfigFile), StaticChallengeSessionsConfig.class);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load trusted static challenge sessions config file", e);
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public IssueCertificateResponse issueCertificate(@Valid IssueCertificateBody body) {
        try {
            checkIsChallengeSessionAllowed(body);

            X509Certificate clientCertificate = clientCertificateExtractor.extract();

            TrustedCASConfig.TrustedCAS trustedCAS = findTrustedCAS(body.casAddress());
            CASClient casClient = casClientFactory.create(trustedCAS);
            attestCAS(casClient);

            String challengeCertificatePEM = validateChallengeSessionReturningCert(casClient, body.challengeSession(), body.verifySession(), body.verifySessionHash());
            verifyClientCertMatchesChallenge(clientCertificate, challengeCertificatePEM);

            IssueCertificateResponse response = CertificateSigner.sign(body.pemEncodedCSR(), trustedCAS, body.verifySession(), body.verifySessionHash());
            Log.info("Issued cert for verified session: " + body.verifySession());
            return response;
        } catch (Exception e) {
            Log.error("Issuing of certificate for session '" + body.verifySession() + "' failed for reason: " + e.getMessage());
            throw e;
        }
    }

    private void checkIsChallengeSessionAllowed(IssueCertificateBody body) {
        if (staticChallengeSessionsConfig == null) {
            // no static challenges config, all allowed
            return;
        }

        String[] parts = extractAddressAndPort(body.casAddress());
        String host = parts[0];
        String port = parts[1];

        boolean isInStaticChallengeSessions = staticChallengeSessionsConfig.staticChallengeSessions().stream().anyMatch(staticChallengeSession ->
            staticChallengeSession.casAddress().equals(host)
                && staticChallengeSession.casPort().equals(port)
                && staticChallengeSession.verifySession().equals(body.verifySession())
                && staticChallengeSession.challengeSession().equals(body.challengeSession()
            )
        );

        if (!isInStaticChallengeSessions) {
            throw new WebApplicationException("Provided sessions and/or CAS combination are not allowed verification.", Response.Status.FORBIDDEN);
        }
    }

    private TrustedCASConfig.TrustedCAS findTrustedCAS(String casAddress) {
        String[] parts = extractAddressAndPort(casAddress);
        String host = parts[0];
        String port = parts[1];

        return trustedCASConfig.trustedCasList().stream()
            .filter(cas -> cas.casAddress().equals(host) && cas.casPort().equals(port))
            .findFirst()
            .orElseThrow(() -> new WebApplicationException("CAS address not known or trusted: " + casAddress, Response.Status.FORBIDDEN));
    }

    private String[] extractAddressAndPort(String casAddress) {
        String defaultCASPort = "8081";
        String[] parts = casAddress.split(":", 2);
        String host = parts[0];
        String port = parts.length > 1 ? parts[1] : defaultCASPort;

        return new String[]{host, port};
    }

    private void attestCAS(CASClient casClient) {
        try {
            casClient.attestCas(Utils.getEnv("CAS_ATTESTION_FLAGS"));
        } catch (CASClient.CASClientException e) {
            throw new WebApplicationException("CAS attestation failed: " + e.getMessage(), Response.Status.FORBIDDEN);
        } catch (IOException | InterruptedException e) {
            throw new WebApplicationException("CAS attestation error: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private String validateChallengeSessionReturningCert(CASClient casClient, String challengeSession, String verifySession, String verifySessionHash) {
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

        validateVerifySessionHash(privateKeySecret.export().getFirst(), verifySessionHash);

        SessionContents.SessionSecret certSecret = contents.secrets().stream()
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

        return readChallengeCertificate(casClient, certSecret.name(), challengeSession, sessionHash);
    }


    private void validateVerifySessionHash(SessionContents.SessionDefinition export, String verifySessionHash) {
        String pinnedHash = export.sessionHash();

        if (pinnedHash == null) {
            if (verifySessionHash != null) {
                throw new WebApplicationException(
                    "verifySessionHash was provided but the challenge session does not pin a session hash", Response.Status.BAD_REQUEST);
            }
            return;
        }

        if (verifySessionHash == null) {
            throw new WebApplicationException(
                "Challenge session pins a session hash, verifySessionHash must be provided", Response.Status.BAD_REQUEST);
        }
        if (!pinnedHash.equals(verifySessionHash)) {
            throw new WebApplicationException(
                "Provided verifySessionHash does not match the session hash pinned by the challenge session", Response.Status.BAD_REQUEST);
        }
    }

    private String readChallengeCertificate(CASClient casClient, String certSecretName, String session, String sessionHash) {
        try {
            ReadSessionValuesResult result = casClient.readSessionValues(session, sessionHash);
            ReadSessionValuesResult.SessionValue certValue = result.values().get(certSecretName);

            if (certValue == null) {
                throw new WebApplicationException("No value found for '" + certSecretName + "' in challenge session public values", Response.Status.BAD_REQUEST);
            }
            if (!certValue.kind().equals("x509")) {
                throw new WebApplicationException("Expected x509 kind for '" + certSecretName + "' but got: " + certValue.kind(), Response.Status.BAD_REQUEST);
            }
            if (certValue.expires() != null && Instant.now().isAfter(Instant.parse(certValue.expires()))) {
                throw new WebApplicationException("Challenge certificate has expired", Response.Status.BAD_REQUEST);
            }

            return certValue.value();
        } catch (CASClient.CASClientException e) {
            throw new WebApplicationException("Failed to read challenge session values: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (IOException | InterruptedException e) {
            throw new WebApplicationException("Challenge session values read error: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
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