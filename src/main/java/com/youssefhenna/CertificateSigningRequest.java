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
import jakarta.annotation.PostConstruct;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;

@Path("/issue-certificate")
public class CertificateSigningRequest {

    private TrustedCASConfig trustedCASConfig;
    private String caCert;
    private String caPrivateKey;

    @PostConstruct
    void init() throws IOException {
        String configFile = Utils.requireEnv("TRUSTED_CAS_CONFIG_FILE");
        trustedCASConfig = new ObjectMapper().readValue(new File(configFile), TrustedCASConfig.class);
        caCert = Files.readString(java.nio.file.Path.of(Utils.requireEnv("CA_CERT_FILE")));
        caPrivateKey = Files.readString(java.nio.file.Path.of(Utils.requireEnv("CA_PRIVATE_KEY_FILE")));
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public IssueCertificateResponse issueCertificate(IssueCertificateBody body) {
        TrustedCASConfig.TrustedCAS trustedCAS = findTrustedCAS(body.casAddress());
        CASClient casClient = new CASClientImpl(trustedCAS.casAddress(), trustedCAS.casPort(), trustedCAS.casKeyHash(), trustedCAS.casSoftwareKeyHash());
        attestCAS(casClient);

        String challengeCertificatePEM = validateChallengeSessionReturningCert(casClient, body.challengeSession(), body.verifySession());
        //TODO: Verify mTLS connection with this cert, if passes, can issue certificate

        return null;
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
            )
            .findFirst()
            .orElseThrow(() -> new WebApplicationException(
                "Challenge session must have a private-key secret exported to exactly the verify session with no explicit value", Response.Status.BAD_REQUEST));

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

}
