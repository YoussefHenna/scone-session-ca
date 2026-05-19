package com.youssefhenna;

import com.youssefhenna.cas.CASClient;
import com.youssefhenna.cas.MockCASClient;
import com.youssefhenna.cas.MockCASClientFactory;
import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.cas.model.ReadSessionValuesResult;
import com.youssefhenna.client_cert.MockClientCertificateExtractor;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static com.youssefhenna.TestUtils.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@QuarkusTestResource(TestCertificateResource.class)
class POSTCertificateSigningRequestTest {

    @Inject
    MockCASClientFactory mockCASClientFactory;

    @Inject
    MockClientCertificateExtractor mockClientCertificateExtractor;

    @BeforeEach
    void setup() {
        MockCASClient client = mockCASClientFactory.getClient();
        client.setAttest(flags -> {}); // succeeds by default
        client.setReadSession(name -> { throw new RuntimeException("readSession not configured"); });
        client.setReadValues((n, h) -> { throw new RuntimeException("readValues not configured"); });
        mockClientCertificateExtractor.setCert(TestCertificateResource.CLIENT_CERT);
    }

    @Test
    void should_returnSignedCertificate_when_validRequest() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> new ReadSessionResult("hash123", validSessionYaml("/my-verify-session")));
        client.setReadValues((n, h) -> valuesWithClientCert());

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(200)
            .body("pemEncodedCertificate", notNullValue())
            .body("expiresAt", notNullValue());
    }

    @Test
    void should_return403_when_casAddressIsNotTrusted() throws Exception {
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "unknown-cas:9999",
                "challengeSession", "/my-session",
                "verifySession", "/my-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return403_when_casAttestationFails() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setAttest(flags -> {
            throw new CASClient.CASClientException(CASClient.CASExceptionSource.CLI, 1, "error");
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return400_when_readSessionThrowsCASClientException() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> {
            throw new CASClient.CASClientException(CASClient.CASExceptionSource.HTTP, 404, "not found");
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return500_when_readSessionThrowsIOException() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> {
            throw new java.io.IOException("connection refused");
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(500);
    }

    @Test
    void should_return400_when_sessionHasNoPrivateKeySecret() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_privateKeyExportedToWrongSession() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /other-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_privateKeySecretHasExplicitValue() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                value: some-secret-value
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_privateKeySecretIsMigratable() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                migrate: true
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_sessionHasNoX509Secret() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /my-verify-session
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_x509SecretHasIssuer() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
                issuer: some-issuer
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_x509SecretHasExplicitValue() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
                value: something
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_x509SecretMissingExportPublic() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: my-private-key
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_x509SecretReferencesWrongPrivateKey() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        String sessionYaml = """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: /my-verify-session
              - name: my-cert
                kind: x509
                private_key: other-key
                export_public: true
            """;
        client.setReadSession(name -> new ReadSessionResult("hash123", sessionYaml));

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_sessionValuesHaveNoX509Value() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> new ReadSessionResult("hash123", validSessionYaml("/my-verify-session")));
        client.setReadValues((n, h) -> {
            ReadSessionValuesResult.SessionValue value = new ReadSessionValuesResult.SessionValue("private-key", null, "some-value");
            return new ReadSessionValuesResult(Map.of("my-cert", value));
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return400_when_challengeCertIsExpired() throws Exception {
        String csrPem = generateCSR();
        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> new ReadSessionResult("hash123", validSessionYaml("/my-verify-session")));
        client.setReadValues((n, h) -> {
            String pastExpiry = Instant.now().minus(1, ChronoUnit.HOURS).toString();
            ReadSessionValuesResult.SessionValue value = new ReadSessionValuesResult.SessionValue("x509", pastExpiry, TestCertificateResource.CLIENT_CERT_PEM);
            return new ReadSessionValuesResult(Map.of("my-cert", value));
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(400);
    }

    @Test
    void should_return403_when_clientCertDoesNotMatchChallengeCert() throws Exception {
        String csrPem = generateCSR();
        String differentCertPem = generateFreshCertPem();

        MockCASClient client = mockCASClientFactory.getClient();
        client.setReadSession(name -> new ReadSessionResult("hash123", validSessionYaml("/my-verify-session")));
        client.setReadValues((n, h) -> {
            ReadSessionValuesResult.SessionValue value = new ReadSessionValuesResult.SessionValue("x509", null, differentCertPem);
            return new ReadSessionValuesResult(Map.of("my-cert", value));
        });

        given()
            .contentType(ContentType.JSON)
            .body(requestBody(csrPem))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }
}