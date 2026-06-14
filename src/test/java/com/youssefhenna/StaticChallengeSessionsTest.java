package com.youssefhenna;

import com.youssefhenna.cas.MockCASClient;
import com.youssefhenna.cas.MockCASClientFactory;
import com.youssefhenna.cas.model.ReadSessionResult;
import com.youssefhenna.client_cert.MockClientCertificateExtractor;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.youssefhenna.TestUtils.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@QuarkusTestResource(TestCertificateResource.class)
@QuarkusTestResource(StaticChallengeSessionsTestResource.class)
class StaticChallengeSessionsTest {

    @Inject
    MockCASClientFactory mockCASClientFactory;

    @Inject
    MockClientCertificateExtractor mockClientCertificateExtractor;

    @BeforeEach
    void setup() {
        MockCASClient client = mockCASClientFactory.getClient();
        client.setAttest(flags -> {});
        client.setReadSession(name -> { throw new RuntimeException("readSession not configured"); });
        client.setReadValues((n, h) -> { throw new RuntimeException("readValues not configured"); });
        mockClientCertificateExtractor.setCert(TestCertificateResource.CLIENT_CERT);
    }

    @Test
    void should_issueCertificate_when_sessionMatchesStaticConfig() throws Exception {
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
            .body("pemEncodedCertificate", notNullValue());
    }

    @Test
    void should_return403_when_challengeSessionNotInStaticConfig() throws Exception {
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "test-cas:8080",
                "challengeSession", "/other-session",
                "verifySession", "/my-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return403_when_verifySessionNotInStaticConfig() throws Exception {
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "test-cas:8080",
                "challengeSession", "/my-session",
                "verifySession", "/other-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return403_when_casAddressNotInStaticConfig() throws Exception {
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "other-cas:8080",
                "challengeSession", "/my-session",
                "verifySession", "/my-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return403_when_casPortNotInStaticConfig() throws Exception {
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "test-cas:9999",
                "challengeSession", "/my-session",
                "verifySession", "/my-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }

    @Test
    void should_return403_when_casAddressHasNoPort() throws Exception {
        // Port-less addresses default to "8081"; static config has "8080" → no match
        String csrPem = generateCSR();

        given()
            .contentType(ContentType.JSON)
            .body(Map.of(
                "casAddress", "test-cas",
                "challengeSession", "/my-session",
                "verifySession", "/my-verify-session",
                "pemEncodedCSR", csrPem
            ))
            .when().post("/issue-certificate")
            .then()
            .statusCode(403);
    }
}