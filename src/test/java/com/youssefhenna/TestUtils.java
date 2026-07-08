package com.youssefhenna;

import com.youssefhenna.cas.model.ReadSessionValuesResult;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

public class TestUtils {

    private TestUtils() {}

    public static String generateCSR() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
            new X500Principal("CN=Test"), kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(csr);
        }
        return sw.toString();
    }

    public static String generateFreshCertPem() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Principal subject = new X500Principal("CN=Other Client");
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(99), notBefore, notAfter, subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        return TestCertificateResource.encodePem(cert);
    }

    public static String validSessionYaml(String verifySession) {
        return """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: %s
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """.formatted(verifySession);
    }

    public static String validSessionYamlWithHash(String verifySession, String sessionHash) {
        return """
            name: my-session
            secrets:
              - name: my-private-key
                kind: private-key
                export:
                  - session: %s
                    session_hash: %s
              - name: my-cert
                kind: x509
                private_key: my-private-key
                export_public: true
            """.formatted(verifySession, sessionHash);
    }

    public static ReadSessionValuesResult valuesWithClientCert() {
        ReadSessionValuesResult.SessionValue value = new ReadSessionValuesResult.SessionValue("x509", null, TestCertificateResource.CLIENT_CERT_PEM);
        return new ReadSessionValuesResult(Map.of("my-cert", value));
    }

    public static Map<String, Object> requestBody(String csrPem) {
        return Map.of(
            "casAddress", "test-cas:8080",
            "challengeSession", "/my-session",
            "verifySession", "/my-verify-session",
            "pemEncodedCSR", csrPem
        );
    }

    public static Map<String, Object> requestBody(String csrPem, String verifySessionHash) {
        return Map.of(
            "casAddress", "test-cas:8080",
            "challengeSession", "/my-session",
            "verifySession", "/my-verify-session",
            "verifySessionHash", verifySessionHash,
            "pemEncodedCSR", csrPem
        );
    }

    public static String certExtensionValue(String pemCert, String oid) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(pemCert.getBytes(StandardCharsets.UTF_8)));
        byte[] raw = cert.getExtensionValue(oid);
        if (raw == null) {
            return null;
        }
        ASN1OctetString envelope = ASN1OctetString.getInstance(raw);
        ASN1Primitive value = ASN1Primitive.fromByteArray(envelope.getOctets());
        return DERUTF8String.getInstance(value).getString();
    }
}