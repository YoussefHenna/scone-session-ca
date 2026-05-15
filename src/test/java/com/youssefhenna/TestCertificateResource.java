package com.youssefhenna;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestCertificateResource implements QuarkusTestResourceLifecycleManager {

    public static X509Certificate CLIENT_CERT;
    public static String CLIENT_CERT_PEM;
    public static KeyPair CLIENT_KEY_PAIR;

    private final List<File> tempFiles = new ArrayList<>();

    @Override
    public Map<String, String> start() {
        try {
            // 1. Generate CA key pair and self-signed certificate
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096);
            KeyPair caKeyPair = kpg.generateKeyPair();

            X500Principal caSubject = new X500Principal("CN=Test CA");
            X509Certificate caCert = buildSelfSignedCert(caSubject, BigInteger.ONE, caKeyPair);
            String caCertPem = encodePem(caCert);
            String caPrivateKeyPem = encodePem(caKeyPair.getPrivate());

            // 2. Generate server TLS key pair, reuse CA cert as server cert for simplicity
            KeyPairGenerator serverKpg = KeyPairGenerator.getInstance("RSA");
            serverKpg.initialize(2048);
            KeyPair serverKeyPair = serverKpg.generateKeyPair();
            X500Principal serverSubject = new X500Principal("CN=localhost");
            X509Certificate serverCert = buildSelfSignedCert(serverSubject, BigInteger.TWO, serverKeyPair);
            String serverCertPem = encodePem(serverCert);
            String serverPrivateKeyPem = encodePem(serverKeyPair.getPrivate());

            // 3. Generate client certificate signed by the CA
            KeyPairGenerator clientKpg = KeyPairGenerator.getInstance("RSA");
            clientKpg.initialize(2048);
            KeyPair clientKeyPair = clientKpg.generateKeyPair();
            X500Principal clientSubject = new X500Principal("CN=Test Client");
            X509Certificate clientCert = buildSignedCert(clientSubject, BigInteger.valueOf(3), clientKeyPair, caCert, caKeyPair);
            String clientCertPem = encodePem(clientCert);

            // Store in static fields for test access
            CLIENT_CERT = clientCert;
            CLIENT_CERT_PEM = clientCertPem;
            CLIENT_KEY_PAIR = clientKeyPair;

            // 4. Write CA cert to temp file
            File caCertFile = writeTempFile("ca-cert-", ".pem", caCertPem);
            System.setProperty("CA_CERT_FILE", caCertFile.getAbsolutePath());

            // 5. Write CA private key to temp file
            File caKeyFile = writeTempFile("ca-key-", ".pem", caPrivateKeyPem);
            System.setProperty("CA_PRIVATE_KEY_FILE", caKeyFile.getAbsolutePath());

            // 6. Write server cert to temp file
            File serverCertFile = writeTempFile("server-cert-", ".pem", serverCertPem);
            System.setProperty("TLS_CERT_FILE", serverCertFile.getAbsolutePath());

            // 7. Write server private key to temp file
            File serverKeyFile = writeTempFile("server-key-", ".pem", serverPrivateKeyPem);
            System.setProperty("TLS_PRIVATE_KEY_FILE", serverKeyFile.getAbsolutePath());

            // 8. Write trusted CAS config JSON to temp file
            String trustedCasJson = """
                {"trustedCasList":[{"casAddress":"test-cas","casPort":"8080","casKeyHash":"test-key-hash","casSoftwareKeyHash":"test-sw-key-hash"}]}
                """.strip();
            File trustedCasFile = writeTempFile("trusted-cas-", ".json", trustedCasJson);
            System.setProperty("TRUSTED_CAS_CONFIG_FILE", trustedCasFile.getAbsolutePath());

            // Also set quarkus.profile so Utils.isTestEnvironment() returns true
            System.setProperty("quarkus.profile", "test");

            // 10. Return config map with TLS file paths for Quarkus config substitution
            Map<String, String> config = new HashMap<>();
            config.put("TLS_CERT_FILE", serverCertFile.getAbsolutePath());
            config.put("TLS_PRIVATE_KEY_FILE", serverKeyFile.getAbsolutePath());
            return config;

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize test certificates", e);
        }
    }

    @Override
    public void stop() {
        for (File f : tempFiles) {
            f.delete();
        }
        tempFiles.clear();
    }

    private File writeTempFile(String prefix, String suffix, String content) throws IOException {
        File file = File.createTempFile(prefix, suffix);
        file.deleteOnExit();
        Files.writeString(file.toPath(), content);
        tempFiles.add(file);
        return file;
    }

    private X509Certificate buildSelfSignedCert(X500Principal subject, BigInteger serial, KeyPair keyPair) throws Exception {
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private X509Certificate buildSignedCert(X500Principal subject, BigInteger serial, KeyPair subjectKeyPair,
                                             X509Certificate issuerCert, KeyPair issuerKeyPair) throws Exception {
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        X500Principal issuerPrincipal = issuerCert.getSubjectX500Principal();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerPrincipal, serial, notBefore, notAfter, subject, subjectKeyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static String encodePem(Object object) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(object);
        }
        return sw.toString();
    }
}