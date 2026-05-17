package com.youssefhenna;

import com.youssefhenna.model.IssueCertificateResponse;
import com.youssefhenna.model.TrustedCASConfig;
import io.quarkus.arc.log.LoggerName;
import io.quarkus.logging.Log;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;


public class CertificateSigner {

    // OIDs encoding custom metadata into issued certificates.
    // https://www.iana.org/assignments/enterprise-numbers/
    // 99999 Used as placeholders with unlikley clash. Production usage should use a registered PEN
    private static final ASN1ObjectIdentifier CAS_ADDRESS_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");
    private static final ASN1ObjectIdentifier CAS_KEY_HASH_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.2");
    private static final ASN1ObjectIdentifier CAS_SW_KEY_HASH_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.3");
    private static final ASN1ObjectIdentifier VERIFIED_SESSION_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.4");


    private static final int CERT_EXPIRY_DAYS = 1;
    private static X509Certificate CA_CERT;
    private static PrivateKey CA_PRIVATE_KEY;

    static void init() {
        try {
            CA_CERT = parseCert(Files.readString(Path.of(Utils.requireEnv("CA_CERT_FILE"))));
            CA_PRIVATE_KEY = parsePrivateKey(Files.readString(Path.of(Utils.requireEnv("CA_PRIVATE_KEY_FILE"))));
            Log.warn("NOT FOR PRODUCTION USE. TO USE FOR PRODUCTION:\n- REGISTER REAL PEN AT https://www.iana.org/assignments/enterprise-numbers/ AND UPDATE OIDs.\n- IMPLEMENT SERIAL COUNTER LOGIC INSTEAD OF CURRENT RANDOM SERIAL LOGIC WITH REVOCATION ABILITY.");
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Failed to load CA certificate and key", e);
        }
    }

    private CertificateSigner() {
    }

    public static IssueCertificateResponse sign(
        String pemEncodedCSR,
        TrustedCASConfig.TrustedCAS trustedCAS,
        String verifySession
    ) {
        PKCS10CertificationRequest csr = parseCsr(pemEncodedCSR);
        verifyCsrSignature(csr);

        Instant now = Instant.now();
        Instant expiry = now.plus(CERT_EXPIRY_DAYS, ChronoUnit.DAYS);
        // uses random serial, should use a centralized global counter in production environments
        BigInteger serial = new BigInteger(128, new SecureRandom());
        String casFullAddress = trustedCAS.casAddress() + ":" + trustedCAS.casPort();

        try {
            PublicKey subjectPublicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                CA_CERT,
                serial,
                Date.from(now),
                Date.from(expiry),
                csr.getSubject(),
                subjectPublicKey
            );
            certBuilder.addExtension(CAS_ADDRESS_OID, false, new DERUTF8String(casFullAddress));
            certBuilder.addExtension(CAS_KEY_HASH_OID, false, new DERUTF8String(trustedCAS.casKeyHash()));
            certBuilder.addExtension(CAS_SW_KEY_HASH_OID, false, new DERUTF8String(trustedCAS.casSoftwareKeyHash()));
            certBuilder.addExtension(VERIFIED_SESSION_OID, false, new DERUTF8String(verifySession));

            // enforce issued cert only used for TLS
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            certBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithmFor(CA_PRIVATE_KEY)).build(CA_PRIVATE_KEY);
            X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

            return new IssueCertificateResponse(encodePem(signedCert, CA_CERT), expiry.toString());
        } catch (Exception e) {
            throw new WebApplicationException("Certificate signing failed: " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    public static PKCS10CertificationRequest parseCsr(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                throw new WebApplicationException("Invalid CSR: expected PKCS#10 format", Response.Status.BAD_REQUEST);
            }
            return csr;
        } catch (IOException e) {
            throw new WebApplicationException("Failed to parse CSR: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    public static void verifyCsrSignature(PKCS10CertificationRequest csr) {
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo());
            if (!csr.isSignatureValid(verifier)) {
                throw new WebApplicationException("CSR signature is invalid", Response.Status.BAD_REQUEST);
            }
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            throw new WebApplicationException("CSR signature verification failed: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    public static X509Certificate parseCert(String pem) throws IOException, CertificateException {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) parser.readObject());
        }
    }

    public static PrivateKey parsePrivateKey(String pem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            PrivateKeyInfo keyInfo = obj instanceof PEMKeyPair kp ? kp.getPrivateKeyInfo() : (PrivateKeyInfo) obj;
            return new JcaPEMKeyConverter().getPrivateKey(keyInfo);
        }
    }

    public static String signatureAlgorithmFor(PrivateKey key) {
        return switch (key.getAlgorithm()) {
            case "EC" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            default ->
                throw new WebApplicationException("Unsupported CA key algorithm: " + key.getAlgorithm(), Response.Status.INTERNAL_SERVER_ERROR);
        };
    }

    public static String encodePem(X509Certificate... certs) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            for (X509Certificate cert : certs) {
                writer.writeObject(cert);
            }
        }
        return sw.toString();
    }
}