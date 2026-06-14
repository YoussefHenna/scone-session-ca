# scone-session-ca

This is a sample CA (Certificate Authority) that verifies a service is running confidentially in a [SCONE](https://sconedocs.github.io/latest/) based enclave. Issues certificates to services that can prove they are running confidentially using a given [SCONE session](https://sconedocs.github.io/latest/CAS_session_lang_0_3/) verified by a given [SCONE CAS](https://sconedocs.github.io/latest/helm_cas/). An issued certificate extends the verification of the CAS to publicly verifiable certificate format.


## How it works
### Step 1
The service admin that is requesting verification creates a SCONE session for the CA challenge. One that follows these requirments:
 - A CAS generated private key secret that is used to for a CAS generated certificate
 - Private key is exported to a single session, the session service admins wants to verify against
 - Private key is non-migratable
   - In the case private key leaks, service admin can update the session to generate a new one. Preventing leaked key from being used for further certificate issuance
 - Certificate is generated using the given private key
 - Certificate is exported publicly

```yaml
name: <CA_CHALLENGE_SESSION_NAME>
version: "0.3.10"

access_policy:
  read:
   - ANY
  update:
   - CREATOR

secrets:
  - name: challenge-private-key
    kind: private-key
    migrate: false # can ommit, default is false
    export:
      - session: <VERIFY_SESSION_NAME>

  - name: challenge-cert
    kind: x509
    private_key: challenge-private-key
    export_public: true
```

### Step 2
Service that is running confidentially under the previously selected SCONE session (<VERIFY_SESSION_NAME>) makes a POST request to the CA with the given requirements:
- Request through mTLS connection with CA, with client certificate matching the certificate created in the challenge SCONE session.
  - Possible since confidential service would have access to the private key of said certificate
- Makes a request with the following body format:
```json
{
  "casAddress": "<CAS_ADDRESS>",
  "challengeSession": " <CA_CHALLENGE_SESSION_NAME>",
  "verifySession":"<VERIFY_SESSION_NAME>",
  "pemEncodedCSR": "<PEM_ENCODED_CERTIFICATE_SIGNING_REQUEST>"
}
```

### Step 3
CA issues signed certificate if the following conditions are met:
- The provided CAS is within the trusted list of the CA
- The CAS can be attested successfully
- The challenge session is queryable through the CAS
- The challenge session follows the correct format and requirements
- The request is made through an mTLS connection with the certificate in the challenge session.

At that stage, the CA provides a response in the following format
```json
{
  "pemEncodedCertificate": "<PEM_ENCODED_SIGNED_CERT>",
  "expiresAt": "<DATE_OF_CERT_EXPIRY>"
}
```
### Step 4
Service can use signed certificate to prove it is running confidentially under a given session under a specific CAS. The certificate is bounded and includes the following proven fields:
- Verified session name
- CAS address where verification was confirmed
- CAS Key Hash where verification was confirmed
- CAS Software Key Hash where verification was confirmed

An external auditor, **if they trust the CA**, can trust a service is running confidentially with this verified session under this CAS upon receiving this certficate.

# Why this works
The main point of verification in the challenge is the mTLS connection with the CAS generated certificate and private key. Only an authentic confidential service under that session could have been able to get access to that private key. As such the CA can state that the service connecting to it is authentic.


# Dev & Deployment
This project uses Quarkus, to learn more about Quarkus, please visit its website: <https://quarkus.io/>.


## Environment variables
Set these in the shell when running dev mode, or when running the image.
- `CA_CERT_FILE`*: Path to the main CA cert file. Used for issuing of certificates. The certificate end clients use to verify an issued cert. Certificate must be generated wit CA capabilities (signing)
- `CA_PRIVATE_KEY_FILE`*: Path to the private key file of `CA_CERT_FILE`. Used for signing issued certs
- `TLS_CERT_FILE`*: Path to the TLS cert file. Used for service->CA communication. Certificate for 'localhost' for local dev, or to hosted domain.
- `TLS_PRIVATE_KEY_FILE`*: Path to the private key file of `TLS_PRIVATE_KEY_FILE`
- `TRUSTED_CAS_CONFIG_FILE`*: Path to a json config file that specifies trusted CAS's. In the following format
```json
{
  "trustedCasList":[
    {
      "casAddress":"<CAS_ADDRESS>",
      "casPort":"<CAS_PORT>",
      "casKeyHash":"<CAS_KEY_HASH>",
      "casSoftwareKeyHash":"<CAS_SW_KEY_HASH>"
    }
  ]
}
```
- `STATIC_CHALLENGE_SESSIONS_CONFIG_FILE`: Path to a json config file that specifies a limited set of pre-created challenge sessions that the CA allows for verification. 
```json
{
  "staticChallengeSessions": [
    {
      "casAddress":"<CAS_ADDRESS>",
      "casPort":"<CAS_PORT>",
      "challengeSession": "<CHALLENGE_SESSION_NAME>",
      "verifySession": "<VERIFY_SESSION_NAME>"
    }
  ]
}
```
- `CAS_ATTESTION_FLAGS`: Additional flags used in the attestation call. Same flags as used in `scone cas attest <ADDR> <FLAGS>`. Should ideally not be set, but useful for development and testing.

\*  required

## Static Challenges
Using the `STATIC_CHALLENGE_SESSIONS_CONFIG_FILE` environment variable, one can set a limited set of challenge sessions that can be used by the CA for verification. This allows for a targeted CA deployment that can be responsible for verification of a specific service. 

Using a non-limited CA deployment means the CA can verify any session, which adds the extra step on the consumer of the certificate to verify the session is the correct one that is expected. With a static set of challenge sessions in a deployed CA, a consumer can trust a service solely based on the certificate, knowing that the CA would only verify the known and previously established sessions. Eliminating the extra step on the consumer to check the verified session, a certificate that chains to the CA would be sufficient for trust.

## Certificates
For testing purposes, one may use the certificates [here](./test-certs).

## Running in dev mode

You can run your application in dev mode that enables live coding using:

```shell script
./mvnw quarkus:dev
```

> **_NOTE:_**  You need to have the `scone` cli available locally for CAS attestation to work.

To run with testing certs + config

```shell script
CA_CERT_FILE=test-certs/ca.crt \
CA_PRIVATE_KEY_FILE=test-certs/ca.key \
TLS_CERT_FILE=test-certs/tls.pem \
TLS_PRIVATE_KEY_FILE=test-certs/tls.key \
TRUSTED_CAS_CONFIG_FILE=test-certs/trusted-cas-config.json \
CAS_ATTESTION_FLAGS='--only_for_testing-debug --only_for_testing-ignore-signer --only_for_testing-trust-any -GCS' \
./mvnw quarkus:dev
```

## Building the image

Package using:

```shell script
./mvnw package
```

It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory. Then build the image:

```shell script
docker build -f src/main/docker/Dockerfile.jvm -t scone-session-ca .
```

> **_NOTE:_**  You need to have access to https://gitlab.scontain.com/scone.cloud to be able to build the image

Then run
```shell script
docker run -i --rm -p 8443:8443 scone-session-ca
```

To run with testing certs + config

```shell script
docker run -i --rm -p 8443:8443 \
  -v $(pwd)/test-certs:/test-certs \
  -e CA_CERT_FILE=/test-certs/ca.crt \
  -e CA_PRIVATE_KEY_FILE=/test-certs/ca.key \
  -e TLS_CERT_FILE=/test-certs/tls.pem \
  -e TLS_PRIVATE_KEY_FILE=/test-certs/tls.key \
  -e TRUSTED_CAS_CONFIG_FILE=/test-certs/trusted-cas-config.json \
  -e CAS_ATTESTION_FLAGS='--only_for_testing-debug --only_for_testing-ignore-signer --only_for_testing-trust-any -GCS' \
  scone-session-ca
```

Image also available from
```
ghcr.io/youssefhenna/scone-session-ca:latest
```

## Port 
Quarkus runs https on port 8443 

## Running Confidentially
TODO, yet to be done. Can only be deployed as a standard service for now. Ideally CA itself runs confidentially and has self-signed cerfticate that proves so. CA root certificate and key can be CAS generated, making the root of trust be based on CAS. 

