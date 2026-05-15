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
    export:
      - session: <VERIFY_SESSION_NAME>
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
- `CA_CERT_FILE`*: Path to the main CA cert file. Used for issuing of certificates. The certificate end clients use to verify an issued cert.
- `CA_PRIVATE_KEY_FILE`*: Path to the private key file of `CA_CERT_FILE`. Used for signing issued certs
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
- `CAS_ATTESTION_FLAGS`: Additional flags used in the attestation call. Same flags as used in `scone cas attest <ADDR> <FLAGS>`. Should ideally not be set, but useful for development and testing.

\*  required
## Running in dev mode

You can run your application in dev mode that enables live coding using:

```shell script
./mvnw quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at <http://localhost:8080/q/dev/>.

## Building the image

Package using:

```shell script
./mvnw package
```

It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory. Then build the image:

```shell script
docker build -f src/main/docker/Dockerfile.jvm -t scone-session-ca .
```

Then run
```shell script
docker run -i --rm -p 8080:8080 scone-session-ca
```

Also see [other docker options](src/main/docker)


