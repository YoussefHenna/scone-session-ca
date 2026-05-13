


- Client first creates CAS session with a CAS generated certificate where the private key is only shared with the session they would like to get a certificate for
```yaml
name: osv-scanner/ca-challenge
version: "0.3.10"

access_policy:
  read:
   - ANY
  update:
   - CREATOR

secrets:
  - name: challenge-private-key
    kind: private-key
    export:
      - session: osv-scanner/scanner

  - name: challenge-cert
    kind: x509
    private_key: challenge-private-key
    export_public: true
    export:
      - session: osv-scanner/scanner
```


- Client makes mTLS request to CA with the given details
```json
{
  "cas": "<cas address>",
  "challenge_session": "osv-scanner/ca-challenge",
  "verify_session":"osv-scanner/scanner"
}
```

- CA attests CAS, makes sure CAS is valid
- CA reads challenge_session from CAS
  - Ensures private key only shared with verify_session
  - Reads public certificate from session
- CA verifies mTLS connection uses same certficate provided in challenge_session
- If valid, issues certificate bounded to given CAS address and verify_session
- Since only an attested service could have access to private key, proves running confidentially under this CAS. 
