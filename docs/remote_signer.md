## Mega++ additions (v24.8.0)
- Audit log now records the *real* client certificate SHA-256 fingerprint per request (extracted from the TLS connection).

# Remote Signer

Un remote signer îți permite să păstrezi cheia privată în afara nodului (pe un host securizat), iar nodul / tool-urile trimit doar mesaje de semnat.

Repo-ul include un client simplu: `iona::crypto::remote_signer::RemoteSigner`.

## HTTP API (contract)

### `GET /pubkey`

Răspuns:

```json
{ "pubkey_base64": "<ed25519-pubkey-bytes-base64>" }
```

### `POST /sign`

Request:

```json
{ "msg_base64": "<bytes-to-sign-base64>" }
```

Response:

```json
{ "sig_base64": "<ed25519-signature-bytes-base64>" }
```

## Recomandări securitate

- Rulează remote signer-ul pe o rețea privată (mTLS / VPN).
- Rate limit strict + allowlist de IP.
- Log minim (fără payload-uri sensibile).
- Ideal: HSM/YubiKey sau enclavă.

## Mega-step security (mTLS + allowlist + audit)

This release ships an optional *reference implementation* of a remote signer server:

- Binary: `iona-remote-signer`
- mTLS is **required** (client certificate must be presented)
- Clients are enforced via an **allowlist** of client certificate SHA-256 fingerprints
- Every signing request is appended to an **audit log** (JSONL)

### Running the server

```bash
cargo run --bin iona-remote-signer -- \
  --listen 0.0.0.0:9100 \
  --key-path ./data/remote_signer_key.bin \
  --tls-cert-pem ./deploy/tls/server.crt.pem \
  --tls-key-pem  ./deploy/tls/server.key.pem \
  --client-ca-pem ./deploy/tls/ca.crt.pem \
  --allowlist ./deploy/tls/allowlist.txt \
  --audit-log ./data/remote_signer_audit.jsonl
```

### Allowlist format

`deploy/tls/allowlist.txt` contains one SHA-256 fingerprint (hex) per line.
Lines starting with `#` are ignored.

### Client configuration

Use `[signing]` in `config.toml` to point the node/tooling to the remote signer.
For mTLS, provide:

- `remote_tls_client_cert_pem` (client cert PEM)
- `remote_tls_client_key_pem` (client key PEM)
- `remote_tls_ca_cert_pem` (CA cert PEM)

