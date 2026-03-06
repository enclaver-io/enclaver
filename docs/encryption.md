# Enclaver Encryption Guide

This document describes the transport-encryption primitives that `odyn` exposes today.

It is intentionally scoped to repository behavior. It does not describe an external platform reverse proxy or application-specific request format.

## What Enclaver provides

`odyn` exposes these building blocks:

- `POST /v1/attestation`
- `GET /v1/encryption/public_key`
- `POST /v1/encryption/decrypt`
- `POST /v1/encryption/encrypt`
- optional signing endpoints such as `POST /v1/eth/sign`

Your application decides:

- how clients send encrypted application payloads
- which ingress or HTTP endpoint receives them
- when to call the Internal API to decrypt or encrypt data

## Why this exists

Ingress traffic reaches the enclave through host-side proxies. That path is not end-to-end encrypted by default. If the host is part of your threat model, application payloads should be encrypted to the enclave itself rather than only to the host edge.

## Cryptographic protocol

`odyn` uses:

| Component | Value |
|-----------|-------|
| Key agreement | P-384 ECDH |
| KDF | HKDF-SHA256 |
| HKDF info | `enclaver-ecdh-aes256gcm-v1` |
| Symmetric cipher | AES-256-GCM |
| Normal nonce length | 12 bytes |

The shared AES key is derived from:

```text
shared_secret = ECDH(client_private, enclave_public)
salt = sort_lexicographically(client_pub_sec1, enclave_pub_sec1) || nonce
aes_key = HKDF-SHA256(shared_secret, salt, "enclaver-ecdh-aes256gcm-v1")
```

Important interoperability details:

- the API exchanges public keys in DER/SPKI form
- internally, HKDF salt construction uses the uncompressed SEC1 form of both public keys
- public keys are sorted lexicographically as raw bytes before concatenation
- `odyn` rejects nonce reuse for the same client public key on decrypt

## Endpoint behavior

### `GET /v1/encryption/public_key`

Returns the enclave P-384 public key:

```json
{
  "public_key_der": "0x3076...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

Use this together with attestation if you need to bind the encryption key to an enclave identity.

### `POST /v1/encryption/decrypt`

Decrypt request:

```json
{
  "nonce": "0x...",
  "client_public_key": "0x...",
  "encrypted_data": "0x..."
}
```

Behavior:

- hex inputs may include or omit `0x`
- `client_public_key` is DER/SPKI
- plaintext output must be valid UTF-8
- legacy 32-byte nonces are still accepted for backward compatibility; the first 12 bytes are used
- duplicate `(client_public_key, nonce)` pairs are rejected

Response:

```json
{
  "plaintext": "decrypted string"
}
```

### `POST /v1/encryption/encrypt`

Encrypt request:

```json
{
  "plaintext": "string to encrypt",
  "client_public_key": "0x..."
}
```

Response:

```json
{
  "encrypted_data": "a1b2c3...",
  "enclave_public_key": "3076...",
  "nonce": "d4e5f6..."
}
```

Important detail:

- this response returns raw hex strings without `0x`

## Attestation and key binding

`POST /v1/attestation` can carry the encryption key in the attestation document.

If the request omits `public_key`, `odyn` uses the enclave P-384 encryption public key by default.

Request:

```json
{
  "nonce": "base64-encoded bytes",
  "user_data": {
    "session": "abc"
  }
}
```

Response:

- content type: `application/cbor`
- body: raw CBOR attestation document

`user_data` handling:

- must be a JSON object when present
- `odyn` always injects `eth_addr`
- if app-wallet material is available, it may also inject `app_wallet`

## Typical client flow

1. Fetch attestation and/or `public_key_der`.
2. Verify the attestation or otherwise establish trust in the enclave key.
3. Generate a client P-384 keypair.
4. Convert both public keys to uncompressed SEC1 form.
5. Derive the shared secret with ECDH.
6. For each message:
   - generate a fresh 12-byte nonce
   - derive a fresh AES key with HKDF using `sorted_pubkeys || nonce`
   - encrypt with AES-256-GCM
7. Send the ciphertext, nonce, and client DER public key to your application endpoint.
8. Inside the enclave, your application calls `odyn` decrypt/encrypt endpoints as needed.

## Response signing

Encryption and signing are separate features.

`POST /v1/encryption/encrypt` does not attach an Ethereum signature automatically.
If your protocol wants signed responses, call a signing endpoint separately, for example:

- `POST /v1/eth/sign`
- `POST /v1/app-wallet/sign`

## Minimal application pattern

Inside the enclave:

1. receive encrypted application payload from your own ingress or HTTP route
2. call `POST /v1/encryption/decrypt`
3. process plaintext in your app
4. call `POST /v1/encryption/encrypt` for the response
5. optionally call a signing endpoint if your protocol requires signatures

## Security notes

- host-edge TLS is not the same as enclave end-to-end encryption
- wall-clock time is not part of this encryption trust model
- replay protection on decrypt is per `(client_public_key, nonce)` pair
- nonce uniqueness is still the client's responsibility

## Related documents

- `docs/internal_api.md`
- `docs/odyn.md`
- `docs/nitro_enclave_clock_drift.md`
