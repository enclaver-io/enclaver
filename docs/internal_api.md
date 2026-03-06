# Enclaver Internal API

Enclaver exposes localhost-only HTTP APIs inside the enclave.

There are two services:

- Primary API: full `/v1/*` surface from `enclaver/src/api.rs`
- Aux API: a restricted proxy surface from `enclaver/src/aux_api.rs`

Both servers bind `127.0.0.1`, not `0.0.0.0`.

## Configuration

Example manifest:

```yaml
api:
  listen_port: 18000

aux_api:
  listen_port: 18001
```

Current implementation details:

- the Primary API is enabled only when `api.listen_port` is configured
- if the Primary API is enabled, the Aux API also starts by default
- if `aux_api.listen_port` is omitted, Aux API binds `api.listen_port + 1` when that value fits in `u16`
- there is no separate `enabled` flag for Aux API today

The API request body limit is 10 MiB.

## Primary API

### `GET /v1/eth/address`

Returns the enclave Ethereum key identity:

```json
{
  "address": "0x...",
  "public_key": "0x..."
}
```

`public_key` is the enclave secp256k1 public key in hex.

### `POST /v1/eth/sign`

Signs a non-empty UTF-8 string using the Ethereum personal-sign prefix.

Request:

```json
{
  "message": "hello world",
  "include_attestation": false
}
```

Response:

```json
{
  "signature": "0x...",
  "address": "0x...",
  "attestation": null
}
```

If `include_attestation=true`, `attestation` is a base64-encoded CBOR attestation document whose nonce is the message hash and whose public key is the enclave Ethereum key.

### `POST /v1/eth/sign-tx`

Signs an EIP-1559 transaction.

Structured request:

```json
{
  "include_attestation": false,
  "payload": {
    "kind": "structured",
    "chain_id": "0x1",
    "nonce": "0x0",
    "max_priority_fee_per_gas": "0x3b9aca00",
    "max_fee_per_gas": "0x77359400",
    "gas_limit": "0x5208",
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "value": "0xde0b6b3a7640000",
    "data": "0x",
    "access_list": []
  }
}
```

Raw-RLP request:

```json
{
  "include_attestation": false,
  "payload": {
    "kind": "raw_rlp",
    "raw_payload": "0x..."
  }
}
```

Response:

```json
{
  "raw_transaction": "0x02...",
  "transaction_hash": "0x...",
  "signature": "0x...",
  "address": "0x...",
  "attestation": null
}
```

If `include_attestation=true`, the attestation nonce is the finalized transaction hash.

### `GET /v1/random`

Returns 32 random bytes:

```json
{
  "random_bytes": "0x..."
}
```

Production uses NSM-backed randomness. Tests fall back to `OsRng`.

### `POST /v1/attestation`

Generates an NSM attestation document.

Request:

```json
{
  "nonce": "base64-encoded bytes",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "user_data": {
    "custom": "value"
  }
}
```

Rules:

- `nonce` is optional and base64-decoded if present
- `public_key` is optional PEM; if omitted, the enclave P-384 encryption public key is used
- `user_data` is optional, but when present it must be a JSON object
- the API always injects `eth_addr` into `user_data`
- if app-wallet material is available quickly enough, it also injects `app_wallet`
- if the caller already provided `eth_addr` or `app_wallet`, the injected values win

Response:

- status: `200 OK`
- content type: `application/cbor`
- body: raw CBOR attestation document bytes

### `GET /v1/encryption/public_key`

Returns the enclave P-384 public key:

```json
{
  "public_key_der": "0x3076...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

### `POST /v1/encryption/decrypt`

Decrypts client data using P-384 ECDH + HKDF-SHA256 + AES-256-GCM.

Request:

```json
{
  "nonce": "0x...",
  "client_public_key": "0x...",
  "encrypted_data": "0x..."
}
```

Rules:

- hex values may be sent with or without `0x`
- `client_public_key` is DER/SPKI
- the normal nonce length is 12 bytes
- for backward compatibility, a 32-byte legacy nonce is still accepted and truncated to its first 12 bytes
- the API rejects nonce reuse for the same `client_public_key`
- decrypted plaintext must be valid UTF-8

Response:

```json
{
  "plaintext": "decrypted string"
}
```

### `POST /v1/encryption/encrypt`

Encrypts plaintext back to a client.

Request:

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

- unlike most other endpoints, this response uses raw hex strings without a `0x` prefix

## S3 storage endpoints

These routes exist only when `storage.s3.enabled=true`.

If S3 is not configured, they return:

- status: `400 Bad Request`
- body: `S3 storage not configured`

Key rules:

- keys may not contain `..`
- keys may not start with `/`
- missing objects return `404 Not Found`

### `POST /v1/s3/get`

Request:

```json
{
  "key": "relative/path/to/object"
}
```

Response:

```json
{
  "value": "base64-encoded bytes",
  "content_type": "text/plain"
}
```

`content_type` is omitted when unavailable.

### `POST /v1/s3/put`

Request:

```json
{
  "key": "relative/path/to/object",
  "value": "base64-encoded bytes",
  "content_type": "text/plain"
}
```

Response:

```json
{
  "success": true
}
```

### `POST /v1/s3/delete`

Request:

```json
{
  "key": "relative/path/to/object"
}
```

Response:

```json
{
  "success": true
}
```

### `POST /v1/s3/list`

Request:

```json
{
  "prefix": "optional/sub-prefix",
  "continuation_token": "optional-token",
  "max_keys": 100
}
```

Response:

```json
{
  "keys": ["a.txt", "b/c.txt"],
  "continuation_token": null,
  "is_truncated": false
}
```

If `storage.s3.encryption.mode=kms`, KMS integration must also be enabled.

## Nova KMS endpoints

These routes are usable only when:

- `kms_integration.enabled=true`
- registry discovery is configured with both `kms_app_id` and `nova_app_registry`

If KMS integration is entirely absent, the API returns:

- status: `400 Bad Request`
- body: `KMS integration not configured`

Transient registry/authz failures return:

- status: `503 Service Unavailable`
- header: `Retry-After: 10`

Validation and non-transient failures return `400 Bad Request`.

### `POST /v1/kms/derive`

Request:

```json
{
  "path": "app/session/alpha",
  "context": "optional-context",
  "length": 32
}
```

Defaults:

- `context`: empty string
- `length`: `32`

Response:

```json
{
  "key": "base64-encoded key bytes"
}
```

Some derive paths are reserved internally and are rejected.

### `POST /v1/kms/kv/get`

Request:

```json
{
  "key": "config/service_token"
}
```

Found response:

```json
{
  "found": true,
  "value": "base64-encoded opaque value"
}
```

Missing-key response:

- status: `404 Not Found`

```json
{
  "found": false,
  "value": null
}
```

### `POST /v1/kms/kv/put`

Request:

```json
{
  "key": "config/service_token",
  "value": "base64-encoded opaque value",
  "ttl_ms": 60000
}
```

Response:

```json
{
  "success": true
}
```

`ttl_ms` defaults to `0`.

### `POST /v1/kms/kv/delete`

Request:

```json
{
  "key": "config/service_token"
}
```

Response:

```json
{
  "success": true
}
```

## App-wallet endpoints

These routes require:

- `kms_integration.enabled=true`
- `kms_integration.use_app_wallet=true`

Current implementation detail:

- app-wallet APIs run in enclave-local mode
- responses currently report `app_id: 0`

If the app-wallet service is unavailable or disabled, these routes return:

- status: `503 Service Unavailable`
- header: `Retry-After: 10`
- body: plain-text error starting with `App wallet service unavailable:`

### `GET /v1/app-wallet/address`

Response:

```json
{
  "address": "0x...",
  "app_id": 0,
  "instance_wallet": "0x..."
}
```

`instance_wallet` is the local enclave instance wallet when it can be resolved.

### `POST /v1/app-wallet/sign`

Request:

```json
{
  "message": "hello app wallet"
}
```

Response:

```json
{
  "signature": "0x...",
  "address": "0x...",
  "app_id": 0
}
```

### `POST /v1/app-wallet/sign-tx`

Request schema is the same as `/v1/eth/sign-tx`.

Implementation detail:

- `include_attestation` is accepted by the request parser but ignored
- app-wallet transaction signing never returns an attestation field

Response:

```json
{
  "raw_transaction": "0x02...",
  "transaction_hash": "0x...",
  "signature": "0x...",
  "address": "0x...",
  "app_id": 0
}
```

## Aux API

Aux API exposes only:

- `GET /v1/eth/address`
- `POST /v1/attestation`
- `GET /v1/encryption/public_key`

All other routes return `404 Not Found`.
Unsupported methods on supported paths return `405 Method Not Allowed`.

### `GET /v1/eth/address`

Exact proxy to the Primary API.

### `GET /v1/encryption/public_key`

Exact proxy to the Primary API.

### `POST /v1/attestation`

Aux API sanitizes the request before forwarding it:

- removes `public_key`
- preserves `nonce`
- preserves `user_data`

This means external callers cannot override the default attestation public key, but can still provide custom `user_data` that will later receive injected `eth_addr` and optional `app_wallet`.

Special behaviors:

- empty request body becomes `{}`
- invalid non-empty JSON returns `400 Bad Request`
- successful responses include `Access-Control-Allow-Origin: *`
- `OPTIONS /v1/attestation` returns CORS preflight headers

CORS preflight response:

- status: `204 No Content`
- headers:
  - `Access-Control-Allow-Origin: *`
  - `Access-Control-Allow-Methods: POST, OPTIONS`
  - `Access-Control-Allow-Headers: Content-Type`
  - `Access-Control-Max-Age: 86400`

If the Primary API is unreachable, Aux API returns:

- status: `503 Service Unavailable`
- content type: `application/json`

```json
{
  "error": "Internal API service unavailable"
}
```

## Related documents

- `docs/encryption.md`
- `docs/odyn.md`
- `docs/port_handling.md`
