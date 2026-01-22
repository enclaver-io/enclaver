# Enclaver Internal API

Enclaver provides internal HTTP APIs that allow applications running inside the enclave to perform sensitive operations, such as signing transactions with the enclave's secure key and obtaining high-quality random numbers.

There are two distinct API services available:

1.  **Primary Internal API (`api`)**: Provides full access to all functionality, including signing with custom payloads and generating attestations with custom user data. This is intended for the main application logic.
2.  **Auxiliary API (`aux_api`)**: Provides a restricted subset of functionality. It proxies requests to the internal API but enforces security restrictions, such as sanitizing attestation requests to prevent spoofing of user data. This is intended for sidecars or auxiliary processes.

## Configuration

The ports for these APIs are defined in the `enclaver.yaml` manifest.

**Example `enclaver.yaml` configuration:**

```yaml
api:
  listen_port: 9000

aux_api:
  listen_port: 9001
```

In this example:
- The **Primary API** is available at `http://127.0.0.1:9000`.
- The **Auxiliary API** is available at `http://127.0.0.1:9001`.

If `aux_api` is not explicitly configured, it defaults to `api.listen_port + 1`.

## Primary Internal API Endpoints

The Primary API supports all the endpoints listed below without restrictions.

### Get Ethereum Address

Retrieve the Ethereum address and public key associated with the enclave's secure key.

- **URL:** `/v1/eth/address`
- **Method:** `GET`
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "public_key": "0x04..."
    }
    ```

### Sign Transaction

Sign an Ethereum transaction using the enclave's secure key.

- **URL:** `/v1/eth/sign-tx`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**

  **Option 1: Structured Payload (EIP-1559)**
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

  **Option 2: Raw RLP Payload**
  ```json
  {
    "include_attestation": false,
    "payload": {
      "kind": "raw_rlp",
      "raw_payload": "0x..."
    }
  }
  ```

- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "raw_transaction": "0x02...",
      "transaction_hash": "0x...",
      "signature": "0x...",
      "address": "0x...",
      "attestation": null
    }
    ```

### Get Random Bytes

Obtain cryptographically secure random bytes from the Nitro Secure Module (NSM).

- **URL:** `/v1/random`
- **Method:** `GET`
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "random_bytes": "0x..." // 32 bytes hex encoded
    }
    ```

### Sign Message

Sign a plain-text message using the EIP-191 personal message prefix (`personal_sign`).

- **URL:** `/v1/eth/sign`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "message": "hello world", // plain-text string (must be non-empty)
    "include_attestation": false
  }
  ```
  The service builds the EIP-191 prefix `"\u0019Ethereum Signed Message:\n<len>"`, concatenates it with the provided message, then signs the result.
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "signature": "0x...",
      "address": "0x...",
      "attestation": null
    }
    ```

### Generate Attestation

Generate an attestation document from the Nitro Secure Module.

- **URL:** `/v1/attestation`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "nonce": "base64_encoded_nonce",       // Optional
    "public_key": "PEM_encoded_public_key", // Optional
    "user_data": "base64_encoded_user_data" // Optional
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/cbor`
  - **Body:** Binary CBOR data (Attestation Document)

### Get Encryption Public Key

Retrieve the enclave's P-384 public key for ECDH-based encryption.

- **URL:** `/v1/encryption/public_key`
- **Method:** `GET`
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "public_key_der": "0x3076...",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
    ```

The `public_key_der` is hex-encoded DER (SPKI format), suitable for use in encryption operations.
The `public_key_pem` is PEM format, suitable for use with standard crypto libraries.

### Decrypt Data

Decrypt data sent from a client using ECDH + AES-256-GCM.

- **URL:** `/v1/encryption/decrypt`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "nonce": "0x...",          // Hex-encoded nonce (at least 12 bytes)
    "client_public_key": "0x...", // Hex-encoded DER public key
    "encrypted_data": "0x..."  // Hex-encoded ciphertext with auth tag
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "plaintext": "decrypted string"
    }
    ```

### Encrypt Data

Encrypt data to send to a client using ECDH + AES-256-GCM.

- **URL:** `/v1/encryption/encrypt`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "plaintext": "string to encrypt",
    "client_public_key": "0x..." // Hex-encoded DER public key
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "encrypted_data": "...",     // Hex-encoded ciphertext
      "enclave_public_key": "...", // Hex-encoded DER public key
      "nonce": "..."               // Hex-encoded nonce
    }
    ```

## Auxiliary API Endpoints

The Auxiliary API exposes a **subset** of the Primary API endpoints with the following restrictions:

### Get Ethereum Address (Aux)

- **URL:** `/v1/eth/address`
- **Method:** `GET`
- **Behavior:** Same as Primary API.

### Generate Attestation (Aux)

- **URL:** `/v1/attestation`
- **Method:** `POST`
- **Restrictions:**
  - The `public_key` and `user_data` fields in the request body are **ignored and removed** before forwarding to the Primary API.
  - Only the `nonce` field is preserved.
  - This ensures that the attestation always uses the enclave's default public key and user data (which typically includes the enclave's Ethereum address).

- **Request Body:**
  ```json
  {
    "nonce": "base64_encoded_nonce" // Optional
  }
  ```

### Get Encryption Public Key (Aux)

- **URL:** `/v1/encryption/public_key`
- **Method:** `GET`
- **Behavior:** Same as Primary API.

### Unavailable Endpoints

The following endpoints are **NOT** available on the Auxiliary API:
- `/v1/eth/sign-tx`
- `/v1/eth/sign`
- `/v1/random`
- `/v1/encryption/decrypt`
- `/v1/encryption/encrypt`

Attempts to access these endpoints on the Auxiliary API port will result in a 404 Not Found error.
The following endpoints are also **NOT** available on the Auxiliary API:
- `/v1/s3/get`
- `/v1/s3/put`
- `/v1/s3/delete`
- `/v1/s3/list`

## S3 Storage API Endpoints

The Internal API provides an S3-compatible interface for persistent storage. These endpoints use the enclave's AWS credentials (obtained via IMDS) and enforce key isolation and path traversal protection. If S3 storage is not enabled in `enclaver.yaml`, these endpoints return `400 Bad Request` with `S3 storage not configured`.

### Get Object

Retrieve a base64-encoded object from S3.

- **URL:** `/v1/s3/get`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "key": "relative/path/to/object"
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "value": "base64_encoded_data"
    }
    ```
- **Example:**
  ```bash
  curl -X POST http://127.0.0.1:9000/v1/s3/get \
    -H "Content-Type: application/json" \
    -d '{"key": "config/settings.json"}'
  ```

### Put Object

Upload a base64-encoded object to S3.

- **URL:** `/v1/s3/put`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "key": "relative/path/to/object",
    "value": "base64_encoded_data",
    "content_type": "text/plain" // Optional
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "success": true
    }
    ```
- **Example:**
  ```bash
  # Upload text data (base64 encoded)
  curl -X POST http://127.0.0.1:9000/v1/s3/put \
    -H "Content-Type: application/json" \
    -d '{"key": "data/test.txt", "value": "SGVsbG8gV29ybGQh", "content_type": "text/plain"}'
  ```

### Delete Object

Delete an object from S3.

- **URL:** `/v1/s3/delete`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "key": "relative/path/to/object"
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "success": true
    }
    ```
- **Example:**
  ```bash
  curl -X POST http://127.0.0.1:9000/v1/s3/delete \
    -H "Content-Type: application/json" \
    -d '{"key": "data/test.txt"}'
  ```

### List Objects

List objects in the app's persistent storage.

- **URL:** `/v1/s3/list`
- **Method:** `POST`
- **Content-Type:** `application/json`
- **Request Body:**
  ```json
  {
    "prefix": "optional/subdirectory/",
    "continuation_token": "token_from_previous_response", // Optional
    "max_keys": 100 // Optional
  }
  ```
- **Success Response:**
  - **Code:** 200 OK
  - **Content-Type:** `application/json`
  - **Body:**
    ```json
    {
      "keys": ["file1.txt", "file2.txt"],
      "continuation_token": "next_token", // Null if no more pages
      "is_truncated": false
    }
    ```
- **Example:**
  ```bash
  # List all objects
  curl -X POST http://127.0.0.1:9000/v1/s3/list \
    -H "Content-Type: application/json" \
    -d '{}'

  # List objects with prefix
  curl -X POST http://127.0.0.1:9000/v1/s3/list \
    -H "Content-Type: application/json" \
    -d '{"prefix": "data/", "max_keys": 50}'
  ```
