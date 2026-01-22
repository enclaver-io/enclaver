# Internal API Mock Service

This document describes the **Mock Service** for the Enclaver Internal API, provided for local development and testing outside the enclave environment.

## Overview

Since Odyn only works inside an actual AWS Nitro Enclave environment, we provide a **Mock Service** that simulates all Odyn API endpoints. This allows developers to develop and test their applications locally without access to an enclave.

## Mock Service Endpoint

```
Mock Base URL: http://odyn.sparsity.cloud:18000
```

> [!NOTE]
> This mock service simulates all Odyn API endpoints and can be used for development and testing purposes.

## Environment-Based Endpoint Configuration

We recommend using the `IN_ENCLAVE` environment variable to automatically switch between development and production environments:

### Python Example

```python
import os

# Choose Odyn endpoint based on environment variable
IN_ENCLAVE = os.getenv("IN_ENCLAVE", "false").lower() == "true"

if IN_ENCLAVE:
    ODYN_BASE_URL = "http://localhost:18000"
else:
    ODYN_BASE_URL = "http://odyn.sparsity.cloud:18000"
```

### Dockerfile Configuration

```dockerfile
# Default to false during development
ENV IN_ENCLAVE=false

# When deployed to enclave, this will be set to true by Odyn
```

### Environment Summary

| Environment | IN_ENCLAVE | Odyn Base URL |
|-------------|------------|---------------|
| Local Development/Testing | `false` | `http://odyn.sparsity.cloud:18000` |
| Enclave Production | `true` | `http://localhost:18000` |

---

## Python Wrapper Class

The following `Odyn` class provides a complete wrapper for interacting with the Odyn API:

```python
"""
Enclave helper class for interacting with enclaver's odyn API.

This module provides a simple interface to the odyn API running on localhost:18000
inside the enclave environment, or the mock service during development.
"""

import json
import requests
from typing import Dict, Any, Optional, Tuple
import os
import base64


class Odyn:
    """Wrapper for enclaver's odyn API with encryption support."""

    DEFAULT_MOCK_ODYN_API = "http://odyn.sparsity.cloud:18000"

    def __init__(self, endpoint: Optional[str] = None):
        """
        Initialize the Odyn helper.

        Args:
            endpoint: The odyn API endpoint. If None, it automatically chooses
                between localhost:18000 (in enclave) and the mock API.
        """
        if endpoint:
            self.endpoint = endpoint
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = "http://localhost:18000" if is_enclave else self.DEFAULT_MOCK_ODYN_API

    def eth_address(self) -> str:
        """
        Get the Ethereum address from the enclave.

        Returns:
            The Ethereum address as a string.
        """
        res = requests.get(f"{self.endpoint}/v1/eth/address", timeout=10)
        res.raise_for_status()
        return res.json()["address"]

    def get_attestation(self) -> bytes:
        """
        Get the attestation document as raw CBOR binary.

        Returns:
            Raw CBOR attestation document bytes.
        """
        encryption_pub_data = self.get_encryption_public_key_data()
        encryption_pub_key_pem = encryption_pub_data["public_key_pem"]

        payload = {
            "nonce": "",
            "public_key": encryption_pub_key_pem,
        }

        res = requests.post(
            f"{self.endpoint}/v1/attestation",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        return res.content

    def get_encryption_public_key_data(self) -> Dict[str, str]:
        """
        Retrieve the enclave's encryption public key data.

        Returns:
            Dict containing 'public_key_der' (hex) and 'public_key_pem'.
        """
        res = requests.get(f"{self.endpoint}/v1/encryption/public_key", timeout=10)
        res.raise_for_status()
        return res.json()

    def get_encryption_public_key_der(self) -> bytes:
        """
        Get the encryption public key in DER format.

        Returns:
            DER-encoded public key bytes.
        """
        pub_data = self.get_encryption_public_key_data()
        pub_key_hex = pub_data["public_key_der"]
        if pub_key_hex.startswith("0x"):
            pub_key_hex = pub_key_hex[2:]
        return bytes.fromhex(pub_key_hex)

    def get_random_bytes(self, count: int = 32) -> bytes:
        """
        Get random bytes from the enclave.

        Args:
            count: Number of random bytes to generate.

        Returns:
            Random bytes.
        """
        res = requests.get(f"{self.endpoint}/v1/random", timeout=10)
        res.raise_for_status()
        random_hex = res.json()["random_bytes"]
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)[:count]

    def sign_message(self, data: Dict[str, Any]) -> str:
        """
        Sign a dict payload by canonical JSON then /v1/eth/sign (EIP-191).
        
        Args:
            data: Dictionary to sign (will be JSON serialized).
            
        Returns:
            Hex signature string.
        """
        message = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return self.sign_data(message)

    def sign_data(self, data: str) -> str:
        """
        Sign plain text data using enclaver's /v1/eth/sign (EIP-191).
        
        Args:
            data: Plain text string to sign.
            
        Returns:
            Hex signature without 0x prefix.
        """
        try:
            res = requests.post(
                f"{self.endpoint}/v1/eth/sign",
                json={"message": data, "include_attestation": False},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            res.raise_for_status()
            sig = res.json()["signature"]
            return sig[2:] if sig.startswith("0x") else sig
        except Exception as e:
            import logging
            logging.warning(f"Signing failed (dev mode): {e}")
            return ""

    def decrypt_data(self, nonce_hex: str, client_public_key_hex: str,
                     encrypted_data_hex: str) -> str:
        """
        Decrypt data encrypted by a client using Odyn API.

        Args:
            nonce_hex: Nonce in hex
            client_public_key_hex: Client's ephemeral public key (DER format, hex)
            encrypted_data_hex: AES-GCM encrypted data (hex)

        Returns:
            Decrypted plaintext string
        """
        nonce_bytes = bytes.fromhex(nonce_hex)
        if len(nonce_bytes) > 12:
            nonce_hex = nonce_bytes[:12].hex()

        payload = {
            "nonce": nonce_hex if nonce_hex.startswith("0x") else f"0x{nonce_hex}",
            "client_public_key": client_public_key_hex if client_public_key_hex.startswith("0x") else f"0x{client_public_key_hex}",
            "encrypted_data": encrypted_data_hex if encrypted_data_hex.startswith("0x") else f"0x{encrypted_data_hex}"
        }

        res = requests.post(
            f"{self.endpoint}/v1/encryption/decrypt",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        return res.json()["plaintext"]

    def encrypt_data(self, data: str, client_public_key_der: bytes) -> Tuple[str, str, str]:
        """
        Encrypt data to send back to the client using Odyn API.

        Args:
            data: Plaintext string to encrypt
            client_public_key_der: Client's public key in DER format

        Returns:
            Tuple of (encrypted data hex, enclave public key hex, nonce hex)
        """
        client_public_key_hex = client_public_key_der.hex()
        payload = {
            "plaintext": data,
            "client_public_key": f"0x{client_public_key_hex}" if not client_public_key_hex.startswith("0x") else client_public_key_hex
        }

        res = requests.post(
            f"{self.endpoint}/v1/encryption/encrypt",
            json=payload,
            timeout=10
        )
        res.raise_for_status()

        res_json = res.json()
        encrypted_data = res_json["encrypted_data"]
        enclave_public_key = res_json["enclave_public_key"]
        nonce = res_json["nonce"]

        # Remove 0x prefixes for consistency
        if encrypted_data.startswith("0x"): encrypted_data = encrypted_data[2:]
        if enclave_public_key.startswith("0x"): enclave_public_key = enclave_public_key[2:]
        if nonce.startswith("0x"): nonce = nonce[2:]

        return encrypted_data, enclave_public_key, nonce

    # -----------------------
    # S3 Storage Helpers
    # -----------------------

    def s3_get(self, key: str) -> bytes:
        """
        Fetch an object from S3 storage via the Internal API.

        Args:
            key: Object key relative to the configured prefix.

        Returns:
            Raw bytes of the object.
        """
        res = requests.post(
            f"{self.endpoint}/v1/s3/get",
            json={"key": key},
            timeout=10
        )
        res.raise_for_status()
        encoded = res.json()["value"]
        return base64.b64decode(encoded)

    def s3_put(self, key: str, data: bytes, content_type: Optional[str] = None) -> None:
        """
        Upload an object to S3 storage via the Internal API.

        Args:
            key: Object key relative to the configured prefix.
            data: Raw bytes to store.
            content_type: Optional content type metadata.
        """
        payload = {
            "key": key,
            "value": base64.b64encode(data).decode("utf-8"),
        }
        if content_type:
            payload["content_type"] = content_type

        res = requests.post(
            f"{self.endpoint}/v1/s3/put",
            json=payload,
            timeout=10
        )
        res.raise_for_status()

    def s3_delete(self, key: str) -> None:
        """
        Delete an object from S3 storage via the Internal API.

        Args:
            key: Object key relative to the configured prefix.
        """
        res = requests.post(
            f"{self.endpoint}/v1/s3/delete",
            json={"key": key},
            timeout=10
        )
        res.raise_for_status()

    def s3_list(self, prefix: Optional[str] = None, continuation_token: Optional[str] = None,
                max_keys: Optional[int] = None) -> Dict[str, Any]:
        """
        List objects under the configured prefix.

        Args:
            prefix: Optional sub-prefix within the app namespace.
            continuation_token: Token from a previous list response.
            max_keys: Optional maximum number of keys to return.

        Returns:
            Response dict with keys, continuation_token, and is_truncated.
        """
        payload: Dict[str, Any] = {}
        if prefix is not None:
            payload["prefix"] = prefix
        if continuation_token is not None:
            payload["continuation_token"] = continuation_token
        if max_keys is not None:
            payload["max_keys"] = max_keys

        res = requests.post(
            f"{self.endpoint}/v1/s3/list",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        return res.json()
```

---

## S3 Storage (Optional)

S3 storage endpoints are available only when `storage.s3` is enabled in `enclaver.yaml` and the enclave has egress access to IMDS and S3. The public mock service may not provide persistent S3 storage.

## Usage Examples

### Basic Usage

```python
from odyn import Odyn

# Automatically selects endpoint based on IN_ENCLAVE environment variable
odyn = Odyn()

# Get Ethereum address
address = odyn.eth_address()
print(f"Address: {address}")

# Sign a message
signature = odyn.sign_message({"data": "hello", "timestamp": 123456})
print(f"Signature: {signature}")

# Get random bytes
random_bytes = odyn.get_random_bytes(16)
print(f"Random: {random_bytes.hex()}")

# Get attestation document
attestation = odyn.get_attestation()
print(f"Attestation size: {len(attestation)} bytes")

# Store and load a blob (requires S3 enabled)
odyn.s3_put("data/example.bin", b"hello", content_type="application/octet-stream")
blob = odyn.s3_get("data/example.bin")
print(f"Blob: {blob}")
```

### Encryption/Decryption Example

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

odyn = Odyn()

# 1. Get enclave's public key
enclave_pub_der = odyn.get_encryption_public_key_der()
enclave_pub_key = serialization.load_der_public_key(enclave_pub_der, backend=default_backend())

# 2. Generate client keypair
client_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_public_key_der = client_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 3. Derive shared secret and AES key
shared_secret = client_private_key.exchange(ec.ECDH(), enclave_pub_key)
aes_key = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None, info=b"encryption data"
).derive(shared_secret)

# 4. Client encrypts message for enclave
plaintext = "Secret message from client"
nonce = odyn.get_random_bytes(12)
ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None)

# 5. Enclave decrypts
decrypted = odyn.decrypt_data(nonce.hex(), client_public_key_der.hex(), ciphertext.hex())
print(f"Decrypted: {decrypted}")

# 6. Enclave encrypts response for client
response = "Hello from enclave!"
enc_data, enc_pub_key, enc_nonce = odyn.encrypt_data(response, client_public_key_der)

# 7. Client decrypts response
client_decrypted = AESGCM(aes_key).decrypt(
    bytes.fromhex(enc_nonce)[:12], 
    bytes.fromhex(enc_data), 
    None
)
print(f"Response: {client_decrypted.decode()}")
```

---

## API Endpoints Reference

The mock service implements endpoints from the [Internal API](internal_api.md). S3 endpoints are available only when storage is configured:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/eth/address` | GET | Get Ethereum address and public key |
| `/v1/eth/sign` | POST | Sign message (EIP-191) |
| `/v1/eth/sign-tx` | POST | Sign transaction |
| `/v1/random` | GET | Get 32 random bytes |
| `/v1/attestation` | POST | Generate attestation document |
| `/v1/encryption/public_key` | GET | Get P-384 encryption public key |
| `/v1/encryption/encrypt` | POST | Encrypt data for client |
| `/v1/encryption/decrypt` | POST | Decrypt data from client |
| `/v1/s3/get` | POST | Get object from S3 storage |
| `/v1/s3/put` | POST | Put object to S3 storage |
| `/v1/s3/delete` | POST | Delete object from S3 storage |
| `/v1/s3/list` | POST | List objects in S3 storage |

---

## Related Resources

- [Internal API Reference](internal_api.md) - Complete API documentation
- [Nova Examples Repository](https://github.com/sparsity-xyz/sparsity-nova-examples) - Example applications
- [secured-chat-bot/enclave/odyn.py](https://github.com/sparsity-xyz/sparsity-nova-examples/blob/main/secured-chat-bot/enclave/odyn.py) - Reference implementation
