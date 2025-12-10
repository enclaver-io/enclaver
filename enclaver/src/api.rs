use anyhow::{Result, anyhow};
use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request, Response, StatusCode};
use pkcs8::{DecodePublicKey, SubjectPublicKeyInfo};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::eth_key::EthKey;
use crate::eth_tx::{self, AccessListEntry, TxSignature, UnsignedEip1559Tx};
use crate::http_util::{self, HttpHandler};
use crate::nsm::{AttestationParams, AttestationProvider, Nsm};

const MIME_APPLICATION_CBOR: &str = "application/cbor";

pub struct ApiHandler {
    attester: Box<dyn AttestationProvider + Send + Sync>,
    eth_key: Arc<EthKey>,
    nsm: Option<Arc<Nsm>>,
}

impl ApiHandler {
    pub fn new(
        attester: Box<dyn AttestationProvider + Send + Sync>,
        nsm: Option<Arc<Nsm>>,
    ) -> Result<Self> {
        let eth_key = match nsm.as_ref() {
            Some(nsm_ref) => match Self::collect_random_bytes(nsm_ref, 32).and_then(|bytes| {
                let mut entropy = [0u8; 32];
                entropy.copy_from_slice(&bytes);
                EthKey::from_entropy(entropy)
            }) {
                Ok(key) => {
                    log::info!("Seeded Ethereum key from NSM RNG");
                    Arc::new(key)
                }
                Err(err) => {
                    log::warn!(
                        "Failed to derive Ethereum key from NSM RNG, falling back to OsRng: {}",
                        err
                    );
                    Arc::new(EthKey::new())
                }
            },
            None => {
                log::info!("NSM unavailable; generating Ethereum key from OsRng");
                Arc::new(EthKey::new())
            }
        };
        log::info!("Enclave Ethereum address: {}", eth_key.address());
        Ok(Self {
            attester,
            eth_key,
            nsm,
        })
    }

    fn collect_random_bytes(nsm: &Arc<Nsm>, len: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            let chunk = nsm.get_random()?;
            if chunk.is_empty() {
                continue;
            }
            let remaining = len - buf.len();
            if chunk.len() >= remaining {
                buf.extend_from_slice(&chunk[..remaining]);
            } else {
                buf.extend_from_slice(&chunk);
            }
        }
        Ok(buf)
    }

    async fn handle_request(
        &self,
        head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        match head.uri.path() {
            "/v1/attestation" => match head.method {
                Method::POST => self.handle_attestation(head, body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/eth/address" => match head.method {
                Method::GET => self.handle_eth_address().await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/eth/sign" => match head.method {
                Method::POST => self.handle_eth_sign(head, body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/eth/sign-tx" => match head.method {
                Method::POST => self.handle_eth_sign_tx(head, body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/random" => match head.method {
                Method::GET => self.handle_random().await,
                _ => Ok(http_util::method_not_allowed()),
            },
            _ => Ok(http_util::not_found()),
        }
    }

    async fn handle_attestation(
        &self,
        _head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let attestation_req: AttestationRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let params = match attestation_req.into_params(&self.eth_key) {
            Ok(params) => params,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let att_doc = self.attester.attestation(params)?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, MIME_APPLICATION_CBOR)
            .body(Full::new(Bytes::from(att_doc)))?)
    }

    async fn handle_eth_address(&self) -> Result<Response<Full<Bytes>>> {
        let response = json::object! {
            address: self.eth_key.address(),
            public_key: self.eth_key.public_key_hex(),
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json::stringify(response))))?)
    }

    async fn handle_eth_sign(
        &self,
        _head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let req: EthSignRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let msg_bytes = req.message.as_bytes();
        if msg_bytes.is_empty() {
            return Ok(http_util::bad_request("Message cannot be empty".to_string()));
        }

        // Construct EIP-191 personal message prefix. The prefixed message will be hashed with keccak256 and signed.
        let prefix = format!("\u{0019}Ethereum Signed Message:\n{}", msg_bytes.len());
        let mut prefixed_msg = prefix.into_bytes();
        prefixed_msg.extend_from_slice(msg_bytes);

        let signature = self.eth_key.sign_message(&prefixed_msg);
        let msg_hash = eth_tx::keccak256(&prefixed_msg);

        let attestation = if req.include_attestation {
            let att_doc = self.attester.attestation(AttestationParams {
                nonce: Some(msg_hash.to_vec()),
                public_key: Some(self.eth_key.public_key_as_der()?),
                user_data: Some(self.eth_key.address_bytes()),
            })?;

            Some(base64::encode(att_doc))
        } else {
            None
        };

        let response = EthSignResponse {
            signature: format!("0x{}", hex::encode(signature)),
            address: self.eth_key.address(),
            attestation,
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&response)?)))?)
    }

    async fn handle_eth_sign_tx(
        &self,
        _head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let req: EthSignTxRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let unsigned_tx = match req.payload.into_unsigned_tx() {
            Ok(tx) => tx,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let signable_payload = unsigned_tx.signing_payload();
        let signature_bytes = self.eth_key.sign_message(&signable_payload);
        let tx_signature = match TxSignature::from_recoverable_bytes(&signature_bytes) {
            Ok(sig) => sig,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let raw_tx = unsigned_tx.finalize(&tx_signature);
        let tx_hash = eth_tx::keccak256(&raw_tx);

        let attestation = if req.include_attestation {
            let att_doc = self.attester.attestation(AttestationParams {
                nonce: Some(tx_hash.to_vec()),
                public_key: Some(self.eth_key.public_key_as_der()?),
                user_data: Some(self.eth_key.address_bytes()),
            })?;
            Some(base64::encode(att_doc))
        } else {
            None
        };

        let response = EthSignTxResponse {
            raw_transaction: format!("0x{}", hex::encode(&raw_tx)),
            transaction_hash: format!("0x{}", hex::encode(tx_hash)),
            signature: format!("0x{}", hex::encode(signature_bytes)),
            address: self.eth_key.address(),
            attestation,
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&response)?)))?)
    }

    async fn handle_random(&self) -> Result<Response<Full<Bytes>>> {
        let random_bytes = if let Some(nsm) = &self.nsm {
            // Use hardware-backed NSM RNG in production
            Self::collect_random_bytes(nsm, 32)?
        } else {
            // Fallback to OsRng for testing
            let mut rng = rand::rngs::OsRng;
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes.to_vec()
        };

        let response = json::object! {
            random_bytes: format!("0x{}", hex::encode(random_bytes)),
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json::stringify(response))))?)
    }
}

#[async_trait]
impl HttpHandler for ApiHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        let (head, body) = req.into_parts();
        let body = body.collect().await?.to_bytes();

        self.handle_request(&head, body).await
    }
}

#[derive(Deserialize)]
struct AttestationRequest {
    nonce: Option<String>,
    public_key: Option<String>,
    user_data: Option<String>,
}

impl AttestationRequest {
    fn into_params(self, eth_key: &EthKey) -> Result<AttestationParams> {
        let nonce = self.nonce.map(base64::decode).transpose()?;

        let public_key = match self.public_key {
            Some(pem) => Some(pem_decode(&pem)?),
            None => Some(eth_key.public_key_as_der()?),
        };

        let user_data = match self.user_data {
            Some(b64) => Some(base64::decode(b64)?),
            None => {
                // Store ETH address as raw 20 bytes (not string)
                // This matches tee-tls format where get_address_bytes() returns 20 bytes
                Some(eth_key.address_bytes())
            }
        };

        Ok(AttestationParams {
            nonce,
            public_key,
            user_data,
        })
    }
}

#[derive(Deserialize)]
struct EthSignRequest {
    message: String,
    #[serde(default)]
    include_attestation: bool,
}

#[derive(Serialize)]
struct EthSignResponse {
    signature: String,
    address: String,
    attestation: Option<String>,
}

#[derive(Deserialize)]
struct EthSignTxRequest {
    #[serde(default)]
    include_attestation: bool,
    payload: TxPayload,
}

#[derive(Serialize)]
struct EthSignTxResponse {
    raw_transaction: String,
    transaction_hash: String,
    signature: String,
    address: String,
    attestation: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TxPayload {
    Structured(StructuredTxPayload),
    RawRlp(RawRlpPayload),
}

impl TxPayload {
    fn into_unsigned_tx(self) -> Result<UnsignedEip1559Tx> {
        match self {
            TxPayload::Structured(inner) => inner.into_unsigned_tx(),
            TxPayload::RawRlp(inner) => inner.into_unsigned_tx(),
        }
    }
}

#[derive(Deserialize)]
struct StructuredTxPayload {
    chain_id: String,
    nonce: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    gas_limit: String,
    to: Option<String>,
    #[serde(default = "zero_hex_string")]
    value: String,
    #[serde(default = "empty_hex_string")]
    data: String,
    #[serde(default)]
    access_list: Vec<AccessListInput>,
}

impl StructuredTxPayload {
    fn into_unsigned_tx(self) -> Result<UnsignedEip1559Tx> {
        let chain_id = eth_tx::parse_scalar_hex(&self.chain_id)?;
        if chain_id.is_empty() {
            return Err(anyhow!("chain_id cannot be zero"));
        }
        let to = match self.to {
            Some(addr) => Some(eth_tx::parse_address_hex(&addr)?),
            None => None,
        };
        let access_list = self
            .access_list
            .into_iter()
            .map(|entry| entry.into_entry())
            .collect::<Result<Vec<_>>>()?;

        Ok(UnsignedEip1559Tx {
            chain_id,
            nonce: eth_tx::parse_scalar_hex(&self.nonce)?,
            max_priority_fee_per_gas: eth_tx::parse_scalar_hex(&self.max_priority_fee_per_gas)?,
            max_fee_per_gas: eth_tx::parse_scalar_hex(&self.max_fee_per_gas)?,
            gas_limit: eth_tx::parse_scalar_hex(&self.gas_limit)?,
            to,
            value: eth_tx::parse_scalar_hex(&self.value)?,
            data: eth_tx::parse_data_hex(&self.data)?,
            access_list,
        })
    }
}

#[derive(Deserialize)]
struct RawRlpPayload {
    raw_payload: String,
}

impl RawRlpPayload {
    fn into_unsigned_tx(self) -> Result<UnsignedEip1559Tx> {
        let bytes = eth_tx::parse_data_hex(&self.raw_payload)?;
        UnsignedEip1559Tx::from_raw_payload(&bytes)
    }
}

#[derive(Deserialize)]
struct AccessListInput {
    address: String,
    #[serde(default)]
    storage_keys: Vec<String>,
}

impl AccessListInput {
    fn into_entry(self) -> Result<AccessListEntry> {
        let address = eth_tx::parse_address_hex(&self.address)?;
        let mut storage_keys = Vec::with_capacity(self.storage_keys.len());
        for key in self.storage_keys {
            storage_keys.push(eth_tx::parse_storage_key_hex(&key)?);
        }
        Ok(AccessListEntry {
            address,
            storage_keys,
        })
    }
}

fn zero_hex_string() -> String {
    "0x0".to_string()
}

fn empty_hex_string() -> String {
    "0x".to_string()
}

struct DerPublicKey {
    bytes: Vec<u8>,
}

impl<'a> TryFrom<SubjectPublicKeyInfo<'a>> for DerPublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: SubjectPublicKeyInfo<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: spki.subject_public_key.to_vec(),
        })
    }
}

impl DecodePublicKey for DerPublicKey {}

impl DerPublicKey {
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn pem_decode(pem: &str) -> Result<Vec<u8>> {
    let der = DerPublicKey::from_public_key_pem(pem)?;
    Ok(der.into_bytes())
}

#[tokio::test]
async fn test_attestation_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let body = json::object!(
        public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyY9b3O0t0zDH3pcxYWW2\nTBjW302L3eL+S4C1rmW6OFIXa6U1ZrBtSvMvI3ievCVHq7AOof6xkbXXqobgbokc\n0514+7stOsq/CqnXGWhWwW+aCIj5FFi+gf4kXbXvUYKhUVFFJm5Rq71r5stt3B1p\njYC0Nm391GjR98gO9Sw8TGYx21Q7KuNFsfMa/dtYboFX38fQFw4eTHvSafErgZNO\nMUmzLPibM+1zXqHbXX1M5hyFMBJE28zNi+TmvopdMxsG/a2yTiM1j6Srw2Y5ZrE6\nO1Rr8MxrAepPbmybNOn0K0YIcf/KZurDuvOIuhsurxFgGTVQhsMZ0iNaXA0usFM+\npQIDAQAB\n-----END PUBLIC KEY-----".to_string(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/v1/attestation")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();

    let resp = handler.handle_request(&head, body).await.unwrap();
    assert!(resp.status() == StatusCode::OK);

    let body = json::object!(
        nonce: base64::encode("the nonce"),
        user_data: base64::encode("my data"),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/v1/attestation")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();

    let resp = handler.handle_request(&head, body).await.unwrap();
    assert!(resp.status() == StatusCode::OK);
}

#[tokio::test]
async fn test_eth_address_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/eth/address")
        .body(Bytes::new())
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    assert!(resp.headers().get(CONTENT_TYPE).unwrap() == "application/json");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().len() == 42);
    assert!(response["public_key"].as_str().unwrap().starts_with("0x"));
    assert!(response["public_key"].as_str().unwrap().len() == 132);
}

#[tokio::test]
async fn test_eth_sign_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let body = json::object! {
        message: "hello world",
        include_attestation: false,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    assert!(resp.headers().get(CONTENT_TYPE).unwrap() == "application/json");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["signature"].as_str().unwrap().starts_with("0x"));
    assert!(response["signature"].as_str().unwrap().len() == 132);
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().len() == 42);
    assert!(response["attestation"].is_null());
}

#[tokio::test]
async fn test_eth_sign_with_attestation() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let body = json::object! {
        message: "hello with attestation",
        include_attestation: true,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["signature"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["attestation"].is_string());
}

#[tokio::test]
async fn test_eth_sign_signature_recovery() {
    use crate::eth_key::EthKey;
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let msg = "recover me";

    let body = json::object! {
        message: msg,
        include_attestation: false,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let signature = response["signature"].as_str().unwrap();
    let address = response["address"].as_str().unwrap();

    // Recreate the EIP-191 prefixed message and verify the signature recovers the same address
    let msg_bytes = msg.as_bytes();
    let prefix = format!("\u{0019}Ethereum Signed Message:\n{}", msg_bytes.len());
    let mut prefixed_msg = prefix.into_bytes();
    prefixed_msg.extend_from_slice(msg_bytes);

    assert!(EthKey::verify_message(
        signature.to_string(),
        &prefixed_msg,
        address.to_string()
    ));
}

#[tokio::test]
async fn test_eth_sign_empty_message() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let body = json::object! {
        message: "",
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::BAD_REQUEST);
}

#[cfg(test)]
fn sample_unsigned_tx_for_tests() -> UnsignedEip1559Tx {
    UnsignedEip1559Tx {
        chain_id: eth_tx::parse_scalar_hex("0x1").unwrap(),
        nonce: eth_tx::parse_scalar_hex("0x0").unwrap(),
        max_priority_fee_per_gas: eth_tx::parse_scalar_hex("0x1").unwrap(),
        max_fee_per_gas: eth_tx::parse_scalar_hex("0x2").unwrap(),
        gas_limit: eth_tx::parse_scalar_hex("0x5208").unwrap(),
        to: Some(eth_tx::parse_address_hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()),
        value: eth_tx::parse_scalar_hex("0x0").unwrap(),
        data: eth_tx::parse_data_hex("0x").unwrap(),
        access_list: vec![AccessListEntry {
            address: eth_tx::parse_address_hex("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap(),
            storage_keys: vec![
                eth_tx::parse_storage_key_hex(
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
            ],
        }],
    }
}

#[tokio::test]
async fn test_eth_sign_tx_structured() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let body = json::object! {
        include_attestation: false,
        payload: {
            kind: "structured",
            chain_id: "0x1",
            nonce: "0x0",
            max_priority_fee_per_gas: "0x1",
            max_fee_per_gas: "0x2",
            gas_limit: "0x5208",
            to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            value: "0x0",
            data: "0x",
            access_list: [
                {
                    address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    storage_keys: [
                        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    ]
                }
            ]
        }
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign-tx")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let raw_tx = response["raw_transaction"].as_str().unwrap();
    assert!(raw_tx.starts_with("0x02"));
    assert!(response["transaction_hash"].as_str().unwrap().len() == 66);
    assert!(response["signature"].as_str().unwrap().len() == 132);
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["attestation"].is_null());
}

#[tokio::test]
async fn test_eth_sign_tx_raw_payload() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let unsigned_tx = sample_unsigned_tx_for_tests();
    let raw_payload = format!("0x{}", hex::encode(unsigned_tx.signing_payload()));

    let body = json::object! {
        include_attestation: false,
        payload: {
            kind: "raw_rlp",
            raw_payload: raw_payload,
        }
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign-tx")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let raw_tx = response["raw_transaction"].as_str().unwrap();
    assert!(raw_tx.starts_with("0x02"));
    assert!(response["transaction_hash"].as_str().unwrap().len() == 66);
    assert!(response["signature"].as_str().unwrap().len() == 132);
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["attestation"].is_null());
}

#[tokio::test]
async fn test_eth_sign_tx_signature_verification() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    // Get the handler's eth address for verification later
    let address_req = Request::builder()
        .method("GET")
        .uri("/v1/eth/address")
        .body(Bytes::new())
        .unwrap();
    let (head, body) = address_req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let addr_response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let expected_address = addr_response["address"].as_str().unwrap();

    // Create and sign a transaction
    let body = json::object! {
        include_attestation: false,
        payload: {
            kind: "structured",
            chain_id: "0x1",
            nonce: "0x9",
            max_priority_fee_per_gas: "0x3b9aca00",
            max_fee_per_gas: "0x77359400",
            gas_limit: "0x5208",
            to: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
            value: "0xde0b6b3a7640000",
            data: "0x",
            access_list: []
        }
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign-tx")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Extract the signed transaction and verify it
    let raw_tx_hex = response["raw_transaction"].as_str().unwrap();
    let raw_tx = hex::decode(raw_tx_hex.strip_prefix("0x").unwrap()).unwrap();

    // Verify the transaction starts with the EIP-1559 type prefix
    assert!(raw_tx[0] == 0x02);

    // Parse the signed transaction to extract signature components
    let rlp = rlp::Rlp::new(&raw_tx[1..]);
    assert!(rlp.item_count().unwrap() == 12); // EIP-1559 signed tx has 12 fields

    // Extract signature components (last 3 fields)
    let y_parity: u8 = rlp.val_at(9).unwrap();
    let r_bytes: Vec<u8> = rlp.val_at(10).unwrap();
    let s_bytes: Vec<u8> = rlp.val_at(11).unwrap();

    // Verify y_parity is valid (0 or 1)
    assert!(y_parity <= 1);

    // Verify r and s are not zero
    assert!(!r_bytes.is_empty());
    assert!(!s_bytes.is_empty());

    // Reconstruct the signing payload and verify the signature recovers to the correct address
    let unsigned_tx = UnsignedEip1559Tx {
        chain_id: eth_tx::parse_scalar_hex("0x1").unwrap(),
        nonce: eth_tx::parse_scalar_hex("0x9").unwrap(),
        max_priority_fee_per_gas: eth_tx::parse_scalar_hex("0x3b9aca00").unwrap(),
        max_fee_per_gas: eth_tx::parse_scalar_hex("0x77359400").unwrap(),
        gas_limit: eth_tx::parse_scalar_hex("0x5208").unwrap(),
        to: Some(eth_tx::parse_address_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb").unwrap()),
        value: eth_tx::parse_scalar_hex("0xde0b6b3a7640000").unwrap(),
        data: eth_tx::parse_data_hex("0x").unwrap(),
        access_list: vec![],
    };

    let signing_payload = unsigned_tx.signing_payload();

    // Verify the signature by recovering the public key
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let mut sig_bytes = [0u8; 64];

    // Pad r and s to 32 bytes each
    let r_padded = if r_bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - r_bytes.len()];
        padded.extend_from_slice(&r_bytes);
        padded
    } else {
        r_bytes.clone()
    };

    let s_padded = if s_bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - s_bytes.len()];
        padded.extend_from_slice(&s_bytes);
        padded
    } else {
        s_bytes.clone()
    };

    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..64].copy_from_slice(&s_padded);

    let signature = Signature::from_bytes(&sig_bytes.into()).unwrap();
    let recovery_id = RecoveryId::from_byte(y_parity).unwrap();

    // Hash the signing payload
    let digest = Keccak256::new_with_prefix(&signing_payload);

    // Recover the public key from the signature
    let recovered_key = VerifyingKey::recover_from_digest(digest, &signature, recovery_id).unwrap();

    // Derive the Ethereum address from the recovered public key
    let pub_bytes = recovered_key.to_encoded_point(false);
    let hash = eth_tx::keccak256(&pub_bytes.as_bytes()[1..]);
    let recovered_address = format!("0x{}", hex::encode(&hash[12..]));

    // Verify the recovered address matches the handler's address
    assert!(recovered_address == expected_address);

    // Also verify it matches the address in the response
    assert!(response["address"].as_str().unwrap() == expected_address);
}

#[tokio::test]
async fn test_random_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler =
        ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new())), None).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/random")
        .body(Bytes::new())
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    assert!(resp.headers().get(CONTENT_TYPE).unwrap() == "application/json");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify the response contains random_bytes field
    assert!(response["random_bytes"].is_string());
    let random_bytes_str = response["random_bytes"].as_str().unwrap();

    // Verify it starts with 0x
    assert!(random_bytes_str.starts_with("0x"));

    // Verify it's 64 hex characters (32 bytes) plus the 0x prefix = 66 characters total
    assert!(random_bytes_str.len() == 66);

    // Verify it's valid hex
    assert!(hex::decode(random_bytes_str.trim_start_matches("0x")).is_ok());
}
