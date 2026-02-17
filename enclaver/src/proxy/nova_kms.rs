use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use ethabi::ethereum_types::{H160, U256};
use ethabi::{Function, Token};
use form_urlencoded::byte_serialize;
use http_body_util::Full;
use hyper::Response;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use log::warn;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::eth_key::EthKey;
use crate::http_util;
use crate::manifest::KmsIntegration;

const APP_WALLET_DERIVE_PATH: &str = "wallet/eth/app/main";
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const AUTHZ_CACHE_TTL_MS: u64 = 10_000;

#[derive(Clone)]
pub struct NovaKmsProxy {
    client: reqwest::Client,
    base_urls: Arc<[String]>,
    odyn_endpoint: String,
    max_retries: usize,
    require_mutual_signature: bool,
    reserved_derive_prefixes: Arc<Vec<String>>,
    audit_log_path: Option<PathBuf>,
    audit_log_sender: Option<mpsc::UnboundedSender<String>>,
    registry_discovery: Option<RegistryDiscoveryConfig>,
    discovery_cache: Arc<Mutex<Option<DiscoveryCacheEntry>>>,
    discovery_refresh_lock: Arc<Mutex<()>>,
    authz_cache: Arc<Mutex<Option<CachedAuthzContext>>>,
}

#[derive(Clone, Debug)]
pub struct AppAuthzContext {
    pub app_id: u64,
    pub app_wallet: String,
    pub instance_wallet: String,
}

#[derive(Clone)]
struct CachedAuthzContext {
    context: AppAuthzContext,
    expires_at_ms: u64,
}

#[derive(Clone)]
struct RegistryDiscoveryConfig {
    kms_app_id: u64,
    registry_address: String,
    rpc_url: String,
    ttl_ms: u64,
}

#[derive(Clone)]
struct DiscoveryCacheEntry {
    base_urls: Vec<String>,
    expires_at_ms: u64,
}

struct AuditLogEntry<'a> {
    request_id: &'a str,
    instance_wallet: &'a str,
    action: &'a str,
    payload_hash: &'a str,
    kms_node: &'a str,
    result: &'a str,
    error_code: Option<&'a str>,
    authz_context: Option<&'a AppAuthzContext>,
}

#[derive(Clone)]
struct RegistryInstance {
    app_id: u64,
    instance_url: String,
    zk_verified: bool,
    status: u64,
}

#[derive(Clone)]
struct RegistryApp {
    status: u64,
    app_wallet: String,
}

#[derive(Deserialize)]
struct DeriveApiRequest {
    path: String,
    #[serde(default)]
    context: String,
    #[serde(default = "default_derive_length")]
    length: usize,
}

fn default_derive_length() -> usize {
    32
}

#[derive(Serialize)]
struct DeriveApiResponse {
    key: String,
}

#[derive(Deserialize)]
struct KvGetApiRequest {
    key: String,
}

#[derive(Serialize)]
struct KvGetApiResponse {
    found: bool,
    value: Option<String>,
}

#[derive(Deserialize)]
struct KvPutApiRequest {
    key: String,
    value: String,
    #[serde(default)]
    ttl_ms: u64,
}

#[derive(Serialize)]
struct KvPutApiResponse {
    success: bool,
}

#[derive(Deserialize)]
struct KvDeleteApiRequest {
    key: String,
}

#[derive(Serialize)]
struct KvDeleteApiResponse {
    success: bool,
}

#[derive(Clone)]
struct KmsNodeIdentity {
    wallet: String,
    tee_pubkey: String,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl NovaKmsProxy {
    pub fn new(config: &KmsIntegration, odyn_endpoint: String) -> Result<Self> {
        let mut base_urls = config
            .base_urls
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .collect::<Vec<_>>();

        if base_urls.is_empty() {
            bail!("kms_integration.base_urls is required when KMS integration is enabled");
        }

        // Keep deterministic node selection order.
        base_urls.sort();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()?;

        let reserved_derive_prefixes = config
            .reserved_derive_prefixes
            .clone()
            .unwrap_or_else(|| vec!["wallet/eth/app/".to_string()]);

        let registry_discovery = Self::build_registry_discovery(config)?;
        let audit_log_path = config.audit_log_path.as_ref().map(PathBuf::from);
        let audit_log_sender = Self::spawn_audit_log_writer(audit_log_path.clone());

        Ok(Self {
            client,
            base_urls: Arc::from(base_urls),
            odyn_endpoint,
            max_retries: usize::from(config.max_retries) + 1,
            require_mutual_signature: config.require_mutual_signature,
            reserved_derive_prefixes: Arc::new(reserved_derive_prefixes),
            audit_log_path,
            audit_log_sender,
            registry_discovery,
            discovery_cache: Arc::new(Mutex::new(None)),
            discovery_refresh_lock: Arc::new(Mutex::new(())),
            authz_cache: Arc::new(Mutex::new(None)),
        })
    }

    fn spawn_audit_log_writer(
        path: Option<PathBuf>,
    ) -> Option<mpsc::UnboundedSender<String>> {
        let path = path?;
        let (sender, mut receiver) = mpsc::unbounded_channel::<String>();
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(err) => {
                warn!(
                    "Nova KMS audit log writer not started (runtime unavailable: {}); falling back to inline writes",
                    err
                );
                return None;
            }
        };
        handle.spawn(async move {
            while let Some(line) = receiver.recv().await {
                if let Ok(mut file) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await
                {
                    let _ = file.write_all(line.as_bytes()).await;
                }
            }
        });
        Some(sender)
    }

    pub fn is_reserved_derive_path(&self, path: &str) -> bool {
        let normalized = path.trim();
        self.reserved_derive_prefixes
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
    }

    pub fn audit_log_path(&self) -> Option<PathBuf> {
        self.audit_log_path.clone()
    }

    pub async fn ensure_kms_access_authorized(&self) -> Result<AppAuthzContext> {
        self.resolve_authz_context(false).await
    }

    pub async fn ensure_app_wallet_authorized(&self) -> Result<AppAuthzContext> {
        // App-wallet signing APIs require the app wallet to be anchored on-chain.
        self.resolve_authz_context(true).await
    }

    pub async fn app_wallet_key(&self) -> Result<EthKey> {
        let key = self
            .derive_reserved_key_internal(APP_WALLET_DERIVE_PATH, "", 32)
            .await?;
        if key.len() != 32 {
            bail!("KMS app wallet derivation returned invalid length {}", key.len());
        }
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&key);
        EthKey::from_entropy(entropy)
    }

    pub async fn app_wallet_address(&self) -> Result<String> {
        self.app_wallet_address_internal().await
    }

    pub async fn audit_local_action(
        &self,
        action: &str,
        payload: Option<&Value>,
        result: &str,
        error_code: Option<&str>,
    ) {
        let request_id = Uuid::new_v4().to_string();
        let payload_hash = self.hash_payload(payload);
        let instance_wallet = match self.local_eth_address().await {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    "Skipping Nova KMS local audit entry due to missing local wallet identity: {}",
                    err
                );
                return;
            }
        };
        let authz_ctx = self.cached_authz_context().await;
        self.append_audit_log(AuditLogEntry {
            request_id: &request_id,
            instance_wallet: &instance_wallet,
            action,
            payload_hash: &payload_hash,
            kms_node: "local",
            result,
            error_code,
            authz_context: authz_ctx.as_ref(),
        })
        .await;
    }

    pub async fn derive_key(
        &self,
        path: &str,
        context: &str,
        length: usize,
    ) -> Result<Vec<u8>> {
        if path.trim().is_empty() {
            bail!("KMS derive path cannot be empty");
        }
        if self.is_reserved_derive_path(path) {
            bail!("KMS derive path '{}' is reserved", path);
        }

        let payload = json!({
            "path": path,
            "context": context,
            "length": length,
        });
        let response = self
            .call_kms_json_internal(Method::POST, "/kms/derive", Some(payload), true)
            .await?;
        let key_b64 = response
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS response missing 'key'"))?;
        general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| anyhow!("invalid KMS key base64: {}", e))
    }

    pub async fn kv_get(&self, key: &str) -> Result<Option<String>> {
        if key.trim().is_empty() {
            bail!("KMS KV key cannot be empty");
        }
        let key_encoded = byte_serialize(key.as_bytes()).collect::<String>();
        let path = format!("/kms/data/{key_encoded}");

        match self
            .call_kms_json_internal(Method::GET, &path, None, true)
            .await
        {
            Ok(response) => {
                let value = response
                    .get("value")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                Ok(value)
            }
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("KMS HTTP 404") || msg.contains("Key not found") {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    pub async fn kv_put(&self, key: &str, value_b64: &str, ttl_ms: u64) -> Result<()> {
        if key.trim().is_empty() {
            bail!("KMS KV key cannot be empty");
        }
        if value_b64.trim().is_empty() {
            bail!("KMS KV value cannot be empty");
        }

        let payload = json!({
            "key": key,
            "value": value_b64,
            "ttl_ms": ttl_ms,
        });
        self.call_kms_json_internal(Method::PUT, "/kms/data", Some(payload), true)
            .await
            .map(|_| ())
    }

    pub async fn kv_delete(&self, key: &str) -> Result<()> {
        if key.trim().is_empty() {
            bail!("KMS KV key cannot be empty");
        }

        let payload = json!({ "key": key });
        self.call_kms_json_internal(Method::DELETE, "/kms/data", Some(payload), true)
            .await
            .map(|_| ())
    }

    pub async fn handle_derive(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: DeriveApiRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        if let Err(err) = self.ensure_kms_access_authorized().await {
            return Ok(http_util::bad_request(err.to_string()));
        }

        if self.is_reserved_derive_path(&req.path) {
            return Ok(http_util::bad_request(
                "KMS derive path is reserved and cannot be requested by app".to_string(),
            ));
        }

        let key = match self.derive_key(&req.path, &req.context, req.length).await {
            Ok(v) => v,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        http_util::ok_json(&DeriveApiResponse {
            key: general_purpose::STANDARD.encode(key),
        })
    }

    pub async fn handle_kv_get(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: KvGetApiRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        if let Err(err) = self.ensure_kms_access_authorized().await {
            return Ok(http_util::bad_request(err.to_string()));
        }

        match self.kv_get(&req.key).await {
            Ok(value) => Ok(http_util::ok_json(&KvGetApiResponse {
                found: value.is_some(),
                value,
            })?),
            Err(err) => Ok(http_util::bad_request(err.to_string())),
        }
    }

    pub async fn handle_kv_put(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: KvPutApiRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        if let Err(err) = self.ensure_kms_access_authorized().await {
            return Ok(http_util::bad_request(err.to_string()));
        }

        match self.kv_put(&req.key, &req.value, req.ttl_ms).await {
            Ok(()) => Ok(http_util::ok_json(&KvPutApiResponse { success: true })?),
            Err(err) => Ok(http_util::bad_request(err.to_string())),
        }
    }

    pub async fn handle_kv_delete(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: KvDeleteApiRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        if let Err(err) = self.ensure_kms_access_authorized().await {
            return Ok(http_util::bad_request(err.to_string()));
        }

        match self.kv_delete(&req.key).await {
            Ok(()) => Ok(http_util::ok_json(&KvDeleteApiResponse { success: true })?),
            Err(err) => Ok(http_util::bad_request(err.to_string())),
        }
    }

    async fn derive_reserved_key_internal(
        &self,
        path: &str,
        context: &str,
        length: usize,
    ) -> Result<Vec<u8>> {
        let payload = json!({
            "path": path,
            "context": context,
            "length": length,
        });
        let response = self
            .call_kms_json_internal(Method::POST, "/kms/derive", Some(payload), false)
            .await?;
        let key_b64 = response
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS response missing 'key'"))?;
        general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| anyhow!("invalid KMS key base64: {}", e))
    }

    async fn app_wallet_address_internal(&self) -> Result<String> {
        let key = self.app_wallet_key().await?;
        canonical_wallet(&key.address())
    }

    async fn call_kms_json_internal(
        &self,
        method: Method,
        path: &str,
        payload: Option<Value>,
        include_authz_metadata: bool,
    ) -> Result<Value> {
        let request_id = Uuid::new_v4().to_string();
        let payload_hash = self.hash_payload(payload.as_ref());
        let instance_wallet = self.local_eth_address().await?;
        let authz_ctx = if include_authz_metadata {
            self.cached_authz_context().await
        } else {
            None
        };
        let mut last_error: Option<anyhow::Error> = None;
        let base_urls = self.resolve_base_urls().await;

        for attempt in 0..self.max_retries {
            for base_url in &base_urls {
                let action = format!("{} {}", method.as_str(), path);
                let result = self
                    .call_kms_on_node(base_url, method.clone(), path, payload.clone())
                    .await;

                match result {
                    Ok(value) => {
                        self.append_audit_log(AuditLogEntry {
                            request_id: &request_id,
                            instance_wallet: &instance_wallet,
                            action: &action,
                            payload_hash: &payload_hash,
                            kms_node: base_url,
                            result: "ok",
                            error_code: None,
                            authz_context: authz_ctx.as_ref(),
                        })
                        .await;
                        return Ok(value);
                    }
                    Err(err) => {
                        last_error = Some(err);
                        let error_code = last_error.as_ref().map(ToString::to_string);
                        self.append_audit_log(AuditLogEntry {
                            request_id: &request_id,
                            instance_wallet: &instance_wallet,
                            action: &action,
                            payload_hash: &payload_hash,
                            kms_node: base_url,
                            result: "error",
                            error_code: error_code.as_deref(),
                            authz_context: authz_ctx.as_ref(),
                        })
                        .await;
                    }
                }
            }

            if attempt + 1 < self.max_retries {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("KMS call failed with unknown error")))
    }

    async fn call_kms_on_node(
        &self,
        base_url: &str,
        method: Method,
        path: &str,
        payload: Option<Value>,
    ) -> Result<Value> {
        let node = self.fetch_node_identity(base_url).await?;
        let nonce_b64 = self.fetch_nonce(base_url).await?;
        let timestamp = current_unix_timestamp();
        let message = format!(
            "NovaKMS:AppAuth:{}:{}:{}",
            nonce_b64,
            canonical_wallet(&node.wallet)?,
            timestamp
        );
        let client_signature = self.local_sign_message(&message).await?;
        let app_wallet = self.local_eth_address().await?;

        let mut req = self.client.request(method.clone(), format!("{base_url}{path}"));
        req = req
            .header("x-app-signature", client_signature.clone())
            .header("x-app-nonce", nonce_b64)
            .header("x-app-timestamp", timestamp.to_string())
            .header("x-app-wallet", app_wallet);

        if let Some(payload_json) = payload {
            let envelope = self
                .encrypt_payload_for_node(&payload_json, &node.tee_pubkey)
                .await?;
            req = req.header(CONTENT_TYPE, "application/json").json(&envelope);
        }

        let response = req.send().await?;
        let status = response.status();
        let mutual_sig = response
            .headers()
            .get("x-kms-response-signature")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        let response_text = response.text().await?;
        if !status.is_success() {
            bail!("KMS HTTP {}: {}", status.as_u16(), response_text);
        }

        if self.require_mutual_signature {
            let sig = mutual_sig
                .as_deref()
                .ok_or_else(|| anyhow!("KMS response missing X-KMS-Response-Signature"))?;
            let verify_message = format!(
                "NovaKMS:Response:{}:{}",
                client_signature,
                canonical_wallet(&node.wallet)?
            );
            if !EthKey::verify_message(
                sig.to_string(),
                verify_message.as_bytes(),
                canonical_wallet(&node.wallet)?,
            ) {
                bail!("KMS mutual response signature verification failed");
            }
        }

        let envelope: Value = serde_json::from_str(&response_text)?;
        self.decrypt_envelope(&envelope).await
    }

    async fn fetch_node_identity(&self, base_url: &str) -> Result<KmsNodeIdentity> {
        let status_url = format!("{base_url}/status");
        let data: Value = self
            .client
            .get(status_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let node = data
            .get("node")
            .ok_or_else(|| anyhow!("KMS /status response missing node"))?;
        let wallet = node
            .get("tee_wallet")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS /status response missing node.tee_wallet"))?;
        let tee_pubkey = node
            .get("tee_pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS /status response missing node.tee_pubkey"))?;
        if tee_pubkey.trim().is_empty() {
            bail!("KMS /status returned empty tee_pubkey");
        }
        Ok(KmsNodeIdentity {
            wallet: canonical_wallet(wallet)?,
            tee_pubkey: trim_0x(tee_pubkey),
        })
    }

    async fn fetch_nonce(&self, base_url: &str) -> Result<String> {
        let nonce_url = format!("{base_url}/nonce");
        let value: Value = self
            .client
            .get(nonce_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let nonce_b64 = value
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS /nonce response missing nonce"))?;
        Ok(nonce_b64.to_string())
    }

    async fn local_eth_address(&self) -> Result<String> {
        let value = self.odyn_get("/v1/eth/address").await?;
        let address = value
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn /v1/eth/address response missing address"))?;
        canonical_wallet(address)
    }

    async fn local_sign_message(&self, message: &str) -> Result<String> {
        let value = self
            .odyn_post(
                "/v1/eth/sign",
                &json!({
                    "message": message,
                    "include_attestation": false
                }),
            )
            .await?;
        let signature = value
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn /v1/eth/sign response missing signature"))?;
        Ok(signature.to_string())
    }

    async fn local_tee_pubkey(&self) -> Result<String> {
        let value = self.odyn_get("/v1/encryption/public_key").await?;
        let pubkey = value
            .get("public_key_der")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn /v1/encryption/public_key response missing public_key_der"))?;
        Ok(trim_0x(pubkey))
    }

    async fn encrypt_payload_for_node(&self, payload: &Value, node_tee_pubkey: &str) -> Result<Value> {
        let sender_pubkey = self.local_tee_pubkey().await?;
        let plaintext = serde_json::to_string(payload)?;
        let value = self
            .odyn_post(
                "/v1/encryption/encrypt",
                &json!({
                    "plaintext": plaintext,
                    "client_public_key": format!("0x{}", trim_0x(node_tee_pubkey)),
                }),
            )
            .await?;
        let nonce = value
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn /v1/encryption/encrypt response missing nonce"))?;
        let encrypted_data = value
            .get("encrypted_data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn /v1/encryption/encrypt response missing encrypted_data"))?;

        Ok(json!({
            "sender_tee_pubkey": sender_pubkey,
            "nonce": trim_0x(nonce),
            "encrypted_data": trim_0x(encrypted_data),
        }))
    }

    async fn decrypt_envelope(&self, envelope: &Value) -> Result<Value> {
        let sender_tee_pubkey = envelope
            .get("sender_tee_pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS response missing sender_tee_pubkey"))?;
        let nonce = envelope
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS response missing nonce"))?;
        let encrypted_data = envelope
            .get("encrypted_data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("KMS response missing encrypted_data"))?;

        let value = self
            .odyn_post(
                "/v1/encryption/decrypt",
                &json!({
                    "nonce": format!("0x{}", trim_0x(nonce)),
                    "client_public_key": format!("0x{}", trim_0x(sender_tee_pubkey)),
                    "encrypted_data": format!("0x{}", trim_0x(encrypted_data)),
                }),
            )
            .await?;
        let plaintext = value
            .get("plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Odyn decrypt response missing plaintext"))?;
        Ok(serde_json::from_str(plaintext)?)
    }

    async fn odyn_get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.odyn_endpoint, path);
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn odyn_post(&self, path: &str, payload: &Value) -> Result<Value> {
        let url = format!("{}{}", self.odyn_endpoint, path);
        Ok(self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .json(payload)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn hash_payload(&self, payload: Option<&Value>) -> String {
        let bytes = payload
            .map(|v| serde_json::to_vec(v).unwrap_or_default())
            .unwrap_or_default();
        let hash = Sha256::digest(bytes);
        hex::encode(hash)
    }

    async fn append_audit_log(&self, entry: AuditLogEntry<'_>) {
        let Some(path) = self.audit_log_path.as_ref() else {
            return;
        };

        let (app_id, app_wallet) = if let Some(ctx) = entry.authz_context {
            (Some(ctx.app_id), Some(ctx.app_wallet.clone()))
        } else {
            (None, None)
        };

        let entry = json!({
            "request_id": entry.request_id,
            "instance_wallet": entry.instance_wallet,
            "app_id": app_id,
            "app_wallet": app_wallet,
            "action": entry.action,
            "payload_hash": entry.payload_hash,
            "kms_node": entry.kms_node,
            "result": entry.result,
            "error_code": entry.error_code,
            "timestamp": current_unix_timestamp(),
        });
        let mut line = entry.to_string();
        line.push('\n');

        if let Some(sender) = self.audit_log_sender.as_ref() {
            if sender.send(line.clone()).is_ok() {
                return;
            }
            warn!("Nova KMS audit log channel unavailable; falling back to inline write");
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            let _ = file.write_all(line.as_bytes()).await;
        }
    }

    async fn resolve_authz_context(&self, require_anchored_wallet: bool) -> Result<AppAuthzContext> {
        if let Some(cached) = self.cached_authz_context().await {
            return Ok(cached);
        }

        let discovery = self
            .registry_discovery
            .as_ref()
            .ok_or_else(|| anyhow!("registry-based authz requires kms_app_id/nova_app_registry/registry_chain_rpc"))?;

        let instance_wallet = self.local_eth_address().await?;
        let instance = self
            .registry_get_instance_by_wallet(discovery, &instance_wallet)
            .await?;

        if !instance.zk_verified {
            bail!("instance {} is not zk-verified on registry", instance_wallet);
        }
        if instance.status != 0 {
            bail!("instance {} is not ACTIVE on registry", instance_wallet);
        }

        let app = self.registry_get_app(discovery, instance.app_id).await?;
        if app.status != 0 {
            bail!("app {} is not ACTIVE on registry", instance.app_id);
        }

        let derived_app_wallet = self.app_wallet_address_internal().await?;
        let anchored_wallet = canonical_wallet(&app.app_wallet)?;
        if !is_zero_address(&anchored_wallet) && anchored_wallet != derived_app_wallet {
            bail!(
                "anchored appWallet {} mismatches derived app wallet {}",
                anchored_wallet,
                derived_app_wallet
            );
        }
        if require_anchored_wallet && is_zero_address(&anchored_wallet) {
            bail!("app {} has no anchored appWallet on registry", instance.app_id);
        }

        let context = AppAuthzContext {
            app_id: instance.app_id,
            app_wallet: if is_zero_address(&anchored_wallet) {
                derived_app_wallet
            } else {
                anchored_wallet
            },
            instance_wallet,
        };

        let expires_at_ms = current_unix_millis().saturating_add(AUTHZ_CACHE_TTL_MS);
        let mut guard = self.authz_cache.lock().await;
        *guard = Some(CachedAuthzContext {
            context: context.clone(),
            expires_at_ms,
        });

        Ok(context)
    }

    async fn cached_authz_context(&self) -> Option<AppAuthzContext> {
        let now_ms = current_unix_millis();
        let mut guard = self.authz_cache.lock().await;
        if let Some(cached) = guard.as_ref()
            && now_ms < cached.expires_at_ms
        {
            return Some(cached.context.clone());
        }
        *guard = None;
        None
    }

    async fn resolve_base_urls(&self) -> Vec<String> {
        let Some(discovery) = self.registry_discovery.as_ref() else {
            return self.base_urls.to_vec();
        };

        let now_ms = current_unix_millis();
        {
            let guard = self.discovery_cache.lock().await;
            if let Some(cached) = guard.as_ref()
                && now_ms < cached.expires_at_ms
                && !cached.base_urls.is_empty()
            {
                return cached.base_urls.clone();
            }
        }

        let _refresh_guard = self.discovery_refresh_lock.lock().await;
        let now_ms = current_unix_millis();
        {
            let guard = self.discovery_cache.lock().await;
            if let Some(cached) = guard.as_ref()
                && now_ms < cached.expires_at_ms
                && !cached.base_urls.is_empty()
            {
                return cached.base_urls.clone();
            }
        }

        match self.discover_kms_nodes_from_registry(discovery).await {
            Ok(urls) if !urls.is_empty() => {
                let mut guard = self.discovery_cache.lock().await;
                *guard = Some(DiscoveryCacheEntry {
                    base_urls: urls.clone(),
                    expires_at_ms: now_ms.saturating_add(discovery.ttl_ms),
                });
                urls
            }
            Ok(_) => {
                warn!("Registry discovery returned no ACTIVE KMS nodes; falling back to static base_urls");
                self.base_urls.to_vec()
            }
            Err(err) => {
                warn!(
                    "Registry discovery failed ({}); falling back to static base_urls",
                    err
                );
                self.base_urls.to_vec()
            }
        }
    }

    async fn discover_kms_nodes_from_registry(
        &self,
        discovery: &RegistryDiscoveryConfig,
    ) -> Result<Vec<String>> {
        let active_wallets = self
            .registry_get_active_instances(discovery, discovery.kms_app_id)
            .await?;
        let mut urls = Vec::new();
        let mut dedup = HashSet::new();

        for wallet in active_wallets {
            let instance = self
                .registry_get_instance_by_wallet(discovery, &wallet)
                .await?;
            if instance.app_id != discovery.kms_app_id {
                continue;
            }
            if instance.status != 0 || !instance.zk_verified {
                continue;
            }
            if let Some(base_url) = normalize_base_url(&instance.instance_url)
                && dedup.insert(base_url.clone())
            {
                urls.push(base_url);
            }
        }

        urls.sort();
        Ok(urls)
    }

    fn build_registry_discovery(config: &KmsIntegration) -> Result<Option<RegistryDiscoveryConfig>> {
        let has_any_registry_field = config.kms_app_id.is_some()
            || config.nova_app_registry.is_some()
            || config.registry_chain_rpc.is_some();
        if !has_any_registry_field {
            return Ok(None);
        }

        let kms_app_id = config
            .kms_app_id
            .ok_or_else(|| anyhow!("kms_integration.kms_app_id is required for registry discovery"))?;
        let registry_address = config
            .nova_app_registry
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("kms_integration.nova_app_registry is required for registry discovery"))?;
        let registry_chain_rpc = config
            .registry_chain_rpc
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("kms_integration.registry_chain_rpc is required for registry discovery"))?;

        Ok(Some(RegistryDiscoveryConfig {
            kms_app_id,
            registry_address: canonical_wallet(registry_address)?,
            rpc_url: registry_chain_rpc.to_string(),
            ttl_ms: config.discovery_ttl_ms.max(1000),
        }))
    }

    async fn registry_get_active_instances(
        &self,
        discovery: &RegistryDiscoveryConfig,
        app_id: u64,
    ) -> Result<Vec<String>> {
        let function = registry_fn_get_active_instances();
        let output = self
            .registry_call(
                discovery,
                &function,
                vec![Token::Uint(U256::from(app_id))],
            )
            .await?;
        let first = output
            .first()
            .ok_or_else(|| anyhow!("registry getActiveInstances returned empty output"))?;
        match first {
            Token::Array(values) => values
                .iter()
                .map(|token| token_to_address(token, "getActiveInstances.wallet"))
                .collect(),
            other => bail!(
                "registry getActiveInstances returned unexpected token: {:?}",
                other
            ),
        }
    }

    async fn registry_get_instance_by_wallet(
        &self,
        discovery: &RegistryDiscoveryConfig,
        wallet: &str,
    ) -> Result<RegistryInstance> {
        let function = registry_fn_get_instance_by_wallet();
        let output = self
            .registry_call(
                discovery,
                &function,
                vec![Token::Address(parse_h160(wallet)?)],
            )
            .await?;
        let tuple = extract_single_tuple(output, "getInstanceByWallet")?;
        if tuple.len() < 10 {
            bail!(
                "registry getInstanceByWallet tuple too short: expected >=10, got {}",
                tuple.len()
            );
        }
        Ok(RegistryInstance {
            app_id: token_to_u64(&tuple[1], "getInstanceByWallet.appId")?,
            instance_url: token_to_string(&tuple[4], "getInstanceByWallet.instanceUrl")?,
            zk_verified: token_to_bool(&tuple[7], "getInstanceByWallet.zkVerified")?,
            status: token_to_u64(&tuple[8], "getInstanceByWallet.status")?,
        })
    }

    async fn registry_get_app(
        &self,
        discovery: &RegistryDiscoveryConfig,
        app_id: u64,
    ) -> Result<RegistryApp> {
        let function = registry_fn_get_app();
        let output = self
            .registry_call(
                discovery,
                &function,
                vec![Token::Uint(U256::from(app_id))],
            )
            .await?;
        let tuple = extract_single_tuple(output, "getApp")?;
        if tuple.len() < 9 {
            bail!(
                "registry getApp tuple too short: expected >=9, got {}",
                tuple.len()
            );
        }
        Ok(RegistryApp {
            status: token_to_u64(&tuple[7], "getApp.status")?,
            app_wallet: token_to_address(&tuple[8], "getApp.appWallet")?,
        })
    }

    async fn registry_call(
        &self,
        discovery: &RegistryDiscoveryConfig,
        function: &Function,
        args: Vec<Token>,
    ) -> Result<Vec<Token>> {
        let calldata = function.encode_input(&args)?;
        let raw_output = self.registry_eth_call(discovery, &calldata).await?;
        function
            .decode_output(&raw_output)
            .map_err(|e| anyhow!("registry decode {} failed: {}", function.name, e))
    }

    async fn registry_eth_call(
        &self,
        discovery: &RegistryDiscoveryConfig,
        calldata: &[u8],
    ) -> Result<Vec<u8>> {
        let payload = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "eth_call",
            params: json!([
                {
                    "to": discovery.registry_address,
                    "data": format!("0x{}", hex::encode(calldata)),
                },
                "latest"
            ]),
        };
        let response: JsonRpcResponse = self
            .client
            .post(&discovery.rpc_url)
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if let Some(err) = response.error {
            bail!("registry eth_call failed: {} ({})", err.message, err.code);
        }
        let result_hex = response
            .result
            .ok_or_else(|| anyhow!("registry eth_call missing result"))?;
        hex::decode(trim_0x(&result_hex))
            .map_err(|e| anyhow!("registry eth_call invalid hex result: {}", e))
    }
}

fn registry_fn_get_active_instances() -> Function {
    registry_function_from_abi(json!({
        "name": "getActiveInstances",
        "inputs": [
            {"name": "appId", "type": "uint256"}
        ],
        "outputs": [
            {"name": "", "type": "address[]"}
        ],
        "stateMutability": "view"
    }))
}

fn registry_fn_get_instance_by_wallet() -> Function {
    registry_function_from_abi(json!({
        "name": "getInstanceByWallet",
        "inputs": [
            {"name": "wallet", "type": "address"}
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "id", "type": "uint256"},
                    {"name": "appId", "type": "uint256"},
                    {"name": "versionId", "type": "uint256"},
                    {"name": "operator", "type": "address"},
                    {"name": "instanceUrl", "type": "string"},
                    {"name": "teePubkey", "type": "bytes"},
                    {"name": "teeWalletAddress", "type": "address"},
                    {"name": "zkVerified", "type": "bool"},
                    {"name": "status", "type": "uint8"},
                    {"name": "registeredAt", "type": "uint256"}
                ]
            }
        ],
        "stateMutability": "view"
    }))
}

fn registry_fn_get_app() -> Function {
    registry_function_from_abi(json!({
        "name": "getApp",
        "inputs": [
            {"name": "appId", "type": "uint256"}
        ],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "appId", "type": "uint256"},
                    {"name": "owner", "type": "address"},
                    {"name": "teeArch", "type": "bytes32"},
                    {"name": "dappContract", "type": "address"},
                    {"name": "metadataUri", "type": "string"},
                    {"name": "latestVersionId", "type": "uint256"},
                    {"name": "createdAt", "type": "uint256"},
                    {"name": "status", "type": "uint8"},
                    {"name": "appWallet", "type": "address"}
                ]
            }
        ],
        "stateMutability": "view"
    }))
}

fn registry_function_from_abi(value: Value) -> Function {
    serde_json::from_value(value).expect("valid registry function ABI")
}

fn extract_single_tuple(tokens: Vec<Token>, context: &str) -> Result<Vec<Token>> {
    if tokens.len() != 1 {
        bail!("{context} returned {} outputs, expected 1", tokens.len());
    }
    match tokens.into_iter().next() {
        Some(Token::Tuple(values)) => Ok(values),
        other => bail!("{context} expected tuple output, got {:?}", other),
    }
}

fn token_to_u64(token: &Token, field: &str) -> Result<u64> {
    match token {
        Token::Uint(v) => {
            if *v > U256::from(u64::MAX) {
                bail!("{field} exceeds u64");
            }
            Ok(v.low_u64())
        }
        other => bail!("{field} expected uint, got {:?}", other),
    }
}

fn token_to_bool(token: &Token, field: &str) -> Result<bool> {
    match token {
        Token::Bool(v) => Ok(*v),
        other => bail!("{field} expected bool, got {:?}", other),
    }
}

fn token_to_string(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::String(v) => Ok(v.clone()),
        other => bail!("{field} expected string, got {:?}", other),
    }
}

fn token_to_address(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::Address(v) => Ok(format!("0x{}", hex::encode(v.as_bytes()))),
        other => bail!("{field} expected address, got {:?}", other),
    }
}

fn parse_h160(address: &str) -> Result<H160> {
    let clean = trim_0x(address);
    if clean.len() != 40 {
        bail!("invalid address length: {}", address);
    }
    let bytes = hex::decode(clean).map_err(|e| anyhow!("invalid address hex: {}", e))?;
    Ok(H160::from_slice(&bytes))
}

fn normalize_base_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    while normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn trim_0x(value: &str) -> String {
    value.trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_string()
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn canonical_wallet(wallet: &str) -> Result<String> {
    let value = wallet.trim().to_lowercase();
    if value.starts_with("0x") && value.len() == 42 {
        return Ok(value);
    }
    if value.len() == 40 {
        return Ok(format!("0x{value}"));
    }
    bail!("invalid wallet address format: {}", wallet)
}

fn is_zero_address(wallet: &str) -> bool {
    canonical_wallet(wallet)
        .map(|v| v == ZERO_ADDRESS)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_path_detection_matches_prefix() {
        let proxy = NovaKmsProxy {
            client: reqwest::Client::new(),
            base_urls: Arc::from(vec!["https://kms-1.example.com".to_string()]),
            odyn_endpoint: "http://127.0.0.1:18000".to_string(),
            max_retries: 1,
            require_mutual_signature: true,
            reserved_derive_prefixes: Arc::new(vec!["wallet/eth/app/".to_string()]),
            audit_log_path: None,
            audit_log_sender: None,
            registry_discovery: None,
            discovery_cache: Arc::new(Mutex::new(None)),
            discovery_refresh_lock: Arc::new(Mutex::new(())),
            authz_cache: Arc::new(Mutex::new(None)),
        };

        assert!(proxy.is_reserved_derive_path("wallet/eth/app/main"));
        assert!(!proxy.is_reserved_derive_path("s3/v1/config.json"));
    }

    #[test]
    fn canonical_wallet_formats_inputs() {
        assert_eq!(
            canonical_wallet("0xAbCd000000000000000000000000000000000001").unwrap(),
            "0xabcd000000000000000000000000000000000001"
        );
        assert_eq!(
            canonical_wallet("abcd000000000000000000000000000000000001").unwrap(),
            "0xabcd000000000000000000000000000000000001"
        );
    }

    #[test]
    fn normalize_base_url_supports_missing_scheme() {
        assert_eq!(
            normalize_base_url("kms.example.com/"),
            Some("https://kms.example.com".to_string())
        );
        assert_eq!(
            normalize_base_url("https://kms.example.com/"),
            Some("https://kms.example.com".to_string())
        );
    }
}
