use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
use log::{info, warn};
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

mod app_wallet;

const APP_WALLET_KV_PRIVATE_KEY: &str = "wallet/eth/app/main/private_key";
const APP_WALLET_KV_ADDRESS: &str = "wallet/eth/app/main/address";
const AUTHZ_CACHE_TTL_MS: u64 = 10_000;
const APP_WALLET_CACHE_TTL_MS: u64 = 10_000;
const DEFAULT_REGISTRY_CHAIN_RPC: &str = "http://127.0.0.1:18545";
const DEFAULT_KMS_REQUEST_TIMEOUT_MS: u64 = 3000;
const DEFAULT_KMS_MAX_ATTEMPTS: usize = 3;
const DEFAULT_KMS_DISCOVERY_TTL_MS: u64 = 60_000;
const DEFAULT_KMS_NODE_REACHABLE_CACHE_TTL_MS: u64 = 30_000;
const DEFAULT_KMS_NODE_UNREACHABLE_CACHE_TTL_MS: u64 = 10_000;
const DEFAULT_KMS_BACKGROUND_REFRESH_INTERVAL_MS: u64 = 20_000;
const DEFAULT_KMS_REQUIRE_MUTUAL_SIGNATURE: bool = true;
const DEFAULT_KMS_RESERVED_DERIVE_PREFIXES: [&str; 1] = ["wallet/eth/app/"];
const DEFAULT_KMS_AUDIT_LOG_PATH: &str = "/tmp/odyn_kms_audit.log";
const KMS_DEBUG_LOG_MAX_LEN: usize = 1024;

#[derive(Clone)]
pub struct NovaKmsProxy {
    client: reqwest::Client,
    odyn_endpoint: String,
    use_app_wallet: bool,
    max_retries: usize,
    require_mutual_signature: bool,
    reserved_derive_prefixes: Arc<Vec<String>>,
    audit_log_path: Option<PathBuf>,
    audit_log_sender: Option<mpsc::UnboundedSender<String>>,
    registry_discovery: Option<RegistryDiscoveryConfig>,
    discovery_cache: Arc<Mutex<Option<DiscoveryCacheEntry>>>,
    background_refresh_started: Arc<AtomicBool>,
    discovery_refresh_lock: Arc<Mutex<()>>,
    authz_cache: Arc<Mutex<Option<CachedAuthzContext>>>,
    app_wallet_cache: Arc<Mutex<Option<CachedAppWallet>>>,
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
struct AppWalletMaterial {
    private_key_hex: String,
    address: String,
}

#[derive(Clone)]
struct CachedAppWallet {
    material: AppWalletMaterial,
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
    nodes: Vec<KmsNodeCacheEntry>,
    expires_at_ms: u64,
}

#[derive(Clone)]
struct KmsNodeCacheEntry {
    wallet: String,
    base_url: String,
    reachable: Option<bool>,
    expires_at_ms: u64,
    last_checked_ms: u64,
    last_http_status: Option<u16>,
    last_error: Option<String>,
}

impl KmsNodeCacheEntry {
    fn new(wallet: String, base_url: String) -> Self {
        Self {
            wallet,
            base_url,
            reachable: None,
            expires_at_ms: 0,
            last_checked_ms: 0,
            last_http_status: None,
            last_error: None,
        }
    }

    fn mark_reachability(
        &mut self,
        reachable: bool,
        expires_at_ms: u64,
        last_http_status: Option<u16>,
        last_error: Option<String>,
    ) {
        self.reachable = Some(reachable);
        self.expires_at_ms = expires_at_ms;
        self.last_checked_ms = current_unix_millis();
        self.last_http_status = last_http_status;
        self.last_error = last_error;
    }
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
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(DEFAULT_KMS_REQUEST_TIMEOUT_MS))
            .build()?;

        let reserved_derive_prefixes = DEFAULT_KMS_RESERVED_DERIVE_PREFIXES
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        let registry_discovery = Self::build_registry_discovery(config)?;
        let audit_log_path = Some(PathBuf::from(DEFAULT_KMS_AUDIT_LOG_PATH));
        let audit_log_sender = Self::spawn_audit_log_writer(audit_log_path.clone());

        Ok(Self {
            client,
            odyn_endpoint,
            use_app_wallet: config.use_app_wallet,
            max_retries: DEFAULT_KMS_MAX_ATTEMPTS,
            require_mutual_signature: DEFAULT_KMS_REQUIRE_MUTUAL_SIGNATURE,
            reserved_derive_prefixes: Arc::new(reserved_derive_prefixes),
            audit_log_path,
            audit_log_sender,
            registry_discovery,
            discovery_cache: Arc::new(Mutex::new(None)),
            background_refresh_started: Arc::new(AtomicBool::new(false)),
            discovery_refresh_lock: Arc::new(Mutex::new(())),
            authz_cache: Arc::new(Mutex::new(None)),
            app_wallet_cache: Arc::new(Mutex::new(None)),
        })
    }

    pub fn start_background_refresh(self: &Arc<Self>) {
        if self.registry_discovery.is_none() {
            info!("Nova KMS background refresh skipped: registry discovery is not configured");
            return;
        }
        if self.background_refresh_started.swap(true, Ordering::AcqRel) {
            info!("Nova KMS background refresh already started");
            return;
        }
        info!(
            "Nova KMS background refresh started (interval={}ms)",
            DEFAULT_KMS_BACKGROUND_REFRESH_INTERVAL_MS
        );

        let proxy = self.clone();
        tokio::spawn(async move {
            loop {
                let request_id = Uuid::new_v4().to_string();
                if let Err(err) = proxy
                    .refresh_registry_and_node_status_once(&request_id)
                    .await
                {
                    warn!(
                        "Nova KMS [{}] background refresh failed: {}",
                        request_id, err
                    );
                }
                tokio::time::sleep(Duration::from_millis(
                    DEFAULT_KMS_BACKGROUND_REFRESH_INTERVAL_MS,
                ))
                .await;
            }
        });
    }

    fn spawn_audit_log_writer(path: Option<PathBuf>) -> Option<mpsc::UnboundedSender<String>> {
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

    pub fn is_app_wallet_enabled(&self) -> bool {
        self.use_app_wallet
    }

    pub async fn ensure_kms_access_authorized(&self) -> Result<AppAuthzContext> {
        self.resolve_authz_context().await
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

    pub async fn derive_key(&self, path: &str, context: &str, length: usize) -> Result<Vec<u8>> {
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
            warn!("Nova KMS authz failed for /v1/kms/derive: {}", err);
            return Ok(http_util::bad_request(err.to_string()));
        }
        info!("Nova KMS authz passed for /v1/kms/derive");

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
            warn!("Nova KMS authz failed for /v1/kms/kv/get: {}", err);
            return Ok(http_util::bad_request(err.to_string()));
        }
        info!("Nova KMS authz passed for /v1/kms/kv/get");

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
            warn!("Nova KMS authz failed for /v1/kms/kv/put: {}", err);
            return Ok(http_util::bad_request(err.to_string()));
        }
        info!("Nova KMS authz passed for /v1/kms/kv/put");

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
            warn!("Nova KMS authz failed for /v1/kms/kv/delete: {}", err);
            return Ok(http_util::bad_request(err.to_string()));
        }
        info!("Nova KMS authz passed for /v1/kms/kv/delete");

        match self.kv_delete(&req.key).await {
            Ok(()) => Ok(http_util::ok_json(&KvDeleteApiResponse { success: true })?),
            Err(err) => Ok(http_util::bad_request(err.to_string())),
        }
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
        let node_candidates = self.resolve_node_candidates(&request_id).await?;
        let payload_preview = payload
            .as_ref()
            .map(preview_json_for_log)
            .unwrap_or_else(|| "<none>".to_string());
        info!(
            "Nova KMS [{}] begin {} {} payload_hash={} payload={} nodes={}",
            request_id,
            method.as_str(),
            path,
            payload_hash,
            payload_preview,
            node_candidates.len(),
        );

        for attempt in 0..self.max_retries {
            for node in &node_candidates {
                let base_url = &node.base_url;
                let action = format!("{} {}", method.as_str(), path);
                info!(
                    "Nova KMS [{}] attempt {}/{} node={} action={}",
                    request_id,
                    attempt + 1,
                    self.max_retries,
                    base_url,
                    action,
                );
                let result = self
                    .call_kms_on_node(&request_id, node, method.clone(), path, payload.clone())
                    .await;

                match result {
                    Ok(value) => {
                        self.update_node_reachability_cache(base_url, true, None, None)
                            .await;
                        let response_preview = preview_json_for_log(&value);
                        info!(
                            "Nova KMS [{}] success node={} action={} response={}",
                            request_id, base_url, action, response_preview,
                        );
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
                        let err_text = err.to_string();
                        if looks_like_connectivity_error(&err_text) {
                            self.update_node_reachability_cache(
                                base_url,
                                false,
                                None,
                                Some(truncate_for_log(&err_text, KMS_DEBUG_LOG_MAX_LEN)),
                            )
                            .await;
                        }
                        warn!(
                            "Nova KMS [{}] failed node={} action={} attempt {}/{} error={}",
                            request_id,
                            base_url,
                            action,
                            attempt + 1,
                            self.max_retries,
                            err_text,
                        );
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
        request_id: &str,
        node: &KmsNodeCacheEntry,
        method: Method,
        path: &str,
        payload: Option<Value>,
    ) -> Result<Value> {
        let base_url = &node.base_url;
        info!(
            "Nova KMS [{}] contacting node={} wallet={} method={} path={}",
            request_id,
            base_url,
            node.wallet,
            method.as_str(),
            path
        );
        let status_identity = self.fetch_node_identity(base_url).await?;
        info!(
            "Nova KMS [{}] selected node identity status_wallet={} tee_pubkey_len={}",
            request_id,
            status_identity.wallet,
            status_identity.tee_pubkey.len()
        );
        if status_identity.wallet != node.wallet {
            warn!(
                "Nova KMS [{}] registry/status wallet mismatch for node={} registry_wallet={} status_wallet={}",
                request_id, base_url, node.wallet, status_identity.wallet
            );
        }
        let nonce_b64 = self.fetch_nonce(base_url).await?;
        info!(
            "Nova KMS [{}] fetched nonce for node={} nonce_b64_len={}",
            request_id,
            base_url,
            nonce_b64.len()
        );
        let timestamp = current_unix_timestamp();
        let message = format!(
            "NovaKMS:AppAuth:{}:{}:{}",
            nonce_b64,
            canonical_wallet(&node.wallet)?,
            timestamp
        );
        let client_signature = self.local_sign_message(&message).await?;
        info!(
            "Nova KMS [{}] PoP signature generated for node={} timestamp={}",
            request_id, base_url, timestamp
        );
        let app_wallet = self.local_eth_address().await?;

        let mut req = self
            .client
            .request(method.clone(), format!("{base_url}{path}"));
        req = req
            .header("x-app-signature", client_signature.clone())
            .header("x-app-nonce", nonce_b64)
            .header("x-app-timestamp", timestamp.to_string())
            .header("x-app-wallet", app_wallet);

        let mut upstream_request_preview = "<none>".to_string();
        if let Some(payload_json) = payload {
            let payload_preview = preview_json_for_log(&payload_json);
            info!(
                "Nova KMS [{}] starting E2E encryption node={} payload={}",
                request_id, base_url, payload_preview
            );
            let envelope = self
                .encrypt_payload_for_node(&payload_json, &status_identity.tee_pubkey)
                .await?;
            upstream_request_preview = preview_json_for_log(&envelope);
            info!(
                "Nova KMS [{}] E2E encryption completed node={} envelope={}",
                request_id, base_url, upstream_request_preview
            );
            req = req.header(CONTENT_TYPE, "application/json").json(&envelope);
        }

        info!(
            "Nova KMS [{}] sending upstream request node={} request={}",
            request_id, base_url, upstream_request_preview
        );
        let response = req.send().await?;
        let status = response.status();
        let mutual_sig = response
            .headers()
            .get("x-kms-response-signature")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        let response_text = response.text().await?;
        let response_preview = preview_text_for_log(&response_text);
        info!(
            "Nova KMS [{}] upstream response node={} status={} body={}",
            request_id,
            base_url,
            status.as_u16(),
            response_preview
        );
        if !status.is_success() {
            bail!("KMS HTTP {}: {}", status.as_u16(), response_text);
        }

        if self.require_mutual_signature {
            let sig = mutual_sig
                .as_deref()
                .ok_or_else(|| anyhow!("KMS response missing X-KMS-Response-Signature"))?;
            self.verify_mutual_response_signature(
                request_id,
                base_url,
                sig,
                &client_signature,
                &node.wallet,
                &status_identity.wallet,
            )
            .await?;
        }

        let envelope: Value = serde_json::from_str(&response_text)?;
        info!(
            "Nova KMS [{}] starting E2E decrypt node={} envelope={}",
            request_id,
            base_url,
            preview_json_for_log(&envelope)
        );
        let plaintext = self.decrypt_envelope(&envelope).await?;
        info!(
            "Nova KMS [{}] E2E decrypt succeeded node={} plaintext={}",
            request_id,
            base_url,
            preview_json_for_log(&plaintext)
        );
        Ok(plaintext)
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
            .ok_or_else(|| {
                anyhow!("Odyn /v1/encryption/public_key response missing public_key_der")
            })?;
        Ok(trim_0x(pubkey))
    }

    async fn encrypt_payload_for_node(
        &self,
        payload: &Value,
        node_tee_pubkey: &str,
    ) -> Result<Value> {
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
            .ok_or_else(|| {
                anyhow!("Odyn /v1/encryption/encrypt response missing encrypted_data")
            })?;

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

    async fn resolve_authz_context(&self) -> Result<AppAuthzContext> {
        if let Some(cached) = self.cached_authz_context().await {
            return Ok(cached);
        }

        let discovery = self
            .registry_discovery
            .as_ref()
            .ok_or_else(|| anyhow!("registry-based authz requires kms_app_id/nova_app_registry"))?;

        let instance_wallet = self.local_eth_address().await?;
        let instance = self
            .registry_get_instance_by_wallet(discovery, &instance_wallet)
            .await?;

        if !instance.zk_verified {
            bail!(
                "instance {} is not zk-verified on registry",
                instance_wallet
            );
        }
        if instance.status != 0 {
            bail!("instance {} is not ACTIVE on registry", instance_wallet);
        }

        let app = self.registry_get_app(discovery, instance.app_id).await?;
        if app.status != 0 {
            bail!("app {} is not ACTIVE on registry", instance.app_id);
        }
        let anchored_wallet = canonical_wallet(&app.app_wallet)?;

        let context = AppAuthzContext {
            app_id: instance.app_id,
            app_wallet: anchored_wallet,
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

    async fn resolve_node_candidates(&self, request_id: &str) -> Result<Vec<KmsNodeCacheEntry>> {
        let discovered_nodes = self.resolve_discovered_nodes(request_id).await?;
        let prioritized_nodes = self
            .resolve_connectable_nodes(request_id, &discovered_nodes)
            .await;
        if !prioritized_nodes.is_empty() {
            return Ok(prioritized_nodes);
        }

        // Keep a safe fallback: if all probes fail, still attempt discovered nodes to avoid
        // over-relying on stale or pessimistic connectivity cache entries.
        warn!(
            "Nova KMS [{}] no eligible node from connectivity cache; fallback to discovered nodes={}",
            request_id,
            format_node_wallet_urls(&discovered_nodes)
        );
        Ok(discovered_nodes)
    }

    async fn refresh_registry_and_node_status_once(&self, request_id: &str) -> Result<()> {
        let discovery = match self.registry_discovery.as_ref() {
            Some(v) => v,
            None => return Ok(()),
        };
        let now_ms = current_unix_millis();
        let previous_snapshot = { self.discovery_cache.lock().await.clone() };
        let discovered_nodes = self.discover_kms_nodes_from_registry(discovery).await?;

        // Build and probe the refreshed list off-lock so existing cache remains fully usable
        // while refresh is in flight.
        let mut refreshed_nodes = if discovered_nodes.is_empty() {
            previous_snapshot
                .as_ref()
                .map(|cached| cached.nodes.clone())
                .unwrap_or_default()
        } else {
            merge_discovered_nodes_with_previous(
                discovered_nodes.clone(),
                previous_snapshot.as_ref(),
                now_ms,
            )
        };

        for node in &mut refreshed_nodes {
            match self.probe_node_status_once(&node.base_url).await {
                Ok(status_code) => {
                    let expires_at_ms = current_unix_millis()
                        .saturating_add(DEFAULT_KMS_NODE_REACHABLE_CACHE_TTL_MS);
                    node.mark_reachability(true, expires_at_ms, Some(status_code), None);
                }
                Err(err) => {
                    let expires_at_ms = current_unix_millis()
                        .saturating_add(DEFAULT_KMS_NODE_UNREACHABLE_CACHE_TTL_MS);
                    node.mark_reachability(
                        false,
                        expires_at_ms,
                        None,
                        Some(truncate_for_log(&err.to_string(), KMS_DEBUG_LOG_MAX_LEN)),
                    );
                }
            }
        }

        let swap_now_ms = current_unix_millis();
        let node_list = {
            let mut guard = self.discovery_cache.lock().await;
            let merged_nodes =
                merge_refresh_with_live_cache(refreshed_nodes, guard.as_ref(), swap_now_ms);
            let node_list = format_node_refresh_list(&merged_nodes, swap_now_ms);
            *guard = Some(DiscoveryCacheEntry {
                nodes: merged_nodes.clone(),
                expires_at_ms: swap_now_ms.saturating_add(discovery.ttl_ms),
            });
            node_list
        };
        info!(
            "Nova KMS [{}] refreshed KMS node list app_id={} nodes={}",
            request_id, discovery.kms_app_id, node_list
        );
        Ok(())
    }

    async fn resolve_discovered_nodes(&self, request_id: &str) -> Result<Vec<KmsNodeCacheEntry>> {
        let discovery = self
            .registry_discovery
            .as_ref()
            .ok_or_else(|| anyhow!("kms_integration requires registry discovery configuration"))?;

        let now_ms = current_unix_millis();
        {
            let guard = self.discovery_cache.lock().await;
            if let Some(cached) = guard.as_ref()
                && now_ms < cached.expires_at_ms
                && !cached.nodes.is_empty()
            {
                info!(
                    "Nova KMS [{}] discovery cache hit rpc={} app_id={} nodes={}",
                    request_id,
                    discovery.rpc_url,
                    discovery.kms_app_id,
                    format_node_wallet_urls(&cached.nodes)
                );
                return Ok(cached.nodes.clone());
            }
        }

        let _refresh_guard = self.discovery_refresh_lock.lock().await;
        let now_ms = current_unix_millis();
        {
            let guard = self.discovery_cache.lock().await;
            if let Some(cached) = guard.as_ref()
                && now_ms < cached.expires_at_ms
                && !cached.nodes.is_empty()
            {
                info!(
                    "Nova KMS [{}] discovery cache hit after lock rpc={} app_id={} nodes={}",
                    request_id,
                    discovery.rpc_url,
                    discovery.kms_app_id,
                    format_node_wallet_urls(&cached.nodes)
                );
                return Ok(cached.nodes.clone());
            }
        }

        match self.discover_kms_nodes_from_registry(discovery).await {
            Ok(nodes) if !nodes.is_empty() => {
                info!(
                    "Nova KMS [{}] discovered active KMS nodes via registry app_id={} rpc={} nodes={}",
                    request_id,
                    discovery.kms_app_id,
                    discovery.rpc_url,
                    format_node_wallet_urls(&nodes)
                );
                let mut guard = self.discovery_cache.lock().await;
                let merged_nodes =
                    merge_discovered_nodes_with_previous(nodes.clone(), guard.as_ref(), now_ms);
                *guard = Some(DiscoveryCacheEntry {
                    nodes: merged_nodes.clone(),
                    expires_at_ms: now_ms.saturating_add(discovery.ttl_ms),
                });
                Ok(merged_nodes)
            }
            Ok(_) => {
                warn!(
                    "Nova KMS [{}] discovery found no active nodes app_id={} rpc={}",
                    request_id, discovery.kms_app_id, discovery.rpc_url
                );
                bail!(
                    "registry discovery returned no ACTIVE KMS nodes for app_id {}",
                    discovery.kms_app_id
                )
            }
            Err(err) => {
                warn!(
                    "Nova KMS [{}] discovery failed app_id={} rpc={} error={}",
                    request_id, discovery.kms_app_id, discovery.rpc_url, err
                );
                Err(anyhow!("registry discovery failed: {}", err))
            }
        }
    }

    async fn resolve_connectable_nodes(
        &self,
        request_id: &str,
        discovered_nodes: &[KmsNodeCacheEntry],
    ) -> Vec<KmsNodeCacheEntry> {
        let now_ms = current_unix_millis();
        let mut reachable = Vec::new();
        let mut unknown = Vec::new();
        let mut unreachable_count = 0usize;

        for node in discovered_nodes {
            if node.reachable == Some(true) && now_ms < node.expires_at_ms {
                info!(
                    "Nova KMS [{}] node reachability cache hit reachable node={} wallet={}",
                    request_id, node.base_url, node.wallet
                );
                reachable.push(node.clone());
                continue;
            }

            if node.reachable == Some(false) && now_ms < node.expires_at_ms {
                unreachable_count += 1;
                warn!(
                    "Nova KMS [{}] node reachability cache hit unreachable node={} wallet={} http_status={:?} last_checked_ms={} reason={}",
                    request_id,
                    node.base_url,
                    node.wallet,
                    node.last_http_status,
                    node.last_checked_ms,
                    node.last_error.as_deref().unwrap_or("<unknown>")
                );
                continue;
            }

            unknown.push(node.clone());
        }

        let mut prioritized = Vec::with_capacity(reachable.len() + unknown.len());
        prioritized.extend(reachable.clone());
        prioritized.extend(unknown.clone());

        if prioritized.is_empty() {
            warn!(
                "Nova KMS [{}] connectable node set is empty (discovered={} unreachable_cached={})",
                request_id,
                format_node_wallet_urls(discovered_nodes),
                unreachable_count
            );
        } else {
            info!(
                "Nova KMS [{}] prioritized nodes reachable_cached={} unknown={} unreachable_cached={} nodes={}",
                request_id,
                reachable.len(),
                unknown.len(),
                unreachable_count,
                format_node_wallet_urls(&prioritized)
            );
        }
        prioritized
    }

    async fn probe_node_status_once(&self, base_url: &str) -> Result<u16> {
        let status_url = format!("{base_url}/status");
        let response = self.client.get(&status_url).send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "status probe failed node={} http={} body={}",
                base_url,
                status.as_u16(),
                truncate_for_log(&body, KMS_DEBUG_LOG_MAX_LEN)
            );
        }
        Ok(status.as_u16())
    }

    async fn update_node_reachability_cache(
        &self,
        base_url: &str,
        reachable: bool,
        last_http_status: Option<u16>,
        last_error: Option<String>,
    ) {
        let ttl_ms = if reachable {
            DEFAULT_KMS_NODE_REACHABLE_CACHE_TTL_MS
        } else {
            DEFAULT_KMS_NODE_UNREACHABLE_CACHE_TTL_MS
        };
        let expires_at_ms = current_unix_millis().saturating_add(ttl_ms);
        let mut guard = self.discovery_cache.lock().await;
        if let Some(cached) = guard.as_mut()
            && let Some(node) = cached.nodes.iter_mut().find(|n| n.base_url == base_url)
        {
            node.mark_reachability(reachable, expires_at_ms, last_http_status, last_error);
        }
    }

    async fn verify_mutual_response_signature(
        &self,
        request_id: &str,
        base_url: &str,
        signature: &str,
        client_signature: &str,
        expected_wallet: &str,
        observed_status_wallet: &str,
    ) -> Result<()> {
        let signer_wallet = canonical_wallet(expected_wallet)?;
        let verify_message = format!("NovaKMS:Response:{}:{}", client_signature, signer_wallet);
        let prefixed_verify_message = eip191_personal_message_bytes(&verify_message);
        if !EthKey::verify_message(
            signature.to_string(),
            &prefixed_verify_message,
            signer_wallet.clone(),
        ) {
            bail!(
                "KMS mutual response signature verification failed (expected_signer={})",
                signer_wallet
            );
        }

        let status_wallet = canonical_wallet(observed_status_wallet)
            .unwrap_or_else(|_| observed_status_wallet.to_string());
        if signer_wallet != status_wallet {
            warn!(
                "Nova KMS [{}] mutual response signer differs from /status wallet: signer={} status_wallet={} node={}",
                request_id, signer_wallet, status_wallet, base_url
            );
        }

        info!(
            "Nova KMS [{}] mutual response signature verification succeeded node={} signer_wallet={} source=node_cache format=eip191",
            request_id, base_url, signer_wallet
        );
        Ok(())
    }

    async fn discover_kms_nodes_from_registry(
        &self,
        discovery: &RegistryDiscoveryConfig,
    ) -> Result<Vec<KmsNodeCacheEntry>> {
        let active_wallets = self
            .registry_get_active_instances(discovery, discovery.kms_app_id)
            .await?;
        let mut nodes = Vec::new();
        let mut dedup = HashSet::new();

        for wallet in active_wallets {
            let canonical = canonical_wallet(&wallet)?;
            let instance = self
                .registry_get_instance_by_wallet(discovery, &canonical)
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
                nodes.push(KmsNodeCacheEntry::new(canonical, base_url));
            }
        }

        nodes.sort_by(|a, b| a.base_url.cmp(&b.base_url));
        Ok(nodes)
    }

    fn build_registry_discovery(
        config: &KmsIntegration,
    ) -> Result<Option<RegistryDiscoveryConfig>> {
        let has_any_registry_field =
            config.kms_app_id.is_some() || config.nova_app_registry.is_some();
        if !has_any_registry_field {
            return Ok(None);
        }

        let kms_app_id = config.kms_app_id.ok_or_else(|| {
            anyhow!("kms_integration.kms_app_id is required for registry discovery")
        })?;
        let registry_address = config
            .nova_app_registry
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                anyhow!("kms_integration.nova_app_registry is required for registry discovery")
            })?;
        Ok(Some(RegistryDiscoveryConfig {
            kms_app_id,
            registry_address: canonical_wallet(registry_address)?,
            rpc_url: DEFAULT_REGISTRY_CHAIN_RPC.to_string(),
            ttl_ms: DEFAULT_KMS_DISCOVERY_TTL_MS,
        }))
    }

    async fn registry_get_active_instances(
        &self,
        discovery: &RegistryDiscoveryConfig,
        app_id: u64,
    ) -> Result<Vec<String>> {
        let function = registry_fn_get_active_instances();
        let output = self
            .registry_call(discovery, &function, vec![Token::Uint(U256::from(app_id))])
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
            .registry_call(discovery, &function, vec![Token::Uint(U256::from(app_id))])
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
        return None;
    }
    let parsed = reqwest::Url::parse(&normalized).ok()?;
    parsed.host_str()?;
    Some(normalized)
}

fn merge_discovered_nodes_with_previous(
    mut discovered_nodes: Vec<KmsNodeCacheEntry>,
    previous: Option<&DiscoveryCacheEntry>,
    now_ms: u64,
) -> Vec<KmsNodeCacheEntry> {
    let Some(previous) = previous else {
        return discovered_nodes;
    };
    let previous_by_url: HashMap<&str, &KmsNodeCacheEntry> = previous
        .nodes
        .iter()
        .map(|entry| (entry.base_url.as_str(), entry))
        .collect();
    for node in &mut discovered_nodes {
        if let Some(previous_node) = previous_by_url.get(node.base_url.as_str())
            && now_ms < previous_node.expires_at_ms
        {
            node.reachable = previous_node.reachable;
            node.expires_at_ms = previous_node.expires_at_ms;
            node.last_checked_ms = previous_node.last_checked_ms;
            node.last_http_status = previous_node.last_http_status;
            node.last_error = previous_node.last_error.clone();
        }
    }
    discovered_nodes
}

fn merge_refresh_with_live_cache(
    mut refreshed_nodes: Vec<KmsNodeCacheEntry>,
    live_cache: Option<&DiscoveryCacheEntry>,
    now_ms: u64,
) -> Vec<KmsNodeCacheEntry> {
    let Some(live_cache) = live_cache else {
        return refreshed_nodes;
    };
    let live_by_url: HashMap<&str, &KmsNodeCacheEntry> = live_cache
        .nodes
        .iter()
        .map(|entry| (entry.base_url.as_str(), entry))
        .collect();
    for refreshed in &mut refreshed_nodes {
        if let Some(live) = live_by_url.get(refreshed.base_url.as_str())
            && live.last_checked_ms > refreshed.last_checked_ms
            && now_ms < live.expires_at_ms
        {
            refreshed.reachable = live.reachable;
            refreshed.expires_at_ms = live.expires_at_ms;
            refreshed.last_checked_ms = live.last_checked_ms;
            refreshed.last_http_status = live.last_http_status;
            refreshed.last_error = live.last_error.clone();
        }
    }
    refreshed_nodes
}

fn format_node_wallet_urls(nodes: &[KmsNodeCacheEntry]) -> String {
    if nodes.is_empty() {
        return "<none>".to_string();
    }
    nodes
        .iter()
        .map(|node| format!("{}@{}", node.wallet, node.base_url))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_node_refresh_list(nodes: &[KmsNodeCacheEntry], now_ms: u64) -> String {
    if nodes.is_empty() {
        return "<none>".to_string();
    }
    nodes
        .iter()
        .map(|node| {
            let reachability = match node.reachable {
                Some(true) if now_ms < node.expires_at_ms => "reachable",
                Some(false) if now_ms < node.expires_at_ms => "unreachable",
                _ => "unknown",
            };
            format!(
                "{{wallet={},url={},reachability={}}}",
                node.wallet, node.base_url, reachability
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn trim_0x(value: &str) -> String {
    value
        .trim_start_matches("0x")
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

fn truncate_for_log(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    format!("{}...(truncated)", &value[..max_len])
}

fn is_sensitive_log_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "key"
            | "value"
            | "private_key"
            | "signature"
            | "encrypted_data"
            | "onchain_proof"
            | "proof"
    )
}

fn redact_json_for_log(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive_log_field(k) {
                    let approx_len = match v {
                        Value::String(s) => s.len(),
                        _ => v.to_string().len(),
                    };
                    redacted.insert(
                        k.clone(),
                        Value::String(format!("<redacted:{} chars>", approx_len)),
                    );
                } else {
                    redacted.insert(k.clone(), redact_json_for_log(v));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json_for_log).collect()),
        _ => value.clone(),
    }
}

fn preview_json_for_log(value: &Value) -> String {
    let redacted = redact_json_for_log(value);
    truncate_for_log(&redacted.to_string(), KMS_DEBUG_LOG_MAX_LEN)
}

fn preview_text_for_log(text: &str) -> String {
    if let Ok(json_value) = serde_json::from_str::<Value>(text) {
        return preview_json_for_log(&json_value);
    }
    truncate_for_log(text, KMS_DEBUG_LOG_MAX_LEN)
}

fn looks_like_connectivity_error(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    let markers = [
        "error sending request for url",
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "dns error",
        "tls",
        "tcp connect",
        "channel closed",
        "broken pipe",
        "network is unreachable",
    ];
    markers.iter().any(|marker| lowered.contains(marker))
}

fn canonical_wallet(wallet: &str) -> Result<String> {
    let value = wallet.trim().to_lowercase();
    let body = if let Some(stripped) = value.strip_prefix("0x") {
        if stripped.len() != 40 {
            bail!("invalid wallet address format: {}", wallet);
        }
        stripped
    } else if value.len() == 40 {
        value.as_str()
    } else {
        bail!("invalid wallet address format: {}", wallet);
    };
    hex::decode(body).map_err(|_| anyhow!("invalid wallet address format: {}", wallet))?;
    Ok(format!("0x{}", body))
}

fn decode_kms_wallet_address(value_b64: &str) -> Result<String> {
    let decoded = general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|e| anyhow!("invalid KMS app wallet address encoding: {}", e))?;
    let address = std::str::from_utf8(&decoded)
        .map_err(|e| anyhow!("invalid KMS app wallet address utf8: {}", e))?;
    canonical_wallet(address)
}

fn decode_kms_private_key_hex(value_b64: &str) -> Result<String> {
    let decoded = general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|e| anyhow!("invalid KMS app wallet key encoding: {}", e))?;

    if decoded.len() == 32 {
        return Ok(format!("0x{}", hex::encode(decoded)));
    }

    let key_text = std::str::from_utf8(&decoded)
        .map_err(|e| anyhow!("invalid KMS app wallet key utf8: {}", e))?;
    let clean = trim_0x(key_text).to_lowercase();
    if clean.len() != 64 {
        bail!("invalid KMS app wallet key length");
    }
    hex::decode(&clean).map_err(|e| anyhow!("invalid KMS app wallet key hex: {}", e))?;
    Ok(format!("0x{}", clean))
}

fn eip191_personal_message_bytes(message: &str) -> Vec<u8> {
    let msg_bytes = message.as_bytes();
    let prefix = format!("\u{0019}Ethereum Signed Message:\n{}", msg_bytes.len());
    let mut prefixed = prefix.into_bytes();
    prefixed.extend_from_slice(msg_bytes);
    prefixed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::KmsIntegration;
    use ethabi::ethereum_types::U256;

    #[test]
    fn reserved_path_detection_matches_prefix() {
        let proxy = NovaKmsProxy {
            client: reqwest::Client::new(),
            odyn_endpoint: "http://127.0.0.1:18000".to_string(),
            use_app_wallet: false,
            max_retries: 1,
            require_mutual_signature: true,
            reserved_derive_prefixes: Arc::new(vec!["wallet/eth/app/".to_string()]),
            audit_log_path: None,
            audit_log_sender: None,
            registry_discovery: None,
            discovery_cache: Arc::new(Mutex::new(None)),
            background_refresh_started: Arc::new(AtomicBool::new(false)),
            discovery_refresh_lock: Arc::new(Mutex::new(())),
            authz_cache: Arc::new(Mutex::new(None)),
            app_wallet_cache: Arc::new(Mutex::new(None)),
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
        assert_eq!(normalize_base_url("https://"), None);
    }

    #[test]
    fn canonical_wallet_rejects_invalid_hex() {
        assert!(canonical_wallet("0xzzzz000000000000000000000000000000000000").is_err());
        assert!(canonical_wallet("not-a-wallet").is_err());
    }

    #[test]
    fn parse_h160_rejects_invalid_inputs() {
        assert!(parse_h160("0x1234").is_err());
        assert!(parse_h160("0xgggg000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn extract_single_tuple_rejects_invalid_shapes() {
        assert!(extract_single_tuple(vec![], "ctx").is_err());
        assert!(extract_single_tuple(vec![Token::Uint(U256::from(1u64))], "ctx").is_err());
        assert!(
            extract_single_tuple(vec![Token::Tuple(vec![]), Token::Tuple(vec![])], "ctx").is_err()
        );
    }

    #[test]
    fn token_to_u64_rejects_overflow_and_wrong_type() {
        let overflow = Token::Uint(U256::from(u64::MAX) + U256::from(1u64));
        assert!(token_to_u64(&overflow, "field").is_err());
        assert!(token_to_u64(&Token::Bool(true), "field").is_err());
    }

    #[test]
    fn truncate_for_log_truncates_and_keeps_short_values() {
        assert_eq!(truncate_for_log("short", 64), "short");
        assert_eq!(truncate_for_log("abcdef", 3), "abc...(truncated)");
    }

    #[test]
    fn eip191_personal_message_prefix_matches_expected_format() {
        let message = "NovaKMS:Response:0xabc:0xdef";
        let bytes = eip191_personal_message_bytes(message);
        let expected = format!(
            "\u{0019}Ethereum Signed Message:\n{}{}",
            message.len(),
            message
        )
        .into_bytes();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn preview_json_for_log_redacts_sensitive_fields() {
        let value = json!({
            "path": "demo/path",
            "key": "base64-secret",
            "value": "plaintext",
            "nested": {
                "signature": "0xabc",
            }
        });
        let preview = preview_json_for_log(&value);
        assert!(preview.contains("\"path\":\"demo/path\""));
        assert!(preview.contains("<redacted:13 chars>"));
        assert!(preview.contains("<redacted:9 chars>"));
        assert!(preview.contains("<redacted:5 chars>"));
        assert!(!preview.contains("base64-secret"));
        assert!(!preview.contains("plaintext"));
        assert!(!preview.contains("0xabc"));
    }

    #[test]
    fn connectivity_error_detector_distinguishes_transport_failures() {
        assert!(looks_like_connectivity_error(
            "registry discovery failed: error sending request for url (http://127.0.0.1:18545/)"
        ));
        assert!(looks_like_connectivity_error(
            "request failed: connection refused"
        ));
        assert!(!looks_like_connectivity_error(
            "KMS HTTP 400: invalid key payload"
        ));
    }

    #[test]
    fn build_registry_discovery_none_when_registry_fields_absent() {
        let config = KmsIntegration {
            enabled: true,
            use_app_wallet: false,
            kms_app_id: None,
            nova_app_registry: None,
        };
        let discovery = NovaKmsProxy::build_registry_discovery(&config).unwrap();
        assert!(discovery.is_none());
    }

    #[test]
    fn build_registry_discovery_uses_internal_rpc_and_ttl() {
        let config = KmsIntegration {
            enabled: true,
            use_app_wallet: false,
            kms_app_id: Some(49),
            nova_app_registry: Some("0x0f68e6e699f2e972998a1ecc000c7ce103e64cc8".to_string()),
        };
        let discovery = NovaKmsProxy::build_registry_discovery(&config)
            .unwrap()
            .expect("discovery config");
        assert_eq!(discovery.rpc_url, DEFAULT_REGISTRY_CHAIN_RPC);
        assert_eq!(discovery.ttl_ms, DEFAULT_KMS_DISCOVERY_TTL_MS);
    }

    #[test]
    fn new_builds_without_static_nodes() {
        let config = KmsIntegration {
            enabled: true,
            use_app_wallet: false,
            kms_app_id: Some(49),
            nova_app_registry: Some("0x0f68e6e699f2e972998a1ecc000c7ce103e64cc8".to_string()),
        };
        let proxy = NovaKmsProxy::new(&config, "http://127.0.0.1:18000".to_string())
            .expect("proxy should build");
        assert!(proxy.registry_discovery.is_some());
    }

    fn test_node(
        wallet: &str,
        base_url: &str,
        reachable: Option<bool>,
        expires_at_ms: u64,
        last_checked_ms: u64,
        last_http_status: Option<u16>,
        last_error: Option<&str>,
    ) -> KmsNodeCacheEntry {
        KmsNodeCacheEntry {
            wallet: wallet.to_string(),
            base_url: base_url.to_string(),
            reachable,
            expires_at_ms,
            last_checked_ms,
            last_http_status,
            last_error: last_error.map(ToString::to_string),
        }
    }

    #[test]
    fn merge_discovered_nodes_with_previous_copies_fresh_status() {
        let now_ms = 1_000;
        let discovered = vec![test_node(
            "0xaaaa000000000000000000000000000000000001",
            "https://kms-1.example.com",
            None,
            0,
            0,
            None,
            None,
        )];
        let previous = DiscoveryCacheEntry {
            nodes: vec![test_node(
                "0xaaaa000000000000000000000000000000000001",
                "https://kms-1.example.com",
                Some(true),
                1_500,
                900,
                Some(200),
                None,
            )],
            expires_at_ms: 2_000,
        };

        let merged = merge_discovered_nodes_with_previous(discovered, Some(&previous), now_ms);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].reachable, Some(true));
        assert_eq!(merged[0].expires_at_ms, 1_500);
        assert_eq!(merged[0].last_checked_ms, 900);
        assert_eq!(merged[0].last_http_status, Some(200));
    }

    #[test]
    fn merge_discovered_nodes_with_previous_ignores_expired_status() {
        let now_ms = 1_000;
        let discovered = vec![test_node(
            "0xbbbb000000000000000000000000000000000002",
            "https://kms-2.example.com",
            None,
            0,
            0,
            None,
            None,
        )];
        let previous = DiscoveryCacheEntry {
            nodes: vec![test_node(
                "0xbbbb000000000000000000000000000000000002",
                "https://kms-2.example.com",
                Some(false),
                999,
                800,
                None,
                Some("timeout"),
            )],
            expires_at_ms: 2_000,
        };

        let merged = merge_discovered_nodes_with_previous(discovered, Some(&previous), now_ms);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].reachable, None);
        assert_eq!(merged[0].last_checked_ms, 0);
        assert_eq!(merged[0].last_http_status, None);
        assert_eq!(merged[0].last_error, None);
    }

    #[test]
    fn merge_refresh_with_live_cache_prefers_newer_live_status() {
        let now_ms = 1_000;
        let refreshed = vec![test_node(
            "0xcccc000000000000000000000000000000000003",
            "https://kms-3.example.com",
            Some(false),
            1_200,
            900,
            None,
            Some("connectivity error"),
        )];
        let live_cache = DiscoveryCacheEntry {
            nodes: vec![test_node(
                "0xcccc000000000000000000000000000000000003",
                "https://kms-3.example.com",
                Some(true),
                1_800,
                950,
                Some(200),
                None,
            )],
            expires_at_ms: 2_000,
        };

        let merged = merge_refresh_with_live_cache(refreshed, Some(&live_cache), now_ms);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].reachable, Some(true));
        assert_eq!(merged[0].expires_at_ms, 1_800);
        assert_eq!(merged[0].last_checked_ms, 950);
        assert_eq!(merged[0].last_http_status, Some(200));
        assert_eq!(merged[0].last_error, None);
    }

    #[test]
    fn merge_refresh_with_live_cache_keeps_refreshed_when_live_is_stale_or_expired() {
        let now_ms = 1_000;
        let refreshed = vec![test_node(
            "0xdddd000000000000000000000000000000000004",
            "https://kms-4.example.com",
            Some(false),
            1_700,
            980,
            None,
            Some("dial tcp"),
        )];

        let live_older = DiscoveryCacheEntry {
            nodes: vec![test_node(
                "0xdddd000000000000000000000000000000000004",
                "https://kms-4.example.com",
                Some(true),
                1_800,
                970,
                Some(200),
                None,
            )],
            expires_at_ms: 2_000,
        };
        let merged_with_older =
            merge_refresh_with_live_cache(refreshed.clone(), Some(&live_older), now_ms);
        assert_eq!(merged_with_older[0].reachable, Some(false));
        assert_eq!(merged_with_older[0].last_checked_ms, 980);
        assert_eq!(merged_with_older[0].last_error.as_deref(), Some("dial tcp"));

        let live_expired = DiscoveryCacheEntry {
            nodes: vec![test_node(
                "0xdddd000000000000000000000000000000000004",
                "https://kms-4.example.com",
                Some(true),
                999,
                1_200,
                Some(200),
                None,
            )],
            expires_at_ms: 2_000,
        };
        let merged_with_expired =
            merge_refresh_with_live_cache(refreshed, Some(&live_expired), now_ms);
        assert_eq!(merged_with_expired[0].reachable, Some(false));
        assert_eq!(merged_with_expired[0].last_checked_ms, 980);
        assert_eq!(
            merged_with_expired[0].last_error.as_deref(),
            Some("dial tcp")
        );
    }

    #[test]
    fn format_node_refresh_list_renders_reachability_states() {
        let now_ms = 1_000;
        let nodes = vec![
            test_node(
                "0xeeee000000000000000000000000000000000005",
                "https://kms-5.example.com",
                Some(true),
                1_100,
                950,
                Some(200),
                None,
            ),
            test_node(
                "0xffff000000000000000000000000000000000006",
                "https://kms-6.example.com",
                Some(false),
                1_100,
                940,
                None,
                Some("timeout"),
            ),
            test_node(
                "0x1111000000000000000000000000000000000007",
                "https://kms-7.example.com",
                Some(true),
                999,
                930,
                Some(200),
                None,
            ),
        ];

        let formatted = format_node_refresh_list(&nodes, now_ms);
        assert!(formatted.contains("wallet=0xeeee000000000000000000000000000000000005,url=https://kms-5.example.com,reachability=reachable"));
        assert!(formatted.contains("wallet=0xffff000000000000000000000000000000000006,url=https://kms-6.example.com,reachability=unreachable"));
        assert!(formatted.contains("wallet=0x1111000000000000000000000000000000000007,url=https://kms-7.example.com,reachability=unknown"));
    }
}
