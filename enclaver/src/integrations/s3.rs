use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Result, anyhow, bail};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use base64::{Engine as _, engine::general_purpose};
use http_body_util::Full;
use hyper::Response;
use hyper::body::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::http_util;
use crate::manifest::{S3EncryptionAadMode, S3EncryptionConfig, S3EncryptionMode};

use super::nova_kms::NovaKmsProxy;

const META_ENC_SCHEME: &str = "odyn-enc";
const META_NONCE: &str = "odyn-nonce";
const META_KEY_VERSION: &str = "odyn-key-version";
const META_AAD_MODE: &str = "odyn-aad-mode";
const META_CONTENT_TYPE: &str = "odyn-content-type";
const ENC_SCHEME_KMS_V1: &str = "kms-v1";

pub struct S3Proxy {
    client: S3Client,
    bucket: String,
    prefix: String,
    encryption: Option<S3EncryptionConfig>,
    nova_kms: RwLock<Option<Arc<NovaKmsProxy>>>,
}

impl S3Proxy {
    pub fn new(
        client: S3Client,
        bucket: String,
        mut prefix: String,
        encryption: Option<S3EncryptionConfig>,
    ) -> Self {
        // Ensure prefix ends with a slash to prevent collision (e.g. app1/ vs app10/)
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        Self {
            client,
            bucket,
            prefix,
            encryption,
            nova_kms: RwLock::new(None),
        }
    }

    pub async fn attach_nova_kms(&self, nova_kms: Arc<NovaKmsProxy>) {
        let mut guard = self.nova_kms.write().await;
        *guard = Some(nova_kms);
    }

    pub fn client(&self) -> &S3Client {
        &self.client
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Build full S3 key with app-specific prefix for isolation.
    /// Returns an error if the key attempts path traversal (e.g. contains "..").
    pub fn build_key(&self, key: &str) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(anyhow!(
                "Invalid key: path traversal or absolute path not allowed"
            ));
        }
        Ok(format!("{}{}", self.prefix, key))
    }

    pub async fn handle_get(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3GetRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key)?;

        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await;

        match result {
            Ok(output) => {
                let content_type = output.content_type().map(ToString::to_string);
                let metadata = output.metadata().cloned().unwrap_or_default();
                let ciphertext = output.body.collect().await?.into_bytes().to_vec();
                let plaintext = self
                    .decrypt_if_needed(&req.key, ciphertext, &metadata)
                    .await?;
                let response = S3GetResponse {
                    value: general_purpose::STANDARD.encode(&plaintext),
                    content_type: content_type.or_else(|| metadata.get(META_CONTENT_TYPE).cloned()),
                };
                Ok(http_util::ok_json(&response)?)
            }
            Err(err) => {
                if let Some(s3_err) = err.as_service_error()
                    && s3_err.is_no_such_key()
                {
                    return Ok(http_util::not_found());
                }
                Ok(http_util::bad_request(format!("S3 error: {}", err)))
            }
        }
    }

    pub async fn handle_put(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3PutRequest = serde_json::from_slice(&body)?;
        let value = general_purpose::STANDARD
            .decode(&req.value)
            .map_err(|e| anyhow!("Invalid base64 value: {}", e))?;
        match self
            .put_object_internal(&req.key, value, req.content_type.clone())
            .await
        {
            Ok(_) => Ok(http_util::ok_json(&S3PutResponse { success: true })?),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn put_raw(
        &self,
        key: &str,
        value: Vec<u8>,
        content_type: Option<String>,
    ) -> Result<()> {
        self.put_object_internal(key, value, content_type).await
    }

    pub async fn handle_delete(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3DeleteRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key)?;

        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
        {
            Ok(_) => Ok(http_util::ok_json(&serde_json::json!({ "success": true }))?),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn handle_list(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3ListRequest = serde_json::from_slice(&body)?;
        let user_prefix = req.prefix.as_deref().unwrap_or("");
        let full_prefix = self.build_key(user_prefix)?;

        let mut list_request = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix);

        if let Some(token) = req.continuation_token {
            list_request = list_request.continuation_token(token);
        }

        if let Some(max_keys) = req.max_keys {
            list_request = list_request.max_keys(max_keys as i32);
        }

        match list_request.send().await {
            Ok(output) => {
                let keys: Vec<String> = output
                    .contents()
                    .iter()
                    .filter_map(|obj| {
                        obj.key()
                            .and_then(|k| k.strip_prefix(&self.prefix).map(|s| s.to_string()))
                    })
                    .collect();

                Ok(http_util::ok_json(&S3ListResponse {
                    keys,
                    continuation_token: output.next_continuation_token().map(|s| s.to_string()),
                    is_truncated: output.is_truncated().unwrap_or(false),
                })?)
            }
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    fn kms_encryption_enabled(&self) -> bool {
        matches!(
            self.encryption.as_ref().map(|e| &e.mode),
            Some(S3EncryptionMode::Kms)
        )
    }

    fn accept_plaintext(&self) -> bool {
        self.encryption
            .as_ref()
            .map(|e| e.accept_plaintext)
            .unwrap_or(true)
    }

    async fn current_nova_kms(&self) -> Result<Arc<NovaKmsProxy>> {
        let guard = self.nova_kms.read().await;
        guard.as_ref().cloned().ok_or_else(|| {
            anyhow!("S3 KMS encryption is enabled, but KMS integration is not configured")
        })
    }

    fn key_version(&self) -> String {
        self.encryption
            .as_ref()
            .map(|cfg| cfg.key_version.clone())
            .unwrap_or_else(|| "v1".to_string())
    }

    fn aad_mode(&self) -> S3EncryptionAadMode {
        self.encryption
            .as_ref()
            .map(|cfg| cfg.aad_mode.clone())
            .unwrap_or(S3EncryptionAadMode::Key)
    }

    fn aad_mode_label(mode: &S3EncryptionAadMode) -> &'static str {
        match mode {
            S3EncryptionAadMode::None => "none",
            S3EncryptionAadMode::Key => "key",
            S3EncryptionAadMode::KeyAndVersion => "key+version",
        }
    }

    fn build_aad(key: &str, key_version: &str, mode: &S3EncryptionAadMode) -> Vec<u8> {
        match mode {
            S3EncryptionAadMode::None => Vec::new(),
            S3EncryptionAadMode::Key => key.as_bytes().to_vec(),
            S3EncryptionAadMode::KeyAndVersion => format!("{key_version}:{key}").into_bytes(),
        }
    }

    fn dek_path(key: &str, key_version: &str) -> String {
        format!("s3/{key_version}/{key}")
    }

    async fn encrypt_for_s3(
        &self,
        key: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, String, String, String)> {
        let key_version = self.key_version();
        let aad_mode = self.aad_mode();
        let aad = Self::build_aad(key, &key_version, &aad_mode);
        let nova_kms = self.current_nova_kms().await?;
        let dek = nova_kms
            .derive_key(&Self::dek_path(key, &key_version), "", 32)
            .await?;
        if dek.len() != 32 {
            bail!("KMS returned invalid DEK length {}, expected 32", dek.len());
        }

        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| anyhow!("Failed to build AES-256-GCM cipher: {}", e))?;

        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("S3 encrypt failed: {}", e))?;

        Ok((
            ciphertext,
            hex::encode(nonce),
            key_version,
            Self::aad_mode_label(&aad_mode).to_string(),
        ))
    }

    async fn decrypt_if_needed(
        &self,
        key: &str,
        ciphertext_or_plaintext: Vec<u8>,
        metadata: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let scheme = metadata.get(META_ENC_SCHEME).cloned().unwrap_or_default();
        if scheme != ENC_SCHEME_KMS_V1 {
            if self.kms_encryption_enabled() && !self.accept_plaintext() {
                bail!("plaintext object is not accepted when kms encryption is enforced");
            }
            return Ok(ciphertext_or_plaintext);
        }

        let nonce_hex = metadata
            .get(META_NONCE)
            .ok_or_else(|| anyhow!("encrypted object metadata missing nonce"))?;
        let nonce = hex::decode(nonce_hex)
            .map_err(|e| anyhow!("invalid nonce metadata '{}': {}", nonce_hex, e))?;
        if nonce.len() != 12 {
            bail!("invalid nonce size {}, expected 12", nonce.len());
        }

        let key_version = metadata
            .get(META_KEY_VERSION)
            .cloned()
            .unwrap_or_else(|| self.key_version());
        let aad_mode = match metadata.get(META_AAD_MODE).map(|v| v.as_str()) {
            Some("none") => S3EncryptionAadMode::None,
            Some("key") => S3EncryptionAadMode::Key,
            Some("key+version") => S3EncryptionAadMode::KeyAndVersion,
            _ => self.aad_mode(),
        };
        let aad = Self::build_aad(key, &key_version, &aad_mode);

        let nova_kms = self.current_nova_kms().await?;
        let dek = nova_kms
            .derive_key(&Self::dek_path(key, &key_version), "", 32)
            .await?;
        if dek.len() != 32 {
            bail!("KMS returned invalid DEK length {}, expected 32", dek.len());
        }

        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| anyhow!("Failed to build AES-256-GCM cipher: {}", e))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: &ciphertext_or_plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("S3 decrypt failed: {}", e))?;
        Ok(plaintext)
    }

    async fn put_object_internal(
        &self,
        key: &str,
        mut data: Vec<u8>,
        content_type: Option<String>,
    ) -> Result<()> {
        let full_key = self.build_key(key)?;
        let mut metadata_pairs: Vec<(String, String)> = Vec::new();

        if self.kms_encryption_enabled() {
            let (ciphertext, nonce_hex, key_version, aad_mode) =
                self.encrypt_for_s3(key, &data).await?;
            data = ciphertext;
            metadata_pairs.push((META_ENC_SCHEME.to_string(), ENC_SCHEME_KMS_V1.to_string()));
            metadata_pairs.push((META_NONCE.to_string(), nonce_hex));
            metadata_pairs.push((META_KEY_VERSION.to_string(), key_version));
            metadata_pairs.push((META_AAD_MODE.to_string(), aad_mode));
            if let Some(ct) = content_type.as_ref() {
                metadata_pairs.push((META_CONTENT_TYPE.to_string(), ct.clone()));
            }
        }

        let mut put_request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .body(ByteStream::from(data));

        if let Some(ct) = content_type.as_ref() {
            put_request = put_request.content_type(ct);
        }

        for (k, v) in metadata_pairs {
            put_request = put_request.metadata(k, v);
        }

        put_request.send().await.map(|_| ()).map_err(|e| anyhow!(e))
    }
}

#[derive(Deserialize)]
struct S3GetRequest {
    key: String,
}

#[derive(Serialize)]
struct S3GetResponse {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

#[derive(Deserialize)]
struct S3PutRequest {
    key: String,
    value: String,
    content_type: Option<String>,
}

#[derive(Serialize)]
struct S3PutResponse {
    success: bool,
}

#[derive(Deserialize)]
struct S3DeleteRequest {
    key: String,
}

#[derive(Deserialize)]
struct S3ListRequest {
    prefix: Option<String>,
    continuation_token: Option<String>,
    max_keys: Option<usize>,
}

#[derive(Serialize)]
struct S3ListResponse {
    keys: Vec<String>,
    continuation_token: Option<String>,
    is_truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::config::{BehaviorVersion, Config};
    use std::collections::HashMap;

    fn mock_proxy_with_encryption(prefix: &str, encryption: Option<S3EncryptionConfig>) -> S3Proxy {
        let config = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .build();
        let client = S3Client::from_conf(config);
        S3Proxy::new(
            client,
            "test-bucket".to_string(),
            prefix.to_string(),
            encryption,
        )
    }

    fn mock_proxy(prefix: &str) -> S3Proxy {
        mock_proxy_with_encryption(prefix, None)
    }

    #[test]
    fn test_build_key() {
        let proxy = mock_proxy("apps/my-app/");
        assert_eq!(
            proxy.build_key("config.json").unwrap(),
            "apps/my-app/config.json"
        );
        assert_eq!(
            proxy.build_key("data/file.txt").unwrap(),
            "apps/my-app/data/file.txt"
        );
    }

    #[test]
    fn test_prefix_slash_enforcement() {
        // Should automatically add trailing slash
        let proxy = mock_proxy("apps/my-app");
        assert_eq!(proxy.prefix(), "apps/my-app/");
        assert_eq!(proxy.build_key("test").unwrap(), "apps/my-app/test");

        // Should handle empty prefix
        let proxy = mock_proxy("");
        assert_eq!(proxy.prefix(), "");
        assert_eq!(proxy.build_key("test").unwrap(), "test");
    }

    #[test]
    fn test_path_traversal_protection() {
        let proxy = mock_proxy("apps/my-app/");

        // These should fail
        assert!(proxy.build_key("../secret").is_err());
        assert!(proxy.build_key("data/../../secret").is_err());
        assert!(proxy.build_key("/absolute/path").is_err());

        // These should succeed
        assert!(proxy.build_key("normal.txt").is_ok());
        assert!(proxy.build_key("dir/file").is_ok());
    }

    #[test]
    fn test_aad_generation() {
        assert_eq!(
            S3Proxy::build_aad("cfg", "v1", &S3EncryptionAadMode::None),
            Vec::<u8>::new()
        );
        assert_eq!(
            S3Proxy::build_aad("cfg", "v1", &S3EncryptionAadMode::Key),
            b"cfg".to_vec()
        );
        assert_eq!(
            S3Proxy::build_aad("cfg", "v1", &S3EncryptionAadMode::KeyAndVersion),
            b"v1:cfg".to_vec()
        );
    }

    #[tokio::test]
    async fn test_decrypt_if_needed_passthrough_plaintext_when_unencrypted() {
        let proxy = mock_proxy("apps/my-app/");
        let payload = b"hello".to_vec();
        let metadata = HashMap::new();
        let out = proxy
            .decrypt_if_needed("config.json", payload.clone(), &metadata)
            .await
            .unwrap();
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn test_decrypt_if_needed_rejects_plaintext_when_kms_enforced() {
        let proxy = mock_proxy_with_encryption(
            "apps/my-app/",
            Some(S3EncryptionConfig {
                mode: S3EncryptionMode::Kms,
                key_scope: crate::manifest::S3EncryptionKeyScope::Object,
                aad_mode: S3EncryptionAadMode::Key,
                key_version: "v1".to_string(),
                accept_plaintext: false,
            }),
        );
        let metadata = HashMap::new();
        let err = proxy
            .decrypt_if_needed("config.json", b"plaintext".to_vec(), &metadata)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("plaintext object is not accepted when kms encryption is enforced")
        );
    }

    #[tokio::test]
    async fn test_decrypt_if_needed_rejects_missing_nonce_metadata() {
        let proxy = mock_proxy("apps/my-app/");
        let mut metadata = HashMap::new();
        metadata.insert(META_ENC_SCHEME.to_string(), ENC_SCHEME_KMS_V1.to_string());

        let err = proxy
            .decrypt_if_needed("config.json", vec![1, 2, 3], &metadata)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("encrypted object metadata missing nonce")
        );
    }

    #[tokio::test]
    async fn test_decrypt_if_needed_rejects_invalid_nonce_size() {
        let proxy = mock_proxy("apps/my-app/");
        let mut metadata = HashMap::new();
        metadata.insert(META_ENC_SCHEME.to_string(), ENC_SCHEME_KMS_V1.to_string());
        metadata.insert(META_NONCE.to_string(), "001122".to_string());

        let err = proxy
            .decrypt_if_needed("config.json", vec![1, 2, 3], &metadata)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid nonce size"));
    }
}
