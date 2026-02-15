use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::pin::Pin;
use tokio::fs::File;
use tokio::io::AsyncRead;

use tokio::io::AsyncReadExt;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub name: String,
    pub target: String,
    pub sources: Sources,
    pub signature: Option<Signature>,
    pub ingress: Option<Vec<Ingress>>,
    pub egress: Option<Egress>,
    pub defaults: Option<Defaults>,
    pub kms_proxy: Option<KmsProxy>,
    pub api: Option<Api>,
    pub aux_api: Option<AuxApi>,
    pub vsock_ports: Option<VsockPorts>,
    pub storage: Option<Storage>,
    pub kms_integration: Option<KmsIntegration>,
    pub chain_access: Option<ChainAccess>,
    pub helios_rpc: Option<HeliosRpc>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub app: String,
    pub odyn: Option<String>,
    pub sleeve: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ingress {
    pub listen_port: u16,
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub key_file: String,
    pub cert_file: String,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub proxy_port: Option<u16>,
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub cpu_count: Option<i32>,
    pub memory_mb: Option<i32>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsProxy {
    pub listen_port: u16,
    pub endpoints: Option<HashMap<String, String>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub listen_port: u16,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxApi {
    pub listen_port: Option<u16>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VsockPorts {
    pub status_port: Option<u32>,
    pub app_log_port: Option<u32>,
    pub http_egress_port: Option<u32>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub s3: Option<S3StorageConfig>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    #[serde(default)]
    pub enabled: bool,
    /// S3 bucket name
    pub bucket: String,
    /// S3 key prefix for isolation (e.g., "apps/my-app/"). 
    /// Odyn will automatically ensure this ends with a trailing slash.
    pub prefix: String,
    /// AWS region (optional, defaults to us-east-1 or IMDS-provided region)
    pub region: Option<String>,
    /// Optional transparent encryption for values stored in S3.
    pub encryption: Option<S3EncryptionConfig>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum S3EncryptionMode {
    Plaintext,
    Kms,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum S3EncryptionKeyScope {
    App,
    Object,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum S3EncryptionAadMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "key")]
    Key,
    #[serde(rename = "key+version")]
    KeyAndVersion,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3EncryptionConfig {
    #[serde(default = "default_s3_encryption_mode")]
    pub mode: S3EncryptionMode,
    #[serde(default = "default_s3_key_scope")]
    pub key_scope: S3EncryptionKeyScope,
    #[serde(default = "default_s3_aad_mode")]
    pub aad_mode: S3EncryptionAadMode,
    #[serde(default = "default_s3_key_version")]
    pub key_version: String,
    #[serde(default = "default_s3_accept_plaintext")]
    pub accept_plaintext: bool,
}

fn default_s3_encryption_mode() -> S3EncryptionMode {
    S3EncryptionMode::Plaintext
}

fn default_s3_key_scope() -> S3EncryptionKeyScope {
    S3EncryptionKeyScope::Object
}

fn default_s3_aad_mode() -> S3EncryptionAadMode {
    S3EncryptionAadMode::Key
}

fn default_s3_key_version() -> String {
    "v1".to_string()
}

fn default_s3_accept_plaintext() -> bool {
    true
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsIntegration {
    #[serde(default)]
    pub enabled: bool,
    pub kms_app_id: Option<u64>,
    pub nova_app_registry: Option<String>,
    pub registry_chain_rpc: Option<String>,
    pub base_urls: Option<Vec<String>>,
    #[serde(default = "default_kms_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_kms_max_retries")]
    pub max_retries: u8,
    #[serde(default = "default_kms_discovery_ttl_ms")]
    pub discovery_ttl_ms: u64,
    #[serde(default = "default_kms_require_mutual_signature")]
    pub require_mutual_signature: bool,
    pub audit_log_path: Option<String>,
    pub reserved_derive_prefixes: Option<Vec<String>>,
}

fn default_kms_timeout_ms() -> u64 {
    3000
}

fn default_kms_max_retries() -> u8 {
    2
}

fn default_kms_discovery_ttl_ms() -> u64 {
    15000
}

fn default_kms_require_mutual_signature() -> bool {
    true
}

impl KmsIntegration {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.kms_app_id.unwrap_or(0) == 0 {
            bail!("kms_integration.kms_app_id is required when enabled");
        }
        let registry = self
            .nova_app_registry
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("kms_integration.nova_app_registry is required when enabled"))?;
        if !(registry.starts_with("0x") || registry.starts_with("0X")) || registry.len() != 42 {
            bail!("kms_integration.nova_app_registry must be a 20-byte hex address");
        }
        let registry_chain_rpc = self
            .registry_chain_rpc
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("kms_integration.registry_chain_rpc is required when enabled"))?;
        if !(registry_chain_rpc.starts_with("http://")
            || registry_chain_rpc.starts_with("https://"))
        {
            bail!("kms_integration.registry_chain_rpc must use http:// or https://");
        }

        let base_urls = self
            .base_urls
            .as_ref()
            .ok_or_else(|| anyhow!("kms_integration.base_urls is required when enabled"))?;
        if base_urls.is_empty() {
            bail!("kms_integration.base_urls cannot be empty when enabled");
        }

        for url in base_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                bail!("kms_integration.base_urls contains an empty URL");
            }
            if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
                bail!("kms_integration.base_urls must use http:// or https://: {}", trimmed);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAccess {
    pub registry_chain: Option<HeliosRpcProvider>,
    pub app_rpc_providers: Option<HashMap<String, HeliosRpcProvider>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeliosRpcProvider {
    pub kind: HeliosRpcKind,
    pub network: String,
    pub execution_rpc: String,
    pub consensus_rpc: Option<String>,
    pub checkpoint: Option<String>,
    pub local_rpc_port: u16,
}

impl HeliosRpcProvider {
    fn validate(&self, context: &str) -> Result<()> {
        let network = self.network.trim().to_lowercase();
        if network.is_empty() {
            bail!("{context}.network is required");
        }

        let execution_rpc = self.execution_rpc.trim();
        if execution_rpc.is_empty() {
            bail!("{context}.execution_rpc is required");
        }

        match self.kind {
            HeliosRpcKind::Ethereum => {
                if !matches!(network.as_str(), "mainnet" | "sepolia" | "holesky") {
                    bail!(
                        "{context}.network '{}' is invalid for kind=ethereum. \
                         Supported: mainnet, sepolia, holesky",
                        network
                    );
                }
            }
            HeliosRpcKind::Opstack => {
                if !matches!(
                    network.as_str(),
                    "op-mainnet" | "base" | "base-sepolia" | "worldchain" | "zora" | "unichain"
                ) {
                    bail!(
                        "{context}.network '{}' is invalid for kind=opstack. \
                         Supported: op-mainnet, base, base-sepolia, worldchain, zora, unichain",
                        network
                    );
                }
            }
        }

        Ok(())
    }
}

impl ChainAccess {
    fn validate(&self) -> Result<()> {
        let mut used_ports = std::collections::HashSet::new();

        if let Some(registry_chain) = &self.registry_chain {
            registry_chain.validate("chain_access.registry_chain")?;
            if !used_ports.insert(registry_chain.local_rpc_port) {
                bail!("duplicate local_rpc_port in chain_access: {}", registry_chain.local_rpc_port);
            }
        }

        if let Some(app_rpc_providers) = &self.app_rpc_providers {
            for (chain_id, provider) in app_rpc_providers {
                provider.validate(&format!("chain_access.app_rpc_providers.{chain_id}"))?;
                if !used_ports.insert(provider.local_rpc_port) {
                    bail!("duplicate local_rpc_port in chain_access: {}", provider.local_rpc_port);
                }
            }
        }

        Ok(())
    }
}

/// Helios client kind: ethereum or opstack
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeliosRpcKind {
    /// Ethereum L1 light client (mainnet, sepolia, holesky)
    Ethereum,
    /// OP Stack L2 light client (op-mainnet, base, etc.)
    Opstack,
}

/// Configuration for Helios Ethereum light client RPC
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeliosRpc {
    /// Enable/disable Helios RPC service
    #[serde(default)]
    pub enabled: bool,
    /// Client kind: "ethereum" or "opstack" (required)
    pub kind: HeliosRpcKind,
    /// Port for JSON-RPC server (default: 8545)
    #[serde(default = "default_helios_port")]
    pub listen_port: u16,
    /// Network name (required when enabled):
    /// - ethereum: "mainnet", "sepolia", "holesky"
    /// - opstack: "op-mainnet", "base", "base-sepolia", "worldchain", "zora", "unichain"
    pub network: Option<String>,
    /// Untrusted execution RPC URL (required when enabled)
    pub execution_rpc: Option<String>,
    /// Consensus RPC URL (optional):
    /// - ethereum: defaults to lightclientdata.org
    /// - opstack: defaults per-network (operationsolarstorm.org)
    pub consensus_rpc: Option<String>,
    /// Weak subjectivity checkpoint (optional, auto-fetched if not provided; ethereum only)
    pub checkpoint: Option<String>,
}

fn default_helios_port() -> u16 {
    8545
}

impl HeliosRpc {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let network = self
            .network
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty());

        if network.is_none() {
            bail!("helios_rpc.network is required when helios_rpc.enabled is true");
        }

        if self
            .execution_rpc
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .is_none()
        {
            bail!("helios_rpc.execution_rpc is required when helios_rpc.enabled is true");
        }

        // Validate network name per kind
        let net = network.unwrap().to_lowercase();
        match self.kind {
            HeliosRpcKind::Ethereum => {
                if !matches!(net.as_str(), "mainnet" | "sepolia" | "holesky") {
                    bail!(
                        "helios_rpc.network '{}' is invalid for kind=ethereum. \
                         Supported: mainnet, sepolia, holesky",
                        net
                    );
                }
            }
            HeliosRpcKind::Opstack => {
                if !matches!(
                    net.as_str(),
                    "op-mainnet" | "base" | "base-sepolia" | "worldchain" | "zora" | "unichain"
                ) {
                    bail!(
                        "helios_rpc.network '{}' is invalid for kind=opstack. \
                         Supported: op-mainnet, base, base-sepolia, worldchain, zora, unichain",
                        net
                    );
                }
            }
        }

        Ok(())
    }
}

fn parse_manifest(buf: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_yaml::from_slice(buf)?;

    if let Some(kms_integration) = manifest.kms_integration.as_ref() {
        kms_integration.validate()?;
    }

    if let Some(chain_access) = manifest.chain_access.as_ref() {
        chain_access.validate()?;
    }

    if let Some(helios) = manifest.helios_rpc.as_ref() {
        helios.validate()?;
    }

    Ok(manifest)
}

pub async fn load_manifest_raw<P: AsRef<Path>>(path: P) -> Result<(Vec<u8>, Manifest)> {
    let mut file: Pin<Box<dyn AsyncRead>> = if path.as_ref() == Path::new("-") {
        Box::pin(tokio::io::stdin())
    } else {
        match File::open(&path).await {
            Ok(file) => Box::pin(file),
            Err(err) => anyhow::bail!("failed to open {}: {err}", path.as_ref().display()),
        }
    };

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;

    let manifest = parse_manifest(&buf)
        .map_err(|e| anyhow!("invalid configuration in {}: {e}", path.as_ref().display()))?;

    Ok((buf, manifest))
}

pub async fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest> {
    let (_, manifest) = load_manifest_raw(path).await?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use crate::manifest::parse_manifest;

    #[test]
    fn test_parse_manifest_with_unknown_fields() {
        assert!(parse_manifest(br#"foo: "bar""#).is_err());
    }

    #[test]
    fn test_parse_minimal_manifest() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.version, "v1");
        assert_eq!(manifest.name, "test");
        assert_eq!(manifest.target, "target-image:latest");
        assert_eq!(manifest.sources.app, "app-image:latest");
    }

    #[test]
    fn test_parse_helios_rpc_full_config() {
        let raw_manifest = br#"
version: v1
name: "test-helios"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: ethereum
  listen_port: 8545
  network: mainnet
  execution_rpc: "https://eth-mainnet.g.alchemy.com/v2/KEY"
  consensus_rpc: "https://www.lightclientdata.org"
  checkpoint: "0x1234567890abcdef"
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        assert_eq!(helios.listen_port, 8545);
        assert_eq!(helios.network.as_deref(), Some("mainnet"));
        assert_eq!(
            helios.execution_rpc.as_deref(),
            Some("https://eth-mainnet.g.alchemy.com/v2/KEY")
        );
        assert_eq!(helios.consensus_rpc, Some("https://www.lightclientdata.org".to_string()));
        assert_eq!(helios.checkpoint, Some("0x1234567890abcdef".to_string()));
    }

    #[test]
    fn test_parse_helios_rpc_minimal_config() {
        let raw_manifest = br#"
version: v1
name: "test-helios-minimal"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc: { enabled: true, kind: ethereum, network: sepolia, execution_rpc: "https://eth-sepolia.g.alchemy.com/v2/KEY" }
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        assert_eq!(helios.listen_port, 8545); // default port
        assert_eq!(helios.network.as_deref(), Some("sepolia"));
        assert_eq!(
            helios.execution_rpc.as_deref(),
            Some("https://eth-sepolia.g.alchemy.com/v2/KEY")
        );
        assert!(helios.consensus_rpc.is_none());
        assert!(helios.checkpoint.is_none());
    }

    #[test]
    fn test_parse_helios_rpc_disabled() {
        let raw_manifest = br#"
version: v1
name: "test-helios-disabled"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc: { enabled: false, kind: ethereum }
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(!helios.enabled);
        assert!(helios.network.is_none());
        assert!(helios.execution_rpc.is_none());
    }

    #[test]
    fn test_parse_helios_rpc_enabled_missing_required_fields() {
        let raw_manifest = br#"
version: v1
name: "test-helios-invalid"
target: "target-image:latest"
sources:
    app: "app-image:latest"
helios_rpc:
    enabled: true
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_manifest_without_helios_rpc() {
        let raw_manifest = br#"
version: v1
name: "test-no-helios"
target: "target-image:latest"
sources:
  app: "app-image:latest"
api:
  listen_port: 9000
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        assert!(manifest.helios_rpc.is_none());
    }

    #[test]
    fn test_parse_helios_rpc_opstack_valid_network() {
        let raw_manifest = br#"
version: v1
name: "test-helios-opstack"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: opstack
  network: op-mainnet
  execution_rpc: "https://example.invalid"
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        assert_eq!(helios.network.as_deref(), Some("op-mainnet"));
    }

    #[test]
    fn test_parse_helios_rpc_opstack_rejects_unknown_network() {
        let raw_manifest = br#"
version: v1
name: "test-helios-opstack-invalid"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: opstack
  network: optimism
  execution_rpc: "https://example.invalid"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_helios_rpc_rejects_cross_kind_networks() {
        // ethereum kind with opstack network
        let raw_manifest = br#"
version: v1
name: "test-helios-cross-kind-1"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: ethereum
  network: op-mainnet
  execution_rpc: "https://example.invalid"
"#;
        assert!(parse_manifest(raw_manifest).is_err());

        // opstack kind with ethereum network
        let raw_manifest = br#"
version: v1
name: "test-helios-cross-kind-2"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: opstack
  network: mainnet
  execution_rpc: "https://example.invalid"
"#;
        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_requires_base_urls() {
        let raw_manifest = br#"
version: v1
name: "test-kms"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_with_base_urls() {
        let raw_manifest = br#"
version: v1
name: "test-kms-ok"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
  registry_chain_rpc: "https://sepolia.base.org"
  base_urls:
    - "https://kms-1.example.com"
    - "https://kms-2.example.com"
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let kms = manifest
            .kms_integration
            .expect("kms_integration should be present");
        assert!(kms.enabled);
        assert_eq!(kms.base_urls.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_chain_access_duplicate_ports_rejected() {
        let raw_manifest = br#"
version: v1
name: "test-chain-access"
target: "target-image:latest"
sources:
  app: "app-image:latest"
chain_access:
  registry_chain:
    kind: opstack
    network: base-sepolia
    execution_rpc: "https://sepolia.base.org"
    local_rpc_port: 18545
  app_rpc_providers:
    "8453":
      kind: opstack
      network: base
      execution_rpc: "https://mainnet.base.org"
      local_rpc_port: 18545
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_chain_access_valid() {
        let raw_manifest = br#"
version: v1
name: "test-chain-access-ok"
target: "target-image:latest"
sources:
  app: "app-image:latest"
chain_access:
  registry_chain:
    kind: opstack
    network: base-sepolia
    execution_rpc: "https://sepolia.base.org"
    local_rpc_port: 18545
  app_rpc_providers:
    "1":
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18546
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let chain_access = manifest.chain_access.expect("chain_access should exist");
        assert!(chain_access.registry_chain.is_some());
        assert_eq!(chain_access.app_rpc_providers.unwrap().len(), 1);
    }
}
