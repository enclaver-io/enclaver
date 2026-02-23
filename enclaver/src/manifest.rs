use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
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
    pub api: Option<Api>,
    pub aux_api: Option<AuxApi>,
    pub vsock_ports: Option<VsockPorts>,
    pub storage: Option<Storage>,
    pub kms_integration: Option<KmsIntegration>,
    pub helios_rpc: Option<HeliosRpc>,
}

const KMS_REGISTRY_HELIOS_PORT: u16 = 18545;

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
    #[serde(default)]
    pub use_app_wallet: bool,
    pub kms_app_id: Option<u64>,
    pub nova_app_registry: Option<String>,
}

impl KmsIntegration {
    fn validate(&self) -> Result<()> {
        if self.use_app_wallet && !self.enabled {
            bail!("kms_integration.use_app_wallet requires kms_integration.enabled=true");
        }

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
        let registry_hex = registry.trim_start_matches("0x").trim_start_matches("0X");
        if hex::decode(registry_hex).is_err() {
            bail!("kms_integration.nova_app_registry must be a 20-byte hex address");
        }
        Ok(())
    }
}

fn validate_helios_network(kind: &HeliosRpcKind, network: &str, context: &str) -> Result<()> {
    let normalized = network.trim().to_lowercase();
    if normalized.is_empty() {
        bail!("{context}.network is required");
    }

    match kind {
        HeliosRpcKind::Ethereum => {
            if !matches!(normalized.as_str(), "mainnet" | "sepolia" | "holesky") {
                bail!(
                    "{context}.network '{}' is unsupported for kind=ethereum. Supported: mainnet, sepolia, holesky.",
                    normalized
                );
            }
        }
        HeliosRpcKind::Opstack => {
            if !matches!(
                normalized.as_str(),
                "op-mainnet" | "base" | "base-sepolia" | "worldchain" | "zora" | "unichain"
            ) {
                bail!(
                    "{context}.network '{}' is unsupported for kind=opstack. Supported: op-mainnet, base, base-sepolia, worldchain, zora, unichain.",
                    normalized
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeliosRpcChain {
    pub name: String,
    pub network_id: Option<String>,
    pub kind: HeliosRpcKind,
    pub network: String,
    pub execution_rpc: String,
    pub consensus_rpc: Option<String>,
    pub checkpoint: Option<String>,
    pub local_rpc_port: u16,
}

impl HeliosRpcChain {
    fn validate(&self, context: &str) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("{context}.name is required");
        }
        if self
            .network_id
            .as_deref()
            .map(str::trim)
            .is_some_and(str::is_empty)
        {
            bail!("{context}.network_id must not be empty");
        }
        if self.execution_rpc.trim().is_empty() {
            bail!("{context}.execution_rpc is required");
        }

        validate_helios_network(&self.kind, &self.network, context)
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

/// Configuration for Helios multi-chain light-client RPC services.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeliosRpc {
    /// Enable/disable Helios RPC service
    #[serde(default)]
    pub enabled: bool,
    /// Multi-chain shape (required when enabled).
    pub chains: Option<Vec<HeliosRpcChain>>,
}

impl HeliosRpc {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let chains = self.chains.as_ref().ok_or_else(|| {
            anyhow!("helios_rpc.chains is required when helios_rpc.enabled is true")
        })?;
        if chains.is_empty() {
            bail!("helios_rpc.chains must not be empty when helios_rpc.enabled is true");
        }

        let mut used_ports = HashSet::new();
        let mut used_names = HashSet::new();
        for (index, chain) in chains.iter().enumerate() {
            chain.validate(&format!("helios_rpc.chains[{index}]"))?;

            let chain_name = chain.name.trim().to_lowercase();
            if !used_names.insert(chain_name) {
                bail!(
                    "duplicate chain name in helios_rpc.chains: {}",
                    chain.name.trim()
                );
            }
            if !used_ports.insert(chain.local_rpc_port) {
                bail!(
                    "duplicate local_rpc_port in helios_rpc.chains: {}",
                    chain.local_rpc_port
                );
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

    if let Some(helios) = manifest.helios_rpc.as_ref() {
        helios.validate()?;
    }

    validate_manifest_cross_constraints(&manifest)?;

    Ok(manifest)
}

fn validate_manifest_cross_constraints(manifest: &Manifest) -> Result<()> {
    let kms_enabled = manifest
        .kms_integration
        .as_ref()
        .map(|kms| kms.enabled)
        .unwrap_or(false);
    if !kms_enabled {
        return Ok(());
    }

    let helios = manifest
        .helios_rpc
        .as_ref()
        .ok_or_else(|| anyhow!("kms_integration.enabled=true requires helios_rpc.enabled=true"))?;
    if !helios.enabled {
        bail!("kms_integration.enabled=true requires helios_rpc.enabled=true");
    }

    let chains = helios.chains.as_ref().ok_or_else(|| {
        anyhow!(
            "kms_integration.enabled=true requires helios_rpc.chains to include local_rpc_port={}",
            KMS_REGISTRY_HELIOS_PORT
        )
    })?;
    if !chains
        .iter()
        .any(|chain| chain.local_rpc_port == KMS_REGISTRY_HELIOS_PORT)
    {
        bail!(
            "kms_integration.enabled=true requires helios_rpc.chains to include local_rpc_port={} for registry discovery",
            KMS_REGISTRY_HELIOS_PORT
        );
    }

    Ok(())
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
    fn test_parse_manifest_rejects_legacy_chain_access_block() {
        let raw_manifest = br#"
version: v1
name: "test-legacy-chain-access"
target: "target-image:latest"
sources:
  app: "app-image:latest"
chain_access:
  registry_chain:
    kind: opstack
    network: base-sepolia
    execution_rpc: "https://sepolia.base.org"
    local_rpc_port: 18545
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_manifest_rejects_legacy_helios_single_chain_shape() {
        let raw_manifest = br#"
version: v1
name: "test-legacy-helios"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  kind: opstack
  network: base-sepolia
  execution_rpc: "https://sepolia.base.org"
  listen_port: 18545
"#;

        assert!(parse_manifest(raw_manifest).is_err());
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
  chains:
    - name: ethereum-mainnet
      network_id: "1"
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth-mainnet.g.alchemy.com/v2/KEY"
      consensus_rpc: "https://www.lightclientdata.org"
      checkpoint: "0x1234567890abcdef"
      local_rpc_port: 18546
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        let chains = helios.chains.expect("chains should be present");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "ethereum-mainnet");
        assert_eq!(chains[0].network_id.as_deref(), Some("1"));
        assert_eq!(chains[0].network, "mainnet");
        assert_eq!(
            chains[0].execution_rpc,
            "https://eth-mainnet.g.alchemy.com/v2/KEY"
        );
        assert_eq!(
            chains[0].consensus_rpc.as_deref(),
            Some("https://www.lightclientdata.org")
        );
        assert_eq!(chains[0].checkpoint.as_deref(), Some("0x1234567890abcdef"));
        assert_eq!(chains[0].local_rpc_port, 18546);
    }

    #[test]
    fn test_parse_helios_rpc_minimal_config() {
        let raw_manifest = br#"
version: v1
name: "test-helios-minimal"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  chains:
    - name: ethereum-sepolia
      network_id: "11155111"
      kind: ethereum
      network: sepolia
      execution_rpc: "https://eth-sepolia.g.alchemy.com/v2/KEY"
      local_rpc_port: 18548
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        let chains = helios.chains.expect("chains should be present");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "ethereum-sepolia");
        assert_eq!(chains[0].network_id.as_deref(), Some("11155111"));
        assert_eq!(chains[0].network, "sepolia");
        assert_eq!(
            chains[0].execution_rpc,
            "https://eth-sepolia.g.alchemy.com/v2/KEY"
        );
        assert!(chains[0].consensus_rpc.is_none());
        assert!(chains[0].checkpoint.is_none());
    }

    #[test]
    fn test_parse_helios_rpc_chains_config() {
        let raw_manifest = br#"
version: v1
name: "test-helios-chains"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  chains:
    - name: L2-base-sepolia
      network_id: "84532"
      kind: opstack
      network: base-sepolia
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545
    - name: ethereum-mainnet
      network_id: "1"
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18546
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        let chains = helios.chains.expect("chains should exist");
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].name, "L2-base-sepolia");
        assert_eq!(chains[0].network_id.as_deref(), Some("84532"));
        assert_eq!(chains[1].name, "ethereum-mainnet");
        assert_eq!(chains[1].network_id.as_deref(), Some("1"));
    }

    #[test]
    fn test_parse_helios_rpc_chains_duplicate_ports_rejected() {
        let raw_manifest = br#"
version: v1
name: "test-helios-chains-bad"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  chains:
    - name: L2-base-sepolia
      kind: opstack
      network: base-sepolia
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545
    - name: ethereum-mainnet
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18545
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_helios_rpc_chains_empty_network_id_rejected() {
        let raw_manifest = br#"
version: v1
name: "test-helios-chains-empty-network-id"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc:
  enabled: true
  chains:
    - name: ethereum-mainnet
      network_id: " "
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18546
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_helios_rpc_disabled() {
        let raw_manifest = br#"
version: v1
name: "test-helios-disabled"
target: "target-image:latest"
sources:
  app: "app-image:latest"
helios_rpc: { enabled: false }
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(!helios.enabled);
        assert!(helios.chains.is_none());
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
  chains:
    - name: L2-op-mainnet
      kind: opstack
      network: op-mainnet
      execution_rpc: "https://example.invalid"
      local_rpc_port: 18550
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let helios = manifest.helios_rpc.expect("helios_rpc should be present");
        assert!(helios.enabled);
        let chains = helios.chains.expect("chains should be present");
        assert_eq!(chains[0].network, "op-mainnet");
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
  chains:
    - name: L2-optimism
      kind: opstack
      network: optimism
      execution_rpc: "https://example.invalid"
      local_rpc_port: 18550
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
  chains:
    - name: ethereum-op-mainnet
      kind: ethereum
      network: op-mainnet
      execution_rpc: "https://example.invalid"
      local_rpc_port: 18550
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
  chains:
    - name: L2-mainnet
      kind: opstack
      network: mainnet
      execution_rpc: "https://example.invalid"
      local_rpc_port: 18550
"#;
        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_minimal() {
        let raw_manifest = br#"
version: v1
name: "test-kms"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
helios_rpc:
  enabled: true
  chains:
    - name: L2-base-sepolia
      kind: opstack
      network: base-sepolia
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let kms = manifest
            .kms_integration
            .expect("kms_integration should be present");
        assert!(kms.enabled);
        assert!(!kms.use_app_wallet);
    }

    #[test]
    fn test_parse_kms_integration_use_app_wallet() {
        let raw_manifest = br#"
version: v1
name: "test-kms-app-wallet"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  use_app_wallet: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
helios_rpc:
  enabled: true
  chains:
    - name: L2-base-sepolia
      kind: opstack
      network: base-sepolia
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let kms = manifest
            .kms_integration
            .expect("kms_integration should be present");
        assert!(kms.enabled);
        assert!(kms.use_app_wallet);
    }

    #[test]
    fn test_parse_kms_integration_rejects_use_app_wallet_when_disabled() {
        let raw_manifest = br#"
version: v1
name: "test-kms-app-wallet-disabled"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: false
  use_app_wallet: true
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_requires_helios_rpc() {
        let raw_manifest = br#"
version: v1
name: "test-kms-needs-helios"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_requires_registry_helios_port() {
        let raw_manifest = br#"
version: v1
name: "test-kms-missing-registry-helios-port"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
helios_rpc:
  enabled: true
  chains:
    - name: ethereum-mainnet
      kind: ethereum
      network: mainnet
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18546
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_rejects_base_urls_field() {
        let raw_manifest = br#"
version: v1
name: "test-kms-base-urls"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
  base_urls:
    - "https://kms-1.example.com"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_rejects_invalid_registry_hex() {
        let raw_manifest = br#"
version: v1
name: "test-kms-bad-registry"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64ccZ"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_rejects_registry_chain_rpc_field() {
        let raw_manifest = br#"
version: v1
name: "test-kms-bad-rpc"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 49
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
  registry_chain_rpc: "https://sepolia.base.org"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_enabled_rejects_zero_app_id() {
        let raw_manifest = br#"
version: v1
name: "test-kms-zero-app-id"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  kms_app_id: 0
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }
}
