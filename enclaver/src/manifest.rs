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
    pub clock_sync: Option<ClockSync>,
}

impl Manifest {
    pub fn effective_clock_sync(&self) -> ClockSync {
        self.clock_sync.clone().unwrap_or_default()
    }

    pub fn hostfs_mounts(&self) -> Option<&[HostFsMountConfig]> {
        self.storage
            .as_ref()
            .and_then(|storage| storage.mounts.as_deref())
    }
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
    pub mounts: Option<Vec<HostFsMountConfig>>,
}

impl Storage {
    fn validate(&self) -> Result<()> {
        let Some(mounts) = self.mounts.as_ref() else {
            return Ok(());
        };

        let mut used_names = HashSet::new();
        let mut used_paths = HashSet::new();
        for (index, mount) in mounts.iter().enumerate() {
            let context = format!("storage.mounts[{index}]");
            mount.validate(&context)?;

            let mount_name = mount.name.trim().to_ascii_lowercase();
            if !used_names.insert(mount_name) {
                bail!("duplicate storage.mounts name: {}", mount.name.trim());
            }

            if !used_paths.insert(mount.mount_path.clone()) {
                bail!(
                    "duplicate storage.mounts mount_path: {}",
                    mount.mount_path.display()
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFsMountConfig {
    pub name: String,
    pub mount_path: PathBuf,
    #[serde(default)]
    pub required: bool,
    pub size_mb: u64,
}

impl HostFsMountConfig {
    fn validate(&self, context: &str) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("{context}.name is required");
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!("{context}.name may contain only ASCII letters, digits, '.', '-', and '_'");
        }
        if !self.mount_path.is_absolute() {
            bail!("{context}.mount_path must be absolute");
        }
        if self.mount_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }) {
            bail!("{context}.mount_path must not contain '.' or '..' path components");
        }
        for forbidden in [
            Path::new("/etc"),
            Path::new("/bin"),
            Path::new("/usr"),
            Path::new("/lib"),
            Path::new("/lib64"),
            Path::new("/sbin"),
            Path::new("/proc"),
            Path::new("/sys"),
            Path::new("/dev"),
        ] {
            if self.mount_path == forbidden || self.mount_path.starts_with(forbidden) {
                bail!(
                    "{context}.mount_path '{}' targets a reserved system path",
                    self.mount_path.display()
                );
            }
        }

        if self.size_mb == 0 {
            bail!("{context}.size_mb must be greater than 0");
        }

        Ok(())
    }
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
    fn has_any_registry_field(&self) -> bool {
        self.kms_app_id.is_some()
            || self
                .nova_app_registry
                .as_deref()
                .map(str::trim)
                .is_some_and(|v| !v.is_empty())
    }

    pub fn registry_discovery_configured(&self) -> bool {
        self.kms_app_id.is_some()
            && self
                .nova_app_registry
                .as_deref()
                .map(str::trim)
                .is_some_and(|v| !v.is_empty())
    }

    fn validate_registry_fields(&self) -> Result<()> {
        let kms_app_id = self.kms_app_id.ok_or_else(|| {
            anyhow!("kms_integration.kms_app_id is required for registry discovery")
        })?;
        if kms_app_id == 0 {
            bail!("kms_integration.kms_app_id must be non-zero for registry discovery");
        }

        let registry = self
            .nova_app_registry
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                anyhow!("kms_integration.nova_app_registry is required for registry discovery")
            })?;
        if !(registry.starts_with("0x") || registry.starts_with("0X")) || registry.len() != 42 {
            bail!("kms_integration.nova_app_registry must be a 20-byte hex address");
        }
        let registry_hex = registry.trim_start_matches("0x").trim_start_matches("0X");
        if hex::decode(registry_hex).is_err() {
            bail!("kms_integration.nova_app_registry must be a 20-byte hex address");
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.use_app_wallet && !self.enabled {
            bail!("kms_integration.use_app_wallet requires kms_integration.enabled=true");
        }

        if !self.enabled {
            return Ok(());
        }

        let has_any_registry_field = self.has_any_registry_field();
        if !self.use_app_wallet && !has_any_registry_field {
            bail!(
                "kms_integration.kms_app_id and kms_integration.nova_app_registry are required when kms_integration.enabled=true and kms_integration.use_app_wallet=false"
            );
        }
        if has_any_registry_field && !self.registry_discovery_configured() {
            bail!(
                "kms_integration.kms_app_id and kms_integration.nova_app_registry must be set together"
            );
        }
        if self.registry_discovery_configured() {
            self.validate_registry_fields()?;
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSync {
    #[serde(default = "default_clock_sync_enabled")]
    pub enabled: bool,
    /// Sync interval in seconds. Default: 300
    #[serde(default = "default_clock_sync_interval")]
    pub interval_secs: u64,
}

impl Default for ClockSync {
    fn default() -> Self {
        Self {
            enabled: default_clock_sync_enabled(),
            interval_secs: default_clock_sync_interval(),
        }
    }
}

impl ClockSync {
    fn validate(&self) -> Result<()> {
        if self.interval_secs == 0 {
            bail!("clock_sync.interval_secs must be greater than 0");
        }

        Ok(())
    }
}

fn default_clock_sync_enabled() -> bool {
    true
}

fn default_clock_sync_interval() -> u64 {
    300
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

    if let Some(storage) = manifest.storage.as_ref() {
        storage.validate()?;
    }

    if let Some(kms_integration) = manifest.kms_integration.as_ref() {
        kms_integration.validate()?;
    }

    if let Some(helios) = manifest.helios_rpc.as_ref() {
        helios.validate()?;
    }

    if let Some(clock_sync) = manifest.clock_sync.as_ref() {
        clock_sync.validate()?;
    }

    validate_manifest_cross_constraints(&manifest)?;

    Ok(manifest)
}

fn validate_manifest_cross_constraints(manifest: &Manifest) -> Result<()> {
    let kms_cfg = manifest.kms_integration.as_ref().filter(|kms| kms.enabled);
    let Some(kms_cfg) = kms_cfg else {
        return Ok(());
    };
    if !kms_cfg.registry_discovery_configured() {
        return Ok(());
    }

    let helios = manifest.helios_rpc.as_ref().ok_or_else(|| {
        anyhow!(
            "kms_integration registry mode requires helios_rpc.enabled=true and local_rpc_port={}",
            KMS_REGISTRY_HELIOS_PORT
        )
    })?;
    if !helios.enabled {
        bail!(
            "kms_integration registry mode requires helios_rpc.enabled=true and local_rpc_port={}",
            KMS_REGISTRY_HELIOS_PORT
        );
    }

    let chains = helios.chains.as_ref().ok_or_else(|| {
        anyhow!(
            "kms_integration registry mode requires helios_rpc.chains to include local_rpc_port={}",
            KMS_REGISTRY_HELIOS_PORT
        )
    })?;
    if !chains
        .iter()
        .any(|chain| chain.local_rpc_port == KMS_REGISTRY_HELIOS_PORT)
    {
        bail!(
            "kms_integration registry mode requires helios_rpc.chains to include local_rpc_port={} for registry discovery",
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
    use std::path::PathBuf;

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
    fn test_parse_manifest_with_hostfs_mount() {
        let raw_manifest = br#"
version: v1
name: "test-hostfs"
target: "target-image:latest"
sources:
  app: "app-image:latest"
storage:
  mounts:
    - name: appdata
      mount_path: /mnt/appdata
      required: true
      size_mb: 128
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let mounts = manifest
            .hostfs_mounts()
            .expect("hostfs mounts should be present");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "appdata");
        assert_eq!(mounts[0].mount_path, PathBuf::from("/mnt/appdata"));
        assert_eq!(mounts[0].size_mb, 128);
    }

    #[test]
    fn test_parse_manifest_rejects_hostfs_mount_on_reserved_path() {
        let raw_manifest = br#"
version: v1
name: "test-hostfs"
target: "target-image:latest"
sources:
  app: "app-image:latest"
storage:
  mounts:
    - name: appdata
      mount_path: /etc/appdata
      size_mb: 128
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_manifest_rejects_duplicate_hostfs_mount_names() {
        let raw_manifest = br#"
version: v1
name: "test-hostfs"
target: "target-image:latest"
sources:
  app: "app-image:latest"
storage:
  mounts:
    - name: appdata
      mount_path: /mnt/appdata
      size_mb: 128
    - name: appdata
      mount_path: /mnt/cache
      size_mb: 64
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_manifest_rejects_legacy_hostfs_fields() {
        let raw_manifest = br#"
version: v1
name: "test-hostfs"
target: "target-image:latest"
sources:
  app: "app-image:latest"
storage:
  mounts:
    - name: appdata
      type: hostfs
      mount_path: /mnt/appdata
      size_mb: 64
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_manifest_defaults_clock_sync_when_omitted() {
        let raw_manifest = br#"
version: v1
name: "test-clock-sync"
target: "target-image:latest"
sources:
  app: "app-image:latest"
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let clock_sync = manifest.effective_clock_sync();

        assert!(clock_sync.enabled);
        assert_eq!(clock_sync.interval_secs, 300);
    }

    #[test]
    fn test_parse_clock_sync_defaults_enabled_and_interval() {
        let raw_manifest = br#"
version: v1
name: "test-clock-sync"
target: "target-image:latest"
sources:
  app: "app-image:latest"
clock_sync: {}
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let clock_sync = manifest.clock_sync.expect("clock_sync should be present");

        assert!(clock_sync.enabled);
        assert_eq!(clock_sync.interval_secs, 300);
    }

    #[test]
    fn test_parse_manifest_rejects_zero_clock_sync_interval() {
        let raw_manifest = br#"
version: v1
name: "test-clock-sync"
target: "target-image:latest"
sources:
  app: "app-image:latest"
clock_sync:
  interval_secs: 0
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_clock_sync_keeps_enabled_when_only_interval_is_set() {
        let raw_manifest = br#"
version: v1
name: "test-clock-sync"
target: "target-image:latest"
sources:
  app: "app-image:latest"
clock_sync:
  interval_secs: 60
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let clock_sync = manifest.clock_sync.expect("clock_sync should be present");

        assert!(clock_sync.enabled);
        assert_eq!(clock_sync.interval_secs, 60);
    }

    #[test]
    fn test_parse_manifest_rejects_deprecated_chain_access_block() {
        let raw_manifest = br#"
version: v1
name: "test-deprecated-chain-access"
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
    fn test_parse_manifest_rejects_deprecated_helios_single_chain_shape() {
        let raw_manifest = br#"
version: v1
name: "test-deprecated-helios"
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
    fn test_parse_kms_integration_use_app_wallet_local_mode_without_registry() {
        let raw_manifest = br#"
version: v1
name: "test-kms-app-wallet-local-only"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  use_app_wallet: true
"#;

        let manifest = parse_manifest(raw_manifest).unwrap();
        let kms = manifest
            .kms_integration
            .expect("kms_integration should be present");
        assert!(kms.enabled);
        assert!(kms.use_app_wallet);
        assert!(kms.kms_app_id.is_none());
        assert!(kms.nova_app_registry.is_none());
    }

    #[test]
    fn test_parse_kms_integration_enabled_requires_registry_when_use_app_wallet_false() {
        let raw_manifest = br#"
version: v1
name: "test-kms-needs-registry"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
"#;

        assert!(parse_manifest(raw_manifest).is_err());
    }

    #[test]
    fn test_parse_kms_integration_rejects_partial_registry_fields() {
        let raw_manifest = br#"
version: v1
name: "test-kms-partial-registry"
target: "target-image:latest"
sources:
  app: "app-image:latest"
kms_integration:
  enabled: true
  use_app_wallet: true
  kms_app_id: 49
"#;

        assert!(parse_manifest(raw_manifest).is_err());
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
    fn test_parse_kms_integration_registry_mode_requires_helios_rpc() {
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
    fn test_parse_kms_integration_registry_mode_requires_registry_helios_port() {
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
