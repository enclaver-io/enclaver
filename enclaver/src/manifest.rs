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
}
