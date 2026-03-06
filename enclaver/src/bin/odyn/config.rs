use anyhow::Result;
use http::Uri;
use std::path::{Path, PathBuf};

use enclaver::constants::{HTTP_EGRESS_PROXY_PORT, MANIFEST_FILE_NAME};
use enclaver::manifest::{HeliosRpcKind, Manifest};

#[derive(Clone, Debug)]
pub struct HeliosRuntimeConfig {
    pub kind: HeliosRpcKind,
    pub network: String,
    pub execution_rpc: String,
    pub consensus_rpc: Option<String>,
    pub checkpoint: Option<String>,
    pub listen_port: u16,
    pub chain_name: String,
}

pub struct Configuration {
    pub config_dir: PathBuf,
    pub manifest: Manifest,
    pub listener_ports: Vec<u16>,
}

impl Configuration {
    pub async fn load<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let mut manifest_path = config_dir.as_ref().to_path_buf();
        manifest_path.push(MANIFEST_FILE_NAME);

        let manifest = enclaver::manifest::load_manifest(manifest_path.to_str().unwrap()).await?;

        let mut listener_ports = Vec::new();

        if let Some(ref ingress) = manifest.ingress {
            for item in ingress {
                listener_ports.push(item.listen_port);
            }
        }

        Ok(Self {
            config_dir: config_dir.as_ref().to_path_buf(),
            manifest,
            listener_ports,
        })
    }

    pub fn egress_proxy_uri(&self) -> Option<Uri> {
        let enabled = if let Some(ref egress) = self.manifest.egress {
            if let Some(ref allow) = egress.allow {
                !allow.is_empty()
            } else {
                false
            }
        } else {
            false
        };

        if enabled {
            let port = self
                .manifest
                .egress
                .as_ref()
                .unwrap()
                .proxy_port
                .unwrap_or(HTTP_EGRESS_PROXY_PORT);

            Some(
                Uri::builder()
                    .scheme("http")
                    .authority(format!("127.0.0.1:{port}"))
                    .path_and_query("")
                    .build()
                    .unwrap(),
            )
        } else {
            None
        }
    }

    pub fn api_port(&self) -> Option<u16> {
        self.manifest.api.as_ref().map(|a| a.listen_port)
    }

    pub fn aux_api_port(&self) -> Option<u16> {
        // Aux API only runs when API service is enabled
        let api_port = self.api_port()?;

        // If aux_api.listen_port is specified, use it; otherwise default to api_port + 1
        self.manifest
            .aux_api
            .as_ref()
            .and_then(|a| a.listen_port)
            .or_else(|| api_port.checked_add(1))
    }

    pub fn s3_config(&self) -> Option<&enclaver::manifest::S3StorageConfig> {
        self.manifest
            .storage
            .as_ref()
            .and_then(|s| s.s3.as_ref())
            .filter(|s3| s3.enabled)
    }

    pub fn kms_integration_config(&self) -> Option<&enclaver::manifest::KmsIntegration> {
        self.manifest
            .kms_integration
            .as_ref()
            .filter(|kms| kms.enabled)
    }

    pub fn helios_configs(&self) -> Vec<HeliosRuntimeConfig> {
        let Some(helios) = self.manifest.helios_rpc.as_ref().filter(|h| h.enabled) else {
            return Vec::new();
        };
        let Some(chains) = helios.chains.as_ref() else {
            return Vec::new();
        };

        let mut configs = Vec::with_capacity(chains.len());
        for chain in chains {
            configs.push(HeliosRuntimeConfig {
                kind: chain.kind.clone(),
                network: chain.network.clone(),
                execution_rpc: chain.execution_rpc.clone(),
                consensus_rpc: chain.consensus_rpc.clone(),
                checkpoint: chain.checkpoint.clone(),
                listen_port: chain.local_rpc_port,
                chain_name: chain.name.clone(),
            });
        }

        configs
    }

    pub fn clock_sync_config(&self) -> Option<&enclaver::manifest::ClockSync> {
        self.manifest
            .clock_sync
            .as_ref()
            .filter(|cs| cs.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclaver::manifest::{Api, AuxApi, HeliosRpc, HeliosRpcChain, Sources};

    fn base_config() -> Configuration {
        Configuration {
            config_dir: PathBuf::from("."),
            manifest: Manifest {
                version: "v1".to_string(),
                name: "test".to_string(),
                target: "target:latest".to_string(),
                sources: Sources {
                    app: "app:latest".to_string(),
                    odyn: None,
                    sleeve: None,
                },
                signature: None,
                ingress: None,
                egress: None,
                defaults: None,
                api: Some(Api { listen_port: 9000 }),
                aux_api: None,
                vsock_ports: None,
                storage: None,
                kms_integration: None,
                helios_rpc: None,
                clock_sync: None,
            },
            listener_ports: Vec::new(),
        }
    }

    #[test]
    fn aux_api_port_defaults_to_api_plus_one() {
        let cfg = base_config();
        assert_eq!(cfg.aux_api_port(), Some(9001));
    }

    #[test]
    fn aux_api_port_uses_explicit_value() {
        let mut cfg = base_config();
        cfg.manifest.aux_api = Some(AuxApi {
            listen_port: Some(9100),
        });
        assert_eq!(cfg.aux_api_port(), Some(9100));
    }

    #[test]
    fn aux_api_port_with_max_api_and_explicit_value_does_not_overflow() {
        let mut cfg = base_config();
        cfg.manifest.api = Some(Api {
            listen_port: u16::MAX,
        });
        cfg.manifest.aux_api = Some(AuxApi {
            listen_port: Some(9001),
        });
        assert_eq!(cfg.aux_api_port(), Some(9001));
    }

    #[test]
    fn aux_api_port_with_max_api_and_no_aux_returns_none() {
        let mut cfg = base_config();
        cfg.manifest.api = Some(Api {
            listen_port: u16::MAX,
        });
        cfg.manifest.aux_api = None;
        assert_eq!(cfg.aux_api_port(), None);
    }

    #[test]
    fn helios_configs_returns_empty_when_disabled() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: false,
            chains: None,
        });

        let configs = cfg.helios_configs();
        assert!(configs.is_empty());
    }

    #[test]
    fn helios_configs_prefers_helios_rpc_chains() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            chains: Some(vec![
                HeliosRpcChain {
                    name: "L2-base-sepolia".to_string(),
                    network_id: Some("84532".to_string()),
                    kind: HeliosRpcKind::Opstack,
                    network: "base-sepolia".to_string(),
                    execution_rpc: "https://sepolia.base.example".to_string(),
                    consensus_rpc: None,
                    checkpoint: None,
                    local_rpc_port: 18545,
                },
                HeliosRpcChain {
                    name: "ethereum-mainnet".to_string(),
                    network_id: Some("1".to_string()),
                    kind: HeliosRpcKind::Ethereum,
                    network: "mainnet".to_string(),
                    execution_rpc: "https://eth.example".to_string(),
                    consensus_rpc: None,
                    checkpoint: None,
                    local_rpc_port: 18546,
                },
            ]),
        });

        let configs = cfg.helios_configs();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].chain_name, "L2-base-sepolia");
        assert_eq!(configs[1].chain_name, "ethereum-mainnet");
    }

    #[test]
    fn helios_configs_returns_empty_when_no_chains() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            chains: None,
        });

        let configs = cfg.helios_configs();
        assert!(configs.is_empty());
    }
}
