use anyhow::Result;
use http::Uri;
use log::debug;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use enclaver::constants::{HTTP_EGRESS_PROXY_PORT, MANIFEST_FILE_NAME};
use enclaver::manifest::{self, HeliosRpcKind, Manifest};
use enclaver::proxy::kms::KmsEndpointProvider;
use enclaver::tls;

#[derive(Clone, Debug)]
pub struct HeliosRuntimeConfig {
    pub kind: HeliosRpcKind,
    pub network: String,
    pub execution_rpc: String,
    pub consensus_rpc: Option<String>,
    pub checkpoint: Option<String>,
    pub listen_port: u16,
    pub chain_id: Option<String>,
}

pub struct Configuration {
    pub config_dir: PathBuf,
    pub manifest: Manifest,
    pub listener_configs: HashMap<u16, ListenerConfig>,
}

#[derive(Clone)]
pub enum ListenerConfig {
    TCP,
    TLS(Arc<rustls::ServerConfig>),
}

impl Configuration {
    pub async fn load<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let mut manifest_path = config_dir.as_ref().to_path_buf();
        manifest_path.push(MANIFEST_FILE_NAME);

        let manifest = enclaver::manifest::load_manifest(manifest_path.to_str().unwrap()).await?;

        let mut tls_path = config_dir.as_ref().to_path_buf();
        tls_path.extend(["tls", "server"]);

        let mut listener_configs = HashMap::new();

        if let Some(ref ingress) = manifest.ingress {
            for item in ingress {
                let cfg = match item.tls {
                    Some(_) => {
                        let tls_config = Configuration::load_tls_server_config(&tls_path, item)?;
                        ListenerConfig::TLS(tls_config)
                    }
                    None => ListenerConfig::TCP,
                };

                listener_configs.insert(item.listen_port, cfg);
            }
        }

        Ok(Self {
            config_dir: config_dir.as_ref().to_path_buf(),
            manifest,
            listener_configs,
        })
    }

    fn load_tls_server_config(
        tls_path: &Path,
        ingress: &manifest::Ingress,
    ) -> Result<Arc<rustls::ServerConfig>> {
        let mut ingress_path = tls_path.to_path_buf();
        ingress_path.push(ingress.listen_port.to_string());

        let mut key_path = ingress_path.clone();
        key_path.push("key.pem");

        let mut cert_path = ingress_path.clone();
        cert_path.push("cert.pem");

        debug!("Loading key_file: {}", key_path.to_string_lossy());
        debug!("Loading cert_file: {}", cert_path.to_string_lossy());
        tls::load_server_config(key_path, cert_path)
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

    pub fn kms_proxy_port(&self) -> Option<u16> {
        self.manifest.kms_proxy.as_ref().map(|kp| kp.listen_port)
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
            .or(Some(api_port + 1))
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
        // New multi-chain manifest shape.
        if let Some(chain_access) = self.manifest.chain_access.as_ref() {
            let mut configs = Vec::new();
            if let Some(registry_chain) = chain_access.registry_chain.as_ref() {
                configs.push(HeliosRuntimeConfig {
                    kind: registry_chain.kind.clone(),
                    network: registry_chain.network.clone(),
                    execution_rpc: registry_chain.execution_rpc.clone(),
                    consensus_rpc: registry_chain.consensus_rpc.clone(),
                    checkpoint: registry_chain.checkpoint.clone(),
                    listen_port: registry_chain.local_rpc_port,
                    chain_id: Some("registry".to_string()),
                });
            }

            if let Some(providers) = chain_access.app_rpc_providers.as_ref() {
                let mut keys: Vec<&String> = providers.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(provider) = providers.get(key) {
                        configs.push(HeliosRuntimeConfig {
                            kind: provider.kind.clone(),
                            network: provider.network.clone(),
                            execution_rpc: provider.execution_rpc.clone(),
                            consensus_rpc: provider.consensus_rpc.clone(),
                            checkpoint: provider.checkpoint.clone(),
                            listen_port: provider.local_rpc_port,
                            chain_id: Some((*key).clone()),
                        });
                    }
                }
            }

            if !configs.is_empty() {
                return configs;
            }
        }

        // Backward-compatible single Helios shape.
        if let Some(legacy) = self.manifest.helios_rpc.as_ref().filter(|h| h.enabled) {
            let network = legacy
                .network
                .as_ref()
                .map(|n| n.trim().to_string())
                .unwrap_or_default();
            let execution_rpc = legacy
                .execution_rpc
                .as_ref()
                .map(|v| v.trim().to_string())
                .unwrap_or_default();
            if !network.is_empty() && !execution_rpc.is_empty() {
                return vec![HeliosRuntimeConfig {
                    kind: legacy.kind.clone(),
                    network,
                    execution_rpc,
                    consensus_rpc: legacy.consensus_rpc.clone(),
                    checkpoint: legacy.checkpoint.clone(),
                    listen_port: legacy.listen_port,
                    chain_id: None,
                }];
            }
        }

        Vec::new()
    }
}

impl KmsEndpointProvider for Configuration {
    fn endpoint(&self, region: &str) -> String {
        let ep = self
            .manifest
            .kms_proxy
            .as_ref()
            .and_then(|kp| kp.endpoints.as_ref().map(|eps| eps.get(region).cloned()))
            .flatten();

        ep.unwrap_or_else(|| format!("kms.{region}.amazonaws.com"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclaver::manifest::{Api, AuxApi, ChainAccess, HeliosRpc, HeliosRpcProvider, Sources};

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
                kms_proxy: None,
                api: Some(Api { listen_port: 9000 }),
                aux_api: None,
                vsock_ports: None,
                storage: None,
                kms_integration: None,
                chain_access: None,
                helios_rpc: None,
            },
            listener_configs: HashMap::new(),
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
    fn helios_configs_falls_back_to_legacy_shape() {
        let mut cfg = base_config();
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            kind: HeliosRpcKind::Ethereum,
            listen_port: 8545,
            network: Some("sepolia".to_string()),
            execution_rpc: Some("https://eth-sepolia.example".to_string()),
            consensus_rpc: None,
            checkpoint: None,
        });

        let configs = cfg.helios_configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].network, "sepolia");
        assert_eq!(configs[0].chain_id, None);
    }

    #[test]
    fn helios_configs_prefers_chain_access_and_sorts_chain_ids() {
        let mut cfg = base_config();
        let mut app_providers = HashMap::new();
        app_providers.insert(
            "8453".to_string(),
            HeliosRpcProvider {
                kind: HeliosRpcKind::Opstack,
                network: "base".to_string(),
                execution_rpc: "https://base.example".to_string(),
                consensus_rpc: None,
                checkpoint: None,
                local_rpc_port: 18547,
            },
        );
        app_providers.insert(
            "1".to_string(),
            HeliosRpcProvider {
                kind: HeliosRpcKind::Ethereum,
                network: "mainnet".to_string(),
                execution_rpc: "https://eth.example".to_string(),
                consensus_rpc: None,
                checkpoint: None,
                local_rpc_port: 18546,
            },
        );
        cfg.manifest.chain_access = Some(ChainAccess {
            registry_chain: Some(HeliosRpcProvider {
                kind: HeliosRpcKind::Opstack,
                network: "base-sepolia".to_string(),
                execution_rpc: "https://sepolia.base.example".to_string(),
                consensus_rpc: None,
                checkpoint: None,
                local_rpc_port: 18545,
            }),
            app_rpc_providers: Some(app_providers),
        });
        cfg.manifest.helios_rpc = Some(HeliosRpc {
            enabled: true,
            kind: HeliosRpcKind::Ethereum,
            listen_port: 9999,
            network: Some("holesky".to_string()),
            execution_rpc: Some("https://unused.example".to_string()),
            consensus_rpc: None,
            checkpoint: None,
        });

        let configs = cfg.helios_configs();
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].chain_id.as_deref(), Some("registry"));
        assert_eq!(configs[1].chain_id.as_deref(), Some("1"));
        assert_eq!(configs[2].chain_id.as_deref(), Some("8453"));
    }
}
