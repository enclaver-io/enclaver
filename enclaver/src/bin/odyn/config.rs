use anyhow::Result;
use http::Uri;
use log::debug;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use enclaver::constants::{HTTP_EGRESS_PROXY_PORT, MANIFEST_FILE_NAME};
use enclaver::manifest::{self, Manifest};
use enclaver::proxy::kms::KmsEndpointProvider;
use enclaver::tls;

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

    pub fn helios_config(&self) -> Option<&enclaver::manifest::HeliosRpc> {
        self.manifest
            .helios_rpc
            .as_ref()
            .filter(|h| h.enabled)
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
