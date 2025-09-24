use std::sync::Arc;

use anyhow::{anyhow, Result};

use log::{error, info};
use tokio::task::JoinHandle;

use enclaver::http_util::HttpServer;
use enclaver::keypair::KeyPair;
use enclaver::nsm::{Nsm, NsmAttestationProvider};
use enclaver::proxy::aws_util;
use enclaver::proxy::kms::{CredentialsGetter, KmsProxyConfig, KmsProxyHandler};

use crate::config::Configuration;

const NO_EGRESS_ERROR: &str = "KMS proxy is configured but egress is not. Configure egress allow policy to access the IMDS at 169.254.169.254 and the AWS KMS endpoint";

pub struct KmsProxyService {
    proxy: Option<JoinHandle<()>>,
}

impl KmsProxyService {
    pub async fn start(config: Arc<Configuration>, nsm: Arc<Nsm>) -> Result<Self> {
        let task = if let Some(port) = config.kms_proxy_port() {
            if let Some(proxy_uri) = config.egress_proxy_uri() {
                info!("Starting KMS proxy");
                let attester = Box::new(NsmAttestationProvider::new(nsm));

                // If a keypair will be needed elsewhere, this should be moved out
                info!("Generating public/private keypair");
                let keypair = Arc::new(KeyPair::generate()?);

                let imds = aws_util::imds_client_with_proxy(proxy_uri.clone()).await?;

                info!("Fetching config from IMDSv2");
                let sdk_config = aws_util::load_config_from_imds(imds).await?;

                let client = Box::new(enclaver::http_client::new_http_proxy_client(proxy_uri));
                let kms_config = KmsProxyConfig {
                    credentials_get: CredentialsGetter::SdkConfig(Box::new(sdk_config)),
                    client,
                    keypair,
                    attester,
                    endpoints: config,
                };

                let proxy = HttpServer::bind(port).await?;
                let handler = KmsProxyHandler::new(kms_config);

                // Set and env var to avoid configuring the port in two places
                unsafe {
                    // SAFETY: While not 100% b/c it is a multi-threaded program, with 3rd party code,
                    // we only get/set env vars in a ::start() methods that are serialized via .await.
                    std::env::set_var("AWS_KMS_ENDPOINT", format!("http://127.0.0.1:{port}"));
                }

                Some(tokio::task::spawn(async move {
                    if let Err(err) = proxy.serve(handler).await {
                        error!("Error serving KMS proxy: {err}");
                    }
                }))
            } else {
                return Err(anyhow!(NO_EGRESS_ERROR));
            }
        } else {
            None
        };

        Ok(Self { proxy: task })
    }

    pub async fn stop(self) {
        if let Some(proxy) = self.proxy {
            proxy.abort();
            _ = proxy.await;
        }
    }
}
