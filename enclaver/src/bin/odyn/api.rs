use std::sync::Arc;

use anyhow::Result;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Region;
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::api::ApiHandler;
use enclaver::http_util::HttpServer;
use enclaver::nsm::{Nsm, NsmAttestationProvider};

pub struct ApiService {
    task: Option<JoinHandle<()>>,
}

impl ApiService {
    pub async fn start(config: &Configuration, nsm: Arc<Nsm>) -> Result<Self> {
        let task = if let Some(port) = config.api_port() {
            info!("Starting API on port {port}");

            // Create S3 proxy if S3 storage is configured
            let s3_proxy = if let Some(s3_config) = config.s3_config() {
                info!("S3 storage enabled: bucket={}, prefix={}", s3_config.bucket, s3_config.prefix);
                
                // Load AWS config from IMDS (EC2 instance metadata) via proxy
                // inside an enclave, we MUST use a proxy to reach IMDS
                let proxy_uri = config.egress_proxy_uri().ok_or_else(|| {
                    anyhow::anyhow!("Egress proxy is not configured, but is required for AWS IMDS access inside the enclave.")
                })?;

                info!("Enclave environment detected: using egress proxy at {} for AWS configuration", proxy_uri);
                
                let http_client = enclaver::proxy::aws_util::new_proxied_client(proxy_uri.clone())?;
                let imds = enclaver::proxy::aws_util::imds_client_with_proxy(proxy_uri).await?;
                
                // Small delay to ensure egress proxy is fully up and ready to handle vsock requests
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                
                let aws_config = enclaver::proxy::aws_util::load_config_from_imds(imds).await?;

                let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);
                s3_config_builder = s3_config_builder.http_client(http_client);

                if let Some(region) = &s3_config.region {
                    s3_config_builder = s3_config_builder.region(Region::new(region.clone()));
                }
                
                let client = S3Client::from_conf(s3_config_builder.build());
                
                Some(Arc::new(enclaver::proxy::s3::S3Proxy::new(
                    client,
                    s3_config.bucket.clone(),
                    s3_config.prefix.clone(),
                )))
            } else {
                None
            };

            let srv = HttpServer::bind(port).await?;
            let handler = ApiHandler::with_s3(
                Box::new(NsmAttestationProvider::new(nsm.clone())),
                Some(nsm),
                s3_proxy,
            )?;

            Some(tokio::task::spawn(async move {
                _ = srv.serve(handler).await;
            }))
        } else {
            None
        };

        Ok(Self { task })
    }

    pub async fn stop(self) {
        if let Some(task) = self.task {
            task.abort();
            _ = task.await;
        }
    }
}
