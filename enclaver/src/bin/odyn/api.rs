use std::sync::Arc;

use anyhow::Result;
use aws_sdk_s3::Client as S3Client;
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
                
                // Load AWS config from IMDS (EC2 instance metadata) via proxy if available
                let (aws_config, http_client) = if let Some(proxy_uri) = config.egress_proxy_uri() {
                    let http_client = enclaver::proxy::aws_util::new_proxied_client(proxy_uri.clone())?;
                    let imds = enclaver::proxy::aws_util::imds_client_with_proxy(proxy_uri).await?;
                    let sdk_config = enclaver::proxy::aws_util::load_config_from_imds(imds).await?;
                    (sdk_config, Some(http_client))
                } else {
                    (aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await, None)
                };

                let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);
                if let Some(hc) = http_client {
                    s3_config_builder = s3_config_builder.http_client(hc);
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
