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
                
                // Load AWS config from IMDS (EC2 instance metadata)
                let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                let client = S3Client::new(&aws_config);
                
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
