use std::sync::Arc;

use anyhow::Result;
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::api::ApiHandler;
use enclaver::http_util::HttpServer;
use enclaver::nsm::AttestationProvider;

pub struct ApiService {
    task: Option<JoinHandle<()>>,
}

impl ApiService {
    pub async fn start(
        config: &Configuration,
        attester: Arc<dyn AttestationProvider + Send + Sync>,
    ) -> Result<Self> {
        let task = if let Some(port) = config.api_port() {
            info!("Starting API on port {port}");

            let srv = HttpServer::bind(port).await?;
            let handler = ApiHandler::new(attester.clone());

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
