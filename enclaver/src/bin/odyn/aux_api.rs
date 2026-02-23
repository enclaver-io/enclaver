use anyhow::Result;
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::aux_api::AuxApiHandler;
use enclaver::http_util::HttpServer;

pub struct AuxApiService {
    task: Option<JoinHandle<()>>,
}

impl AuxApiService {
    pub async fn start(config: &Configuration) -> Result<Self> {
        let task = if let Some(port) = config.aux_api_port() {
            // Verify API port exists as a safety check
            if config.api_port().is_none() {
                return Ok(Self { task: None });
            }

            let api_port = config.api_port().unwrap();
            info!("Starting Aux API on port {port} (proxying to API on port {api_port})");

            let srv = HttpServer::bind(port).await?;
            let handler = AuxApiHandler::new(api_port);

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
