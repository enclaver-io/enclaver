use anyhow::Result;
use ignore_result::Ignore;
use log::info;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::proxy::ingress::EnclaveProxy;

pub struct IngressService {
    proxies: Vec<JoinHandle<()>>,
    shutdown: watch::Sender<()>,
}

impl IngressService {
    pub fn start(config: &Configuration) -> Result<Self> {
        let mut tasks = Vec::new();

        let (tx, rx) = tokio::sync::watch::channel(());
        for port in &config.listener_ports {
            info!("Starting TCP ingress on port {}", *port);
            let proxy = EnclaveProxy::bind(*port)?;
            tasks.push(tokio::spawn(proxy.serve(rx.clone())));
        }

        Ok(Self {
            proxies: tasks,
            shutdown: tx,
        })
    }

    pub async fn stop(self) {
        self.shutdown.send(()).ignore();

        for p in self.proxies {
            p.await.ignore();
        }
    }
}
