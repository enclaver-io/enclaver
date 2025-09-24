use std::sync::Arc;

use anyhow::Result;
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use enclaver::constants::HTTP_EGRESS_VSOCK_PORT;
use enclaver::policy::EgressPolicy;
use enclaver::proxy::egress_http::EnclaveHttpProxy;

pub struct EgressService {
    proxy: Option<JoinHandle<()>>,
}

impl EgressService {
    pub async fn start(config: &Configuration) -> Result<Self> {
        let task = if let Some(proxy_uri) = config.egress_proxy_uri() {
            info!("Starting egress");

            let policy = Arc::new(EgressPolicy::new(config.manifest.egress.as_ref().unwrap()));

            set_proxy_env_var(&proxy_uri.to_string());

            let proxy = EnclaveHttpProxy::bind(proxy_uri.port_u16().unwrap()).await?;

            Some(tokio::task::spawn(async move {
                proxy.serve(HTTP_EGRESS_VSOCK_PORT, policy).await;
            }))
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

fn set_proxy_env_var(value: &str) {
    unsafe {
        // SAFETY: While not 100% b/c it is a multi-threaded program, with 3rd party code,
        // we only get/set env vars in a ::start() methods that are serialized via .await.

        std::env::set_var("http_proxy", value);
        std::env::set_var("https_proxy", value);
        std::env::set_var("HTTP_PROXY", value);
        std::env::set_var("HTTPS_PROXY", value);

        const NO_PROXY: &str = "localhost,127.0.0.1";
        std::env::set_var("no_proxy", NO_PROXY);
        std::env::set_var("NO_PROXY", NO_PROXY);
    }
}
