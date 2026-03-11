use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use futures::{Stream, StreamExt};
use log::{error, info};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_vsock::VsockStream;

use crate::hostfs_service::HostFsService;
use crate::{utils, vsock};

pub struct HostFsProxy<S> {
    mount_name: String,
    port: u32,
    incoming: Box<dyn Stream<Item = S> + Send>,
    service: Arc<HostFsService>,
}

impl HostFsProxy<VsockStream> {
    pub fn bind(
        mount_name: impl Into<String>,
        root: impl Into<PathBuf>,
        read_only: bool,
        port: u32,
    ) -> Result<Self> {
        let mount_name = mount_name.into();
        let service = Arc::new(HostFsService::new(&mount_name, root, read_only)?);
        let incoming = vsock::serve(port)?;

        Ok(Self {
            mount_name,
            port,
            incoming: Box::new(incoming),
            service,
        })
    }
}

impl<S> HostFsProxy<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn serve(self) {
        let mount_name = self.mount_name.clone();
        let port = self.port;
        info!(
            "hostfs proxy for mount '{}' listening on vsock port {port}",
            mount_name
        );

        let mut incoming = Box::into_pin(self.incoming);
        while let Some(stream) = incoming.next().await {
            let service = Arc::clone(&self.service);
            let connection_mount_name = self.mount_name.clone();

            utils::spawn!(
                &format!("hostfs proxy ({connection_mount_name})"),
                async move {
                    if let Err(err) = service.serve_conn(stream).await {
                        error!(
                            "hostfs proxy connection for mount '{}' failed: {err:#}",
                            connection_mount_name
                        );
                    }
                }
            )
            .expect("spawn hostfs proxy");
        }
    }
}
