use anyhow::Result;
use futures::{Stream, StreamExt};
use log::{debug, error, info};
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_vsock::{VsockListener, VsockStream};

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_CID_HOST: u32 = 2;

pub type TlsServerStream = tokio_rustls::server::TlsStream<VsockStream>;
pub type TlsClientStream = tokio_rustls::client::TlsStream<VsockStream>;

// Listen on a vsock with the given port.
// Returns a Stream of connected sockets.
pub fn serve(port: u32) -> Result<impl Stream<Item = VsockStream> + Unpin> {
    let listener = VsockListener::bind(VMADDR_CID_ANY, port)?;

    info!("Listening on vsock port {port}");
    let stream = listener.incoming().filter_map(move |result| {
        futures::future::ready(match result {
            Ok(vsock) => {
                debug!("Connection accepted on port {port}");
                Some(vsock)
            }

            Err(err) => {
                error!("Failed to accept a vsock: {err}");
                None
            }
        })
    });

    Ok(stream)
}

// Listen on a vsock with the given port for TLS connections.
// Returns a Stream of TLS connected sockets.
pub fn tls_serve(
    port: u32,
    tls_config: Arc<ServerConfig>,
) -> Result<impl Stream<Item = TlsServerStream>> {
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = VsockListener::bind(VMADDR_CID_ANY, port)?;

    info!("Listening on TLS vsock port {}", port);
    let stream = listener.incoming().filter_map(move |result| {
        let acceptor = acceptor.clone();
        async move {
            match result {
                Ok(vsock) => {
                    debug!("Connection accepted on port {port}");
                    match acceptor.accept(vsock).await {
                        Ok(vsock) => Some(vsock),
                        Err(err) => {
                            error!("TLS handshake failed: {err}");
                            None
                        }
                    }
                }

                Err(err) => {
                    error!("Failed to accept a vsock: {err}");
                    None
                }
            }
        }
    });

    Ok(stream)
}

pub async fn tls_connect(
    cid: u32,
    port: u32,
    name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
) -> Result<TlsClientStream> {
    let stream = VsockStream::connect(cid, port).await?;
    let connector = TlsConnector::from(tls_config);
    let tls_stream = connector.connect(name, stream).await?;
    Ok(tls_stream)
}
