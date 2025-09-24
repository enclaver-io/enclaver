use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use crate::{utils, vsock};
use anyhow::Result;
use futures::{Stream, StreamExt};
use log::{debug, error};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_vsock::VsockStream;

use crate::vsock::TlsServerStream;

// The enclave side of the proxy. Listens on a vsock and
// connects over the localhost to the app. The connection
// over vsock is over the TLS. EnclaveProxy terminates the
// TLS and connects out to the app over plain TCP.
pub struct EnclaveProxy<S> {
    incoming: Box<dyn Stream<Item = S> + Send>,
    port: u16,
}

impl EnclaveProxy<VsockStream> {
    pub fn bind(port: u16) -> Result<EnclaveProxy<VsockStream>> {
        let incoming = vsock::serve(port as u32)?;
        Ok(Self {
            incoming: Box::new(incoming),
            port,
        })
    }
}

impl EnclaveProxy<TlsServerStream> {
    pub fn bind_tls(
        port: u16,
        tls_config: Arc<ServerConfig>,
    ) -> Result<EnclaveProxy<TlsServerStream>> {
        let incoming = vsock::tls_serve(port as u32, tls_config)?;
        Ok(Self {
            incoming: Box::new(incoming),
            port,
        })
    }
}

impl<S> EnclaveProxy<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn serve(self, mut shutdown: watch::Receiver<()>) {
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port);
        let mut incoming = Box::into_pin(self.incoming);

        let mut proxies = Vec::new();
        loop {
            tokio::select!(
                Some(stream) = incoming.next() => {
                    proxies.push(
                        utils::spawn!("ingress stream", async move {
                            EnclaveProxy::service_conn(stream, addr).await;
                        })
                            .expect("spawn ingress stream"),
                    )
                }
                Ok(()) = shutdown.changed() => break,
            )
        }
        futures::future::join_all(proxies).await;
    }

    async fn service_conn(mut vsock: S, target: SocketAddrV4) {
        debug!("Connecting to {target}");
        match TcpStream::connect(&target).await {
            Ok(mut tcp) => {
                debug!("Connected to {target}, proxying data");
                _ = tokio::io::copy_bidirectional(&mut vsock, &mut tcp).await;
            }
            Err(err) => error!("Connection to upstream ({target}) failed: {err}"),
        }
    }
}

// The host side of the proxy. Listens on the localhost and connects
// out to the vsock. The proxied connection will be over TLS but HostProxy
// just proxies raw bytes (no TLS termination)
pub struct HostProxy {
    listener: TcpListener,
}

impl HostProxy {
    pub async fn bind(port: u16) -> Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub async fn serve(self, target_cid: u32, target_port: u32) {
        while let Ok((sock, _)) = self.listener.accept().await {
            // TODO: don't use detached tasks
            utils::spawn!(&format!("host proxy ({target_port})"), async move {
                HostProxy::service_conn(sock, target_cid, target_port).await;
            })
            .expect("spawn host proxy");
        }
    }

    async fn service_conn(mut tcp: TcpStream, target_cid: u32, target_port: u32) {
        debug!("Connecting to CID={target_cid} port={target_port}");
        match VsockStream::connect(target_cid, target_port).await {
            Ok(mut vsock) => {
                debug!("Connected to {target_port}:{target_cid}, proxying data");
                _ = tokio::io::copy_bidirectional(&mut vsock, &mut tcp).await;
            }
            Err(err) => {
                error!("Connection to upstream vsock ({target_cid}:{target_port}) failed: {err}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use assert2::assert;
    use rand::RngCore;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch::Sender;
    use tokio::task::JoinHandle;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, ServerConfig};
    use tokio_rustls::TlsConnector;

    use super::{EnclaveProxy, HostProxy};

    struct TcpEchoServer {
        listener: TcpListener,
    }

    impl TcpEchoServer {
        async fn bind(port: u16) -> Result<Self> {
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            Ok(Self {
                listener: TcpListener::bind(addr).await?,
            })
        }

        async fn serve(&mut self) {
            while let Ok((mut sock, _)) = self.listener.accept().await {
                tokio::task::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        }
    }

    fn random_bytes(count: usize) -> Vec<u8> {
        let mut v = vec![0u8; count];
        rand::thread_rng().fill_bytes(&mut v);
        v
    }

    fn start_enclave_proxy(port: u16, cfg: Arc<ServerConfig>) -> (JoinHandle<()>, Sender<()>) {
        let proxy = EnclaveProxy::bind_tls(port, cfg).unwrap();
        let (tx, rx) = tokio::sync::watch::channel(());
        let handle = tokio::task::spawn(async move {
            proxy.serve(rx).await;
        });
        (handle, tx)
    }

    async fn start_host_proxy(host_port: u16, enclave_port: u32) -> JoinHandle<()> {
        let proxy = HostProxy::bind(host_port).await.unwrap();
        tokio::task::spawn(async move {
            proxy
                .serve(crate::vsock::VMADDR_CID_HOST, enclave_port)
                .await;
        })
    }

    fn start_source<W: AsyncWrite + Send + Unpin + 'static>(mut w: W) -> JoinHandle<u64> {
        tokio::task::spawn(async move {
            let mut hasher = DefaultHasher::new();
            for _ in 0..1000 {
                let buf = random_bytes(4096);
                hasher.write(&buf);
                w.write_all(&buf).await.expect("write_all failed");
            }
            w.shutdown().await.expect("shutdown failed");

            hasher.finish()
        })
    }

    fn start_sink<R: AsyncRead + Send + Unpin + 'static>(mut r: R) -> JoinHandle<u64> {
        tokio::task::spawn(async move {
            let mut hasher = DefaultHasher::new();
            let mut buf = vec![0u8; 1024];
            while let Ok(nread) = r.read(&mut buf).await {
                if nread == 0 {
                    break;
                }
                hasher.write(&buf[..nread]);
            }
            hasher.finish()
        })
    }

    #[tokio::test]
    async fn test_enclave_proxy() {
        const PORT: u16 = 7777;

        let server_config = crate::tls::test_server_config().unwrap();
        let (proxy_task, proxy_stop) = start_enclave_proxy(PORT, server_config);

        // start a simple TCP echo server
        let mut echo = TcpEchoServer::bind(PORT)
            .await
            .expect("bind for the echo server failed");
        let echo_task = tokio::task::spawn(async move {
            echo.serve().await;
        });

        // connect to the proxy and send a stream of random bytes
        // and make sure it comes back the same (via a hash)
        let client_config =
            crate::tls::load_insecure_client_config().expect("client config load failed");
        let server_name = ServerName::try_from("test.local").expect("invalid server name");
        let conn = crate::vsock::tls_connect(
            crate::vsock::VMADDR_CID_HOST,
            PORT as u32,
            server_name,
            client_config,
        )
        .await
        .expect("connect failed");
        let (r, w) = tokio::io::split(conn);

        let (expected, actual) = tokio::join!(start_source(w), start_sink(r));
        let (expected, actual) = (expected.unwrap(), actual.unwrap());
        assert!(expected == actual);

        echo_task.abort();
        _ = echo_task.await;

        _ = proxy_stop.send(());
        _ = proxy_task.await;
    }

    //type TlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;
    type TlsClientStream = tokio_rustls::client::TlsStream<TcpStream>;

    async fn tls_connect(
        host: Ipv4Addr,
        port: u16,
        name: ServerName<'static>,
        cfg: Arc<ClientConfig>,
    ) -> Result<TlsClientStream> {
        let addr = SocketAddrV4::new(host, port);
        let stream = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(cfg);
        let tls_stream = connector.connect(name, stream).await?;
        Ok(tls_stream)
    }

    #[tokio::test]
    async fn test_full_proxy() {
        const PORT: u16 = 7787;

        let server_config = crate::tls::test_server_config().unwrap();
        let (enclave_proxy_task, enclave_proxy_stop) = start_enclave_proxy(PORT + 1, server_config);
        let host_proxy_task = start_host_proxy(PORT, (PORT + 1) as u32).await;

        // start a simple TCP echo server
        let mut echo = TcpEchoServer::bind(PORT + 1)
            .await
            .expect("bind for the echo server failed");
        let echo_task = tokio::task::spawn(async move {
            echo.serve().await;
        });

        // connect to the proxy and send a stream of random bytes
        // and make sure it comes back the same (via a hash)
        let client_config =
            crate::tls::load_insecure_client_config().expect("client config load failed");
        let server_name = ServerName::try_from("test.local").expect("invalid server name");
        let conn = tls_connect(Ipv4Addr::LOCALHOST, PORT, server_name, client_config)
            .await
            .expect("connect failed");
        let (r, w) = tokio::io::split(conn);

        let (expected, actual) = tokio::join!(start_source(w), start_sink(r));
        let (expected, actual) = (expected.unwrap(), actual.unwrap());
        assert!(expected == actual);

        echo_task.abort();
        _ = echo_task.await;

        _ = enclave_proxy_stop.send(());
        _ = enclave_proxy_task.await;

        host_proxy_task.abort();
        _ = host_proxy_task.await;
    }
}
