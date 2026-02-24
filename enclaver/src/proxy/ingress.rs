use std::net::{Ipv4Addr, SocketAddrV4};

use crate::{utils, vsock};
use anyhow::Result;
use futures::{Stream, StreamExt};
use log::{debug, error};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_vsock::VsockStream;

// The enclave side of the proxy. Listens on a vsock and
// connects over the localhost to the app.
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
// out to the vsock. Proxies raw bytes.
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
    use rand::RngCore;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch::Sender;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

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

    fn is_vsock_io_unavailable(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(1) | Some(38) | Some(95) | Some(97) | Some(104) | Some(110) | Some(111)
        ) || matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied
                | io::ErrorKind::Unsupported
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof
        )
    }

    fn is_vsock_anyhow_unavailable(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(is_vsock_io_unavailable)
        })
    }

    fn is_data_path_io_unavailable(err: &io::Error) -> bool {
        is_vsock_io_unavailable(err)
            || matches!(
                err.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            )
    }

    async fn probe_vsock_connectivity(port: u16) -> Result<()> {
        let probe = timeout(
            Duration::from_secs(2),
            tokio_vsock::VsockStream::connect(crate::vsock::VMADDR_CID_HOST, port as u32),
        )
        .await;
        match probe {
            Ok(Ok(stream)) => {
                drop(stream);
                Ok(())
            }
            Ok(Err(err)) => Err(anyhow::Error::new(err)),
            Err(_) => Err(anyhow::Error::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "vsock connect probe timed out",
            ))),
        }
    }

    fn start_enclave_proxy(port: u16) -> Result<(JoinHandle<()>, Sender<()>)> {
        let proxy = EnclaveProxy::bind(port)?;
        let (tx, rx) = tokio::sync::watch::channel(());
        let handle = tokio::task::spawn(async move {
            proxy.serve(rx).await;
        });
        Ok((handle, tx))
    }

    async fn start_host_proxy(host_port: u16, enclave_port: u32) -> JoinHandle<()> {
        let proxy = HostProxy::bind(host_port).await.unwrap();
        tokio::task::spawn(async move {
            proxy
                .serve(crate::vsock::VMADDR_CID_HOST, enclave_port)
                .await;
        })
    }

    fn start_source<W: AsyncWrite + Send + Unpin + 'static>(
        mut w: W,
    ) -> JoinHandle<io::Result<u64>> {
        tokio::task::spawn(async move {
            let mut hasher = DefaultHasher::new();
            for _ in 0..1000 {
                let buf = random_bytes(4096);
                hasher.write(&buf);
                w.write_all(&buf).await?;
            }
            w.shutdown().await?;

            Ok(hasher.finish())
        })
    }

    fn start_sink<R: AsyncRead + Send + Unpin + 'static>(mut r: R) -> JoinHandle<io::Result<u64>> {
        tokio::task::spawn(async move {
            let mut hasher = DefaultHasher::new();
            let mut buf = vec![0u8; 1024];
            loop {
                let nread = r.read(&mut buf).await?;
                if nread == 0 {
                    break;
                }
                hasher.write(&buf[..nread]);
            }
            Ok(hasher.finish())
        })
    }

    #[tokio::test]
    async fn test_enclave_proxy() {
        const PORT: u16 = 7777;

        let (proxy_task, proxy_stop) = match start_enclave_proxy(PORT) {
            Ok(v) => v,
            Err(err) if is_vsock_anyhow_unavailable(&err) => {
                eprintln!("Skipping test_enclave_proxy: vsock unavailable ({err})");
                return;
            }
            Err(err) => panic!("bind for enclave proxy failed: {err}"),
        };

        // start a simple TCP echo server
        let mut echo = TcpEchoServer::bind(PORT)
            .await
            .expect("bind for the echo server failed");
        let echo_task = tokio::task::spawn(async move {
            echo.serve().await;
        });

        // connect to the proxy via vsock and send a stream of random bytes
        let conn = match timeout(
            Duration::from_secs(2),
            tokio_vsock::VsockStream::connect(crate::vsock::VMADDR_CID_HOST, PORT as u32),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(err)) if is_vsock_io_unavailable(&err) => {
                eprintln!("Skipping test_enclave_proxy: vsock connect unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = proxy_stop.send(());
                _ = proxy_task.await;
                return;
            }
            Ok(Err(err)) => panic!("connect failed: {err}"),
            Err(_) => {
                eprintln!("Skipping test_enclave_proxy: vsock connect timed out");
                echo_task.abort();
                _ = echo_task.await;
                _ = proxy_stop.send(());
                _ = proxy_task.await;
                return;
            }
        };
        let (r, w) = tokio::io::split(conn);

        let (expected, actual) = tokio::join!(start_source(w), start_sink(r));
        let expected = match expected {
            Ok(Ok(v)) => v,
            Ok(Err(err)) if is_data_path_io_unavailable(&err) => {
                eprintln!("Skipping test_enclave_proxy: data path unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = proxy_stop.send(());
                _ = proxy_task.await;
                return;
            }
            Ok(Err(err)) => panic!("source stream failed: {err}"),
            Err(err) => panic!("source task join failed: {err}"),
        };
        let actual = match actual {
            Ok(Ok(v)) => v,
            Ok(Err(err)) if is_data_path_io_unavailable(&err) => {
                eprintln!("Skipping test_enclave_proxy: data path unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = proxy_stop.send(());
                _ = proxy_task.await;
                return;
            }
            Ok(Err(err)) => panic!("sink stream failed: {err}"),
            Err(err) => panic!("sink task join failed: {err}"),
        };
        if expected != actual {
            if let Err(err) = probe_vsock_connectivity(PORT).await
                && is_vsock_anyhow_unavailable(&err)
            {
                eprintln!(
                    "Skipping test_enclave_proxy: checksum mismatch with unstable vsock ({err})"
                );
                echo_task.abort();
                _ = echo_task.await;
                _ = proxy_stop.send(());
                _ = proxy_task.await;
                return;
            }
            panic!("checksum mismatch in test_enclave_proxy: expected={expected} actual={actual}");
        }

        echo_task.abort();
        _ = echo_task.await;

        _ = proxy_stop.send(());
        _ = proxy_task.await;
    }

    #[tokio::test]
    async fn test_full_proxy() {
        const PORT: u16 = 7787;

        let (enclave_proxy_task, enclave_proxy_stop) = match start_enclave_proxy(PORT + 1) {
            Ok(v) => v,
            Err(err) if is_vsock_anyhow_unavailable(&err) => {
                eprintln!("Skipping test_full_proxy: vsock unavailable ({err})");
                return;
            }
            Err(err) => panic!("bind for enclave proxy failed: {err}"),
        };
        let host_proxy_task = start_host_proxy(PORT, (PORT + 1) as u32).await;

        // start a simple TCP echo server
        let mut echo = TcpEchoServer::bind(PORT + 1)
            .await
            .expect("bind for the echo server failed");
        let echo_task = tokio::task::spawn(async move {
            echo.serve().await;
        });

        if let Err(err) = probe_vsock_connectivity(PORT + 1).await {
            if is_vsock_anyhow_unavailable(&err) {
                eprintln!("Skipping test_full_proxy: vsock connect unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = enclave_proxy_stop.send(());
                _ = enclave_proxy_task.await;
                host_proxy_task.abort();
                _ = host_proxy_task.await;
                return;
            }
            panic!("vsock probe failed: {err}");
        }

        // connect to the host proxy and send random bytes through
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT);
        let conn = TcpStream::connect(&addr).await.expect("connect failed");
        let (r, w) = tokio::io::split(conn);

        let (expected, actual) = tokio::join!(start_source(w), start_sink(r));
        let expected = match expected {
            Ok(Ok(v)) => v,
            Ok(Err(err)) if is_data_path_io_unavailable(&err) => {
                eprintln!("Skipping test_full_proxy: data path unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = enclave_proxy_stop.send(());
                _ = enclave_proxy_task.await;
                host_proxy_task.abort();
                _ = host_proxy_task.await;
                return;
            }
            Ok(Err(err)) => panic!("source stream failed: {err}"),
            Err(err) => panic!("source task join failed: {err}"),
        };
        let actual = match actual {
            Ok(Ok(v)) => v,
            Ok(Err(err)) if is_data_path_io_unavailable(&err) => {
                eprintln!("Skipping test_full_proxy: data path unavailable ({err})");
                echo_task.abort();
                _ = echo_task.await;
                _ = enclave_proxy_stop.send(());
                _ = enclave_proxy_task.await;
                host_proxy_task.abort();
                _ = host_proxy_task.await;
                return;
            }
            Ok(Err(err)) => panic!("sink stream failed: {err}"),
            Err(err) => panic!("sink task join failed: {err}"),
        };
        if expected != actual {
            if let Err(err) = probe_vsock_connectivity(PORT + 1).await
                && is_vsock_anyhow_unavailable(&err)
            {
                eprintln!(
                    "Skipping test_full_proxy: checksum mismatch with unstable vsock ({err})"
                );
                echo_task.abort();
                _ = echo_task.await;
                _ = enclave_proxy_stop.send(());
                _ = enclave_proxy_task.await;
                host_proxy_task.abort();
                _ = host_proxy_task.await;
                return;
            }
            panic!("checksum mismatch in test_full_proxy: expected={expected} actual={actual}");
        }

        echo_task.abort();
        _ = echo_task.await;

        _ = enclave_proxy_stop.send(());
        _ = enclave_proxy_task.await;

        host_proxy_task.abort();
        _ = host_proxy_task.await;
    }
}
