use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use crate::utils;
use anyhow::anyhow;
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::Full;
use hyper::body::{Body, Bytes, Incoming};
use hyper::client::conn::http1 as http1_client;
use hyper::header::HeaderValue;
use hyper::http::uri::PathAndQuery;
use hyper::server::conn::http1 as http1_server;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::VsockStream;

use crate::policy::EgressPolicy;

#[async_trait]
trait JsonTransport: Sized + Sync {
    async fn send<W: AsyncWrite + Unpin + Send>(&self, w: &mut W) -> anyhow::Result<()>;
    async fn recv<R: AsyncRead + Unpin + Send>(r: &mut R) -> anyhow::Result<Self>;
}

#[async_trait]
impl<M: Serialize + DeserializeOwned + Sync> JsonTransport for M {
    async fn send<W: AsyncWrite + Unpin + Send>(&self, w: &mut W) -> anyhow::Result<()> {
        // Frame and serialize
        // use JSON serialization to avoid pulling in another dependency
        let msg = serde_json::to_vec(self)?;
        // frame it by a 2 byte length
        let len = msg.len() as u16;
        let mut pkt = Vec::with_capacity(2 + msg.len());
        pkt.extend_from_slice(&len.to_le_bytes());
        pkt.extend_from_slice(&msg);
        w.write_all(&pkt).await?;
        Ok(())
    }

    async fn recv<R: AsyncRead + Unpin + Send>(r: &mut R) -> anyhow::Result<Self> {
        let mut len_buf = [0u8; 2];
        r.read_exact(&mut len_buf).await?;
        let len = u16::from_le_bytes(len_buf);

        let mut msg = vec![0u8; len as usize];
        r.read_exact(&mut msg).await?;

        let req: Self = serde_json::from_slice(&msg)?;
        Ok(req)
    }
}

#[derive(Serialize, Deserialize)]
struct ConnectRequest {
    host: String,
    port: u16,
}

impl ConnectRequest {
    fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

#[derive(Serialize, Deserialize)]
enum ConnectResponse {
    Ok,
    Err { os_code: i32, message: String },
}

impl ConnectResponse {
    fn failed(err: &std::io::Error) -> Self {
        Self::Err {
            os_code: err.raw_os_error().unwrap_or(0i32),
            message: err.to_string(),
        }
    }
}

pub struct EnclaveHttpProxy {
    listener: TcpListener,
}

impl EnclaveHttpProxy {
    pub async fn bind(port: u16) -> anyhow::Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub async fn serve(self, egress_port: u32, egress_policy: Arc<EgressPolicy>) {
        loop {
            match self.listener.accept().await {
                Ok((sock, _)) => {
                    let egress_policy = egress_policy.clone();

                    utils::spawn!("egress stream", async move {
                        EnclaveHttpProxy::service_conn(sock, egress_port, egress_policy).await;
                    })
                    .expect("spawn egress stream");
                }
                Err(err) => {
                    error!("Accept failed: {err}");
                }
            }
        }
    }

    async fn service_conn(tcp: TcpStream, egress_port: u32, egress_policy: Arc<EgressPolicy>) {
        let svc = service_fn(move |req| {
            let egress_policy = egress_policy.clone();
            async move { proxy(egress_port, req, &egress_policy).await }
        });

        let io = TokioIo::new(tcp);

        if let Err(err) = http1_server::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, svc)
            .with_upgrades()
            .await
        {
            error!("Failed to serve connection: {err}");
        }
    }
}

pub struct HostHttpProxy {
    incoming: Box<dyn Stream<Item = VsockStream> + Unpin + Send>,
}

impl HostHttpProxy {
    pub fn bind(egress_port: u32) -> anyhow::Result<Self> {
        Ok(Self {
            incoming: Box::new(crate::vsock::serve(egress_port)?),
        })
    }

    pub async fn serve(self) {
        let mut incoming = Box::into_pin(self.incoming);

        while let Some(stream) = incoming.next().await {
            tokio::task::spawn(async move {
                if let Err(err) = HostHttpProxy::service_conn(stream).await {
                    error!("{err}");
                }
            });
        }
    }

    async fn service_conn(mut vsock: VsockStream) -> anyhow::Result<()> {
        let conn_req = ConnectRequest::recv(&mut vsock).await?;

        // A special hostname "host" refers to the localhost on the outside
        // of the enclave.
        let host = if conn_req
            .host
            .eq_ignore_ascii_case(crate::constants::OUTSIDE_HOST)
        {
            "127.0.0.1".to_string()
        } else {
            conn_req.host
        };

        match TcpStream::connect((host.as_ref(), conn_req.port)).await {
            Ok(mut tcp) => {
                ConnectResponse::Ok.send(&mut vsock).await?;

                debug!(
                    "Connected to {}:{}, starting to proxy bytes",
                    host, conn_req.port
                );
                _ = tokio::io::copy_bidirectional(&mut vsock, &mut tcp).await;
            }
            Err(err) => {
                ConnectResponse::failed(&err).send(&mut vsock).await?;
            }
        }

        Ok(())
    }
}

async fn proxy(
    egress_port: u32,
    req: Request<Incoming>,
    egress_policy: &EgressPolicy,
) -> anyhow::Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    if Method::CONNECT == req.method() {
        let resp = handle_connect(egress_port, req, egress_policy).await;
        Ok(with_boxed_body(resp))
    } else {
        match handle_request(egress_port, req, egress_policy).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                let resp = err_resp(StatusCode::SERVICE_UNAVAILABLE, err.to_string());
                Ok(with_boxed_body(resp))
            }
        }
    }
}

fn with_boxed_body<B>(resp: Response<B>) -> Response<BoxBody<Bytes, anyhow::Error>>
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    <B as hyper::body::Body>::Error: std::error::Error + Send + Sync,
{
    use http_body_util::BodyExt;

    let (head, body) = resp.into_parts();
    let body = body.map_err(anyhow::Error::new).boxed();
    Response::from_parts(head, body)
}

async fn handle_connect(
    egress_port: u32,
    req: Request<Incoming>,
    egress_policy: &EgressPolicy,
) -> Response<Full<Bytes>> {
    match req.uri().authority() {
        Some(authority) => {
            let port = match authority.port() {
                Some(port) => port.as_u16(),
                None => {
                    let err_msg = "CONNECT address is missing a port";
                    error!("{err_msg}");
                    return bad_request(err_msg.to_string());
                }
            };

            // Check the policy
            if !egress_policy.is_host_allowed(authority.host()) {
                return blocked();
            }

            debug!("Handling CONNECT to {}:{port}", authority.host());

            // Connect to remote server before the upgrade so we can return an error if it fails
            let mut remote = match remote_connect(egress_port, authority.host(), port).await {
                Ok(remote) => remote,
                Err(err) => return err_resp(StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
            };

            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut io = TokioIo::new(upgraded);
                        _ = tokio::io::copy_bidirectional(&mut io, &mut remote).await;
                    }
                    Err(err) => {
                        error!("Upgrade failed: {err}");
                    }
                }
            });

            Response::new(Full::new(Bytes::new()))
        }
        None => {
            let err_msg = format!("CONNECT host is not a socket addr: {:?}", req.uri());
            error!("{err_msg}");
            bad_request(err_msg)
        }
    }
}

async fn handle_request(
    egress_port: u32,
    mut req: Request<Incoming>,
    egress_policy: &EgressPolicy,
) -> anyhow::Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    let host = match req.uri().host() {
        Some(host) => host,
        None => {
            return Ok(with_boxed_body(bad_request(
                "URI is missing a host".to_string(),
            )))
        }
    };
    let port = req.uri().port_u16().unwrap_or(80);

    // Check the policy
    if !egress_policy.is_host_allowed(host) {
        return Ok(with_boxed_body(blocked()));
    }

    // TODO: pool connections
    let stream = remote_connect(egress_port, host, port).await?;
    let io = TokioIo::new(stream);

    // Set the Host: header to match the URL
    let host_hdr = match req.uri().port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    req.headers_mut()
        .insert(hyper::header::HOST, HeaderValue::from_str(&host_hdr)?);

    // If a proxy receives an OPTIONS request with an absolute-form of
    // request-target in which the URI has an empty path and no query
    // component, then the last proxy on the request chain MUST send a
    // request-target of "*" when it forwards the request to the indicated
    // origin server.
    let pq = if req.method() == Method::OPTIONS && is_empty(req.uri().path_and_query()) {
        PathAndQuery::from_static("*")
    } else {
        // Convert the absolute-form into origin-form
        match req.uri().path_and_query() {
            Some(pq) => pq.clone(),
            None => PathAndQuery::from_static("/"),
        }
    };

    *req.uri_mut() = hyper::http::Uri::builder().path_and_query(pq).build()?;

    let (mut sender, conn) = http1_client::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;

    // Spawning detached here is not ideal but the right thing to do
    // according to the docs
    tokio::task::spawn(async move {
        _ = conn.await;
    });

    Ok(with_boxed_body(sender.send_request(req).await?))
}

fn err_resp(status: StatusCode, msg: String) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(msg)));
    *resp.status_mut() = status;
    resp
}

fn bad_request(msg: String) -> Response<Full<Bytes>> {
    err_resp(StatusCode::BAD_REQUEST, msg)
}

fn blocked() -> Response<Full<Bytes>> {
    err_resp(
        StatusCode::UNAUTHORIZED,
        "blocked by egress security policy".to_string(),
    )
}

fn is_empty(pq: Option<&PathAndQuery>) -> bool {
    if let Some(pq) = pq {
        if pq.path() != "/" {
            return false;
        }

        match pq.query() {
            Some(q) => q.is_empty(),
            None => true,
        }
    } else {
        true
    }
}

// connects to the host via vsock and then asks it to
// connect to the remote address
async fn remote_connect(egress_port: u32, host: &str, port: u16) -> anyhow::Result<VsockStream> {
    let mut vsock = VsockStream::connect(crate::vsock::VMADDR_CID_HOST, egress_port).await?;
    debug!(
        "Connected to vsock {}:{}, sending connect request",
        crate::vsock::VMADDR_CID_HOST,
        egress_port
    );

    ConnectRequest::new(host.to_string(), port)
        .send(&mut vsock)
        .await?;
    debug!("Sent request to connect to {host}:{port}");

    match ConnectResponse::recv(&mut vsock).await? {
        ConnectResponse::Ok => Ok(vsock),
        ConnectResponse::Err { os_code, message } => Err(anyhow!("os_err: {os_code}: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use http::{uri::PathAndQuery, Method, Version};
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1 as http1_server;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use rand::RngCore;
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tls_listener::TlsListener;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        assert!(req.method() == Method::POST);
        assert!(req.version() == Version::HTTP_11);
        assert!(req.uri().authority() == None);
        assert!(req.uri().path_and_query() == Some(&PathAndQuery::from_static("/echo")));

        let body = req.into_body().collect().await.unwrap();
        Ok(Response::new(Full::new(body.to_bytes())))
    }

    async fn echo_server(port: u16) -> anyhow::Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let listener = TcpListener::bind(addr).await?;
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        http1_server::Builder::new()
            .serve_connection(io, service_fn(echo))
            .await?;

        Ok(())
    }

    async fn tls_echo_server(port: u16) -> anyhow::Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let server_config = crate::tls::test_server_config().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let acceptor: tokio_rustls::TlsAcceptor = server_config.into();
        let mut incoming = TlsListener::new(acceptor, listener);

        let (stream, _) = incoming.accept().await?;

        let io = TokioIo::new(stream);

        http1_server::Builder::new()
            .serve_connection(io, service_fn(echo))
            .await?;

        Ok(())
    }

    fn start_echo_server(port: u16, use_tls: bool) -> JoinHandle<anyhow::Result<()>> {
        if !use_tls {
            tokio::task::spawn(echo_server(port))
        } else {
            tokio::task::spawn(tls_echo_server(port))
        }
    }

    async fn start_enclave_proxy(proxy_port: u16, egress_port: u32) -> JoinHandle<()> {
        let proxy = super::EnclaveHttpProxy::bind(proxy_port).await.unwrap();
        let policy = Arc::new(crate::policy::EgressPolicy::allow_all());
        tokio::task::spawn(async move {
            proxy.serve(egress_port, policy).await;
        })
    }

    fn start_host_proxy(egress_port: u32) -> JoinHandle<()> {
        let proxy = super::HostHttpProxy::bind(egress_port).unwrap();
        tokio::task::spawn(async move {
            proxy.serve().await;
        })
    }

    struct HttpProxyFixture {
        base_port: u16,
        host_proxy_task: JoinHandle<()>,
        enclave_proxy_task: JoinHandle<()>,
        echo_task: JoinHandle<anyhow::Result<()>>,
    }

    impl HttpProxyFixture {
        async fn start(base_port: u16, use_tls: bool) -> Self {
            _ = pretty_env_logger::try_init();

            return Self {
                base_port,
                enclave_proxy_task: start_enclave_proxy(base_port, base_port as u32).await,
                host_proxy_task: start_host_proxy(base_port as u32),
                echo_task: start_echo_server(base_port + 1, use_tls),
            };
        }

        fn proxy_uri(&self) -> http::Uri {
            format!("http://127.0.0.1:{}", self.base_port)
                .parse()
                .unwrap()
        }

        fn webserver_port(&self) -> u16 {
            self.base_port + 1
        }

        async fn stop(self) {
            self.echo_task.abort();
            _ = self.echo_task.await;

            self.enclave_proxy_task.abort();
            _ = self.enclave_proxy_task.await;

            self.host_proxy_task.abort();
            _ = self.host_proxy_task.await;
        }
    }

    fn random_bytes(count: usize) -> Vec<u8> {
        let mut v = vec![0u8; count];
        rand::thread_rng().fill_bytes(&mut v);
        v
    }

    #[tokio::test]
    async fn test_http_proxy() {
        let fixture = HttpProxyFixture::start(13000, false).await;

        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(fixture.proxy_uri().to_string()).unwrap())
            .build()
            .unwrap();

        let expected = random_bytes(128 * 1000);

        // 200 expected
        let resp1 = client
            .post(format!(
                "http://localhost:{}/echo",
                fixture.webserver_port()
            ))
            .body(expected.clone())
            .send()
            .await
            .unwrap();

        let actual = resp1.bytes().await.unwrap();

        assert!(&expected == &actual);

        // Connection failure
        let resp2 = client
            .post("http://adfadfadfadfadsfa.local/echo".to_string())
            .body(expected.clone())
            .send()
            .await
            .unwrap();

        assert!(resp2.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE);

        fixture.stop().await;
    }

    #[tokio::test]
    async fn test_https_proxy() {
        let fixture = HttpProxyFixture::start(14000, true).await;

        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(fixture.proxy_uri().to_string()).unwrap())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let expected = random_bytes(128 * 1000);

        let resp1 = client
            .post(format!(
                "https://localhost:{}/echo",
                fixture.webserver_port()
            ))
            .body(expected.clone())
            .send()
            .await
            .unwrap();

        let actual = resp1.bytes().await.unwrap();

        assert!(&expected == &actual);

        // Connection failure
        let resp_result = client
            .post("https://adfadfadfadfadsfa.local/echo".to_string())
            .body(expected.clone())
            .send()
            .await;

        assert!(resp_result.is_err());
        assert!(resp_result.unwrap_err().is_connect());

        fixture.stop().await;
    }
}
