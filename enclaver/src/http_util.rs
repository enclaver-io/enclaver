use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::BytesMut;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

#[async_trait]
pub trait HttpHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>>;

    fn max_request_body_bytes(&self) -> usize {
        DEFAULT_MAX_REQUEST_BODY_BYTES
    }
}

pub struct HttpServer {
    listener: TcpListener,
}

impl HttpServer {
    pub async fn bind(listen_port: u16) -> Result<Self> {
        let listen_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, listen_port));
        Ok(Self {
            listener: TcpListener::bind(&listen_addr).await?,
        })
    }

    pub async fn serve<H: HttpHandler + Send + Sync + 'static>(self, handler: H) -> Result<()> {
        let handler = Arc::new(handler);

        loop {
            let (stream, _) = self.listener.accept().await?;

            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let io = TokioIo::new(stream);

            let handler = handler.clone();

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                    // `service_fn` converts our function in a `Service`
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<Incoming>| {
                            let handler = handler.clone(); // Clone before moving into async block
                            async move {
                                let (head, body) = req.into_parts();
                                let body = match collect_request_body_with_limit(
                                    body,
                                    handler.max_request_body_bytes(),
                                )
                                .await
                                {
                                    Ok(body) => body,
                                    Err(err) => {
                                        let message = err.to_string();
                                        let response = if message.contains("request body exceeds") {
                                            payload_too_large(message)
                                        } else {
                                            bad_request(message)
                                        };
                                        return Ok(response);
                                    }
                                };

                                let req_full = Request::from_parts(head, Full::new(body));
                                handler.handle(req_full).await
                            }
                        }),
                    )
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn collect_request_body_with_limit(body: Incoming, max_bytes: usize) -> Result<Bytes> {
    let mut body = body;
    let mut out = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(chunk) = frame.data_ref() {
            let next_len = out.len().saturating_add(chunk.len());
            if next_len > max_bytes {
                return Err(anyhow!(
                    "request body exceeds {} bytes (received at least {})",
                    max_bytes,
                    next_len
                ));
            }
            out.extend_from_slice(chunk);
        }
    }
    Ok(out.freeze())
}

pub fn internal_srv_err(msg: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(msg)))
        .unwrap()
}

pub fn bad_request(msg: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Full::new(Bytes::from(msg)))
        .unwrap()
}

pub fn payload_too_large(msg: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(Full::new(Bytes::from(msg)))
        .unwrap()
}

pub fn method_not_allowed() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

pub fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

pub fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(body)?)))?)
}

pub fn ok_json<T: serde::Serialize>(body: &T) -> Result<Response<Full<Bytes>>> {
    json_response(StatusCode::OK, body)
}
