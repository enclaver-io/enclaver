use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[async_trait]
pub trait HttpHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>>;
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
                                let body = body.collect().await?;

                                let req_full =
                                    Request::from_parts(head, Full::new(body.to_bytes()));
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
