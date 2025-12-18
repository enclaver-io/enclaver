use anyhow::Result;
use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

use crate::http_util::{self, HttpHandler};

type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub struct AuxApiHandler {
    internal_api_url: String,
    client: HttpClient,
}

impl AuxApiHandler {
    pub fn new(api_port: u16) -> Self {
        let internal_api_url = format!("http://127.0.0.1:{}", api_port);
        let connector = HttpConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(connector);

        Self {
            internal_api_url,
            client,
        }
    }

    async fn proxy_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<Response<Full<Bytes>>> {
        let uri = format!("{}{}", self.internal_api_url, path);
        let uri: Uri = uri.parse()?;

        let mut req_builder = Request::builder().method(method).uri(uri);

        // Forward Content-Type header if body is present
        if body.is_some() {
            req_builder = req_builder.header(CONTENT_TYPE, "application/json");
        }

        let body_bytes = body.unwrap_or_default();
        let req = req_builder.body(Full::new(body_bytes))?;

        match self.client.request(req).await {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                let body_bytes = body.collect().await?.to_bytes();

                let mut response_builder = Response::builder()
                    .status(parts.status)
                    .version(parts.version);

                // Copy headers from internal API response
                for (key, value) in parts.headers.iter() {
                    response_builder = response_builder.header(key, value.clone());
                }

                Ok(response_builder.body(Full::new(body_bytes))?)
            }
            Err(_) => {
                let response = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Internal API service unavailable"}"#,
                    )))?;
                Ok(response)
            }
        }
    }

    async fn handle_eth_address(&self) -> Result<Response<Full<Bytes>>> {
        self.proxy_request(Method::GET, "/v1/eth/address", None)
            .await
    }

    async fn handle_attestation(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        // Parse JSON body and filter only public_key (user_data is allowed, eth_addr will be injected by api.rs)
        let sanitized_body = match serde_json::from_slice::<Value>(&body) {
            Ok(mut json_value) => {
                // Remove public_key to prevent external callers from overriding defaults
                // user_data is allowed - api.rs will inject eth_addr into it
                if let Some(obj) = json_value.as_object_mut() {
                    obj.remove("public_key");
                }
                serde_json::to_vec(&json_value)?
            }
            Err(_) => {
                // If JSON is invalid and body is not empty, return bad request
                if !body.is_empty() {
                    return Ok(http_util::bad_request(
                        "Invalid JSON in request body".to_string(),
                    ));
                }
                // If body is empty, send empty object (will use defaults)
                serde_json::to_vec(&Value::Object(serde_json::Map::new()))?
            }
        };

        self.proxy_request(
            Method::POST,
            "/v1/attestation",
            Some(Bytes::from(sanitized_body)),
        )
        .await
    }

    fn cors_preflight_response(&self) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type")
            .header("Access-Control-Max-Age", "86400")
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn add_cors_headers(&self, response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
        let (mut parts, body) = response.into_parts();
        parts.headers.insert(
            "Access-Control-Allow-Origin",
            "*".parse().unwrap(),
        );
        Response::from_parts(parts, body)
    }

    async fn handle_attestation_with_cors(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let response = self.handle_attestation(body).await?;
        Ok(self.add_cors_headers(response))
    }

    async fn handle_encryption_public_key(&self) -> Result<Response<Full<Bytes>>> {
        self.proxy_request(Method::GET, "/v1/encryption/public_key", None)
            .await
    }

    async fn handle_request(
        &self,
        head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        match head.uri.path() {
            "/v1/eth/address" => match head.method {
                Method::GET => self.handle_eth_address().await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/attestation" => match head.method {
                Method::OPTIONS => Ok(self.cors_preflight_response()),
                Method::POST => self.handle_attestation_with_cors(body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/encryption/public_key" => match head.method {
                Method::GET => self.handle_encryption_public_key().await,
                _ => Ok(http_util::method_not_allowed()),
            },
            _ => Ok(http_util::not_found()),
        }
    }
}

#[async_trait]
impl HttpHandler for AuxApiHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        let (head, body) = req.into_parts();
        let body = body.collect().await?.to_bytes();

        self.handle_request(&head, body).await
    }
}

