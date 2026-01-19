use anyhow::{anyhow, Result};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;
use serde::{Deserialize, Serialize};

use crate::http_util;

pub struct S3Proxy {
    client: S3Client,
    bucket: String,
    prefix: String,
}

impl S3Proxy {
    pub fn new(client: S3Client, bucket: String, prefix: String) -> Self {
        Self { client, bucket, prefix }
    }

    pub fn client(&self) -> &S3Client {
        &self.client
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Build full S3 key with app-specific prefix for isolation
    pub fn build_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }

    pub async fn handle_get(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3GetRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key);

        let result = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await;

        match result {
            Ok(output) => {
                let data = output.body.collect().await?.into_bytes();
                let response = S3GetResponse {
                    value: base64::encode(&data),
                };
                Ok(http_util::ok_json(&response))
            }
            Err(err) => {
                let err_str = err.to_string();
                if err_str.contains("NoSuchKey") {
                    Ok(http_util::not_found())
                } else {
                    Ok(http_util::bad_request(format!("S3 error: {}", err_str)))
                }
            }
        }
    }

    pub async fn handle_put(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3PutRequest = serde_json::from_slice(&body)?;
        let data = base64::decode(&req.value)
            .map_err(|e| anyhow!("Invalid base64 value: {}", e))?;

        let full_key = self.build_key(&req.key);

        let mut put_request = self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .body(ByteStream::from(data));

        if let Some(ct) = &req.content_type {
            put_request = put_request.content_type(ct);
        }

        match put_request.send().await {
            Ok(_) => Ok(http_util::ok_json(&S3PutResponse { success: true })),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn handle_delete(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3DeleteRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key);

        match self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
        {
            Ok(_) => Ok(http_util::ok_json(&serde_json::json!({ "success": true }))),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn handle_list(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3ListRequest = serde_json::from_slice(&body)?;
        let user_prefix = req.prefix.as_deref().unwrap_or("");
        let full_prefix = self.build_key(user_prefix);

        let list_request = self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix);

        match list_request.send().await {
            Ok(output) => {
                let keys: Vec<String> = output
                    .contents()
                    .iter()
                    .filter_map(|obj| {
                        obj.key().map(|k| {
                            k.strip_prefix(&self.prefix).unwrap_or(k).to_string()
                        })
                    })
                    .collect();

                Ok(http_util::ok_json(&S3ListResponse { keys }))
            }
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }
}

#[derive(Deserialize)]
struct S3GetRequest {
    key: String,
}

#[derive(Serialize)]
struct S3GetResponse {
    value: String,
}

#[derive(Deserialize)]
struct S3PutRequest {
    key: String,
    value: String,
    content_type: Option<String>,
}

#[derive(Serialize)]
struct S3PutResponse {
    success: bool,
}

#[derive(Deserialize)]
struct S3DeleteRequest {
    key: String,
}

#[derive(Deserialize)]
struct S3ListRequest {
    prefix: Option<String>,
}

#[derive(Serialize)]
struct S3ListResponse {
    keys: Vec<String>,
}
