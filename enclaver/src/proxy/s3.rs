use anyhow::{anyhow, Result};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use base64::{engine::general_purpose, Engine as _};
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
    pub fn new(client: S3Client, bucket: String, mut prefix: String) -> Self {
        // Ensure prefix ends with a slash to prevent collision (e.g. app1/ vs app10/)
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
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

    /// Build full S3 key with app-specific prefix for isolation.
    /// Returns an error if the key attempts path traversal (e.g. contains "..").
    pub fn build_key(&self, key: &str) -> Result<String> {
        if key.contains("..") || key.starts_with('/') {
            return Err(anyhow!("Invalid key: path traversal or absolute path not allowed"));
        }
        Ok(format!("{}{}", self.prefix, key))
    }

    pub async fn handle_get(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3GetRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key)?;

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
                    value: general_purpose::STANDARD.encode(&data),
                };
                Ok(http_util::ok_json(&response)?)
            }
            Err(err) => {
                if let Some(s3_err) = err.as_service_error()
                    && s3_err.is_no_such_key()
                {
                    return Ok(http_util::not_found());
                }
                Ok(http_util::bad_request(format!("S3 error: {}", err)))
            }
        }
    }

    pub async fn handle_put(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3PutRequest = serde_json::from_slice(&body)?;
        let data = general_purpose::STANDARD.decode(&req.value)
            .map_err(|e| anyhow!("Invalid base64 value: {}", e))?;

        let full_key = self.build_key(&req.key)?;

        let mut put_request = self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .body(ByteStream::from(data));

        if let Some(ct) = &req.content_type {
            put_request = put_request.content_type(ct);
        }

        match put_request.send().await {
            Ok(_) => Ok(http_util::ok_json(&S3PutResponse { success: true })?),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn handle_delete(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3DeleteRequest = serde_json::from_slice(&body)?;
        let full_key = self.build_key(&req.key)?;

        match self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
        {
            Ok(_) => Ok(http_util::ok_json(&serde_json::json!({ "success": true }))?),
            Err(err) => Ok(http_util::bad_request(format!("S3 error: {}", err))),
        }
    }

    pub async fn handle_list(&self, body: Bytes) -> Result<Response<Full<Bytes>>> {
        let req: S3ListRequest = serde_json::from_slice(&body)?;
        let user_prefix = req.prefix.as_deref().unwrap_or("");
        let full_prefix = self.build_key(user_prefix)?;

        let mut list_request = self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix);

        if let Some(token) = req.continuation_token {
            list_request = list_request.continuation_token(token);
        }

        if let Some(max_keys) = req.max_keys {
            list_request = list_request.max_keys(max_keys as i32);
        }

        match list_request.send().await {
            Ok(output) => {
                let keys: Vec<String> = output
                    .contents()
                    .iter()
                    .filter_map(|obj| {
                        obj.key().and_then(|k| {
                            k.strip_prefix(&self.prefix).map(|s| s.to_string())
                        })
                    })
                    .collect();

                Ok(http_util::ok_json(&S3ListResponse {
                    keys,
                    continuation_token: output.next_continuation_token().map(|s| s.to_string()),
                    is_truncated: output.is_truncated().unwrap_or(false),
                })?)
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
    continuation_token: Option<String>,
    max_keys: Option<usize>,
}

#[derive(Serialize)]
struct S3ListResponse {
    keys: Vec<String>,
    continuation_token: Option<String>,
    is_truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::config::{BehaviorVersion, Config};
    
    fn mock_proxy(prefix: &str) -> S3Proxy {
        let config = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .build();
        let client = S3Client::from_conf(config);
        S3Proxy::new(client, "test-bucket".to_string(), prefix.to_string())
    }

    #[test]
    fn test_build_key() {
        let proxy = mock_proxy("apps/my-app/");
        assert_eq!(proxy.build_key("config.json").unwrap(), "apps/my-app/config.json");
        assert_eq!(proxy.build_key("data/file.txt").unwrap(), "apps/my-app/data/file.txt");
    }

    #[test]
    fn test_prefix_slash_enforcement() {
        // Should automatically add trailing slash
        let proxy = mock_proxy("apps/my-app");
        assert_eq!(proxy.prefix(), "apps/my-app/");
        assert_eq!(proxy.build_key("test").unwrap(), "apps/my-app/test");
        
        // Should handle empty prefix
        let proxy = mock_proxy("");
        assert_eq!(proxy.prefix(), "");
        assert_eq!(proxy.build_key("test").unwrap(), "test");
    }

    #[test]
    fn test_path_traversal_protection() {
        let proxy = mock_proxy("apps/my-app/");
        
        // These should fail
        assert!(proxy.build_key("../secret").is_err());
        assert!(proxy.build_key("data/../../secret").is_err());
        assert!(proxy.build_key("/absolute/path").is_err());
        
        // These should succeed
        assert!(proxy.build_key("normal.txt").is_ok());
        assert!(proxy.build_key("dir/file").is_ok());
    }
}
