use std::sync::Arc;

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use http::Uri;
use http_body_util::BodyExt;
use hyper::body::Bytes;

use aws_config::imds;
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_config::imds::region::ImdsRegionProvider;
use aws_config::provider_config::ProviderConfig;
use aws_types::sdk_config::{SdkConfig, SharedCredentialsProvider, SharedHttpClient};

use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_runtime_api::http::Request;
use aws_smithy_types::body::SdkBody;

use crate::http_client::HttpProxyClient;

const IMDS_URL: &str = "http://169.254.169.254:80/";

#[derive(Debug, Clone)]
pub struct ProxiedHttpClient(pub Arc<HttpProxyClient<SdkBody>>);

impl ProxiedHttpClient {
    pub fn new(proxy_uri: Uri) -> Self {
        Self(Arc::new(crate::http_client::new_http_proxy_client(
            proxy_uri,
        )))
    }
}

impl HttpClient for ProxiedHttpClient {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}

impl HttpConnector for ProxiedHttpClient {
    fn call(&self, request: Request) -> HttpConnectorFuture {
        let client = self.0.clone();
        let result = async move {
            let request = request.try_into_http1x().map_err(|err| ConnectorError::user(err.into()))?;
            let response = client.request(request).await.map_err(|err| ConnectorError::user(err.into()))?;
            let (head, body) = response.into_parts();
            body.collect()
                .await
                .map_err(|err| ConnectorError::user(err.into()))
                .and_then(|body| into_aws_response(head, body.to_bytes()))
        };

        HttpConnectorFuture::new(result)
    }
}

fn into_aws_response(
    head: hyper::http::response::Parts,
    body: Bytes,
) -> Result<aws_smithy_runtime_api::client::orchestrator::HttpResponse, ConnectorError> {
    let resp = http::Response::from_parts(head, body.into());
    aws_smithy_runtime_api::client::orchestrator::HttpResponse::try_from(resp)
        .map_err(|err| ConnectorError::user(err.into()))
}

pub fn new_proxied_client(proxy_uri: Uri) -> Result<SharedHttpClient> {
    let client = ProxiedHttpClient::new(proxy_uri);
    Ok(SharedHttpClient::new(client))
}

pub async fn imds_client_with_proxy(proxy_uri: Uri) -> Result<imds::Client> {
    let http_client = new_proxied_client(proxy_uri)?;

    let config = ProviderConfig::without_region().with_http_client(http_client);

    let client = imds::Client::builder()
        .configure(&config)
        .endpoint(IMDS_URL)
        .map_err(anyhow::Error::from_boxed)?
        .build();

    Ok(client)
}

pub async fn load_config_from_imds(imds_client: imds::Client) -> Result<SdkConfig> {
    let mut last_err = anyhow!("failed to fetch the region from IMDS");
    let mut retry_delay = std::time::Duration::from_millis(250);
    let max_attempts = 15;

    info!("Starting IMDS configuration fetch (max {} attempts)", max_attempts);

    for attempt in 0..max_attempts {
        if attempt > 0 {
            debug!("IMDS fetch attempt {} failed, retrying in {:?}...", attempt, retry_delay);
            tokio::time::sleep(retry_delay).await;
            retry_delay *= 2;
            if retry_delay > std::time::Duration::from_secs(3) {
                retry_delay = std::time::Duration::from_secs(3);
            }
        }

        let region_result = ImdsRegionProvider::builder()
            .imds_client(imds_client.clone())
            .build()
            .region()
            .await;

        if let Some(region) = region_result {
            info!("Successfully fetched region from IMDS: {}", region);
            let cred_provider = ImdsCredentialsProvider::builder()
                .imds_client(imds_client)
                .build();

            let config = SdkConfig::builder()
                .behavior_version(aws_config::BehaviorVersion::latest())
                .region(Some(region))
                .credentials_provider(SharedCredentialsProvider::new(cred_provider))
                .build();

            return Ok(config);
        } else {
            last_err = anyhow!("IMDS region provider returned None (attempt {})", attempt + 1);
        }
    }

    error!("Failed to fetch IMDS configuration after {} attempts: {}", max_attempts, last_err);
    Err(last_err)
}
