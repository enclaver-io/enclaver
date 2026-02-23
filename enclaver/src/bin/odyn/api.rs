use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Region;
use enclaver::manifest::S3EncryptionMode;
use log::{info, warn};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::Configuration;
use enclaver::api::ApiHandler;
use enclaver::http_util::HttpServer;
use enclaver::nsm::{Nsm, NsmAttestationProvider};
use enclaver::proxy::nova_kms::NovaKmsProxy;
use enclaver::proxy::s3::S3Proxy;

pub struct ApiService {
    task: Option<JoinHandle<()>>,
    audit_archive_task: Option<JoinHandle<()>>,
}

impl ApiService {
    pub async fn start(config: &Configuration, nsm: Arc<Nsm>) -> Result<Self> {
        let mut audit_archive_task: Option<JoinHandle<()>> = None;
        let task = if let Some(port) = config.api_port() {
            info!("Starting API on port {port}");
            let odyn_endpoint = format!("http://127.0.0.1:{port}");

            // Create S3 proxy if S3 storage is configured
            let s3_proxy = if let Some(s3_config) = config.s3_config() {
                info!(
                    "S3 storage enabled: bucket={}, prefix={}",
                    s3_config.bucket, s3_config.prefix
                );

                // Load AWS config from IMDS (EC2 instance metadata) via proxy
                // inside an enclave, we MUST use a proxy to reach IMDS
                let proxy_uri = config.egress_proxy_uri().ok_or_else(|| {
                    anyhow::anyhow!("Egress proxy is not configured, but is required for AWS IMDS access inside the enclave.")
                })?;

                info!(
                    "Enclave environment detected: using egress proxy at {} for AWS configuration",
                    proxy_uri
                );

                let http_client = enclaver::proxy::aws_util::new_proxied_client(proxy_uri.clone())?;
                let imds = enclaver::proxy::aws_util::imds_client_with_proxy(proxy_uri).await?;

                // Small delay to ensure egress proxy is fully up and ready to handle vsock requests
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                let aws_config = enclaver::proxy::aws_util::load_config_from_imds(imds).await?;

                let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);
                s3_config_builder = s3_config_builder.http_client(http_client);

                if let Some(region) = &s3_config.region {
                    s3_config_builder = s3_config_builder.region(Region::new(region.clone()));
                }

                let client = S3Client::from_conf(s3_config_builder.build());

                Some(Arc::new(enclaver::proxy::s3::S3Proxy::new(
                    client,
                    s3_config.bucket.clone(),
                    s3_config.prefix.clone(),
                    s3_config.encryption.clone(),
                )))
            } else {
                None
            };

            // Create Nova KMS proxy if configured.
            let nova_kms = if let Some(kms_config) = config.kms_integration_config() {
                info!("Nova KMS integration enabled (registry discovery mode)");
                Some(Arc::new(NovaKmsProxy::new(kms_config, odyn_endpoint)?))
            } else {
                None
            };

            // If S3 encryption requires KMS, attach the KMS proxy.
            if let Some(s3_proxy_ref) = s3_proxy.as_ref()
                && let Some(s3_cfg) = config.s3_config()
                && matches!(
                    s3_cfg.encryption.as_ref().map(|v| &v.mode),
                    Some(S3EncryptionMode::Kms)
                )
            {
                if let Some(nova_kms_ref) = nova_kms.as_ref() {
                    s3_proxy_ref.attach_nova_kms(nova_kms_ref.clone()).await;
                } else {
                    anyhow::bail!(
                        "storage.s3.encryption.mode=kms requires kms_integration.enabled=true"
                    );
                }
            }

            // Periodically rotate and archive audit logs into encrypted S3.
            if let (Some(nova_kms_ref), Some(s3_proxy_ref)) = (nova_kms.as_ref(), s3_proxy.as_ref())
                && let Some(s3_cfg) = config.s3_config()
                && matches!(
                    s3_cfg.encryption.as_ref().map(|v| &v.mode),
                    Some(S3EncryptionMode::Kms)
                )
                && let Some(audit_log_path) = nova_kms_ref.audit_log_path()
            {
                let s3_clone = s3_proxy_ref.clone();
                audit_archive_task = Some(tokio::task::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;

                        // 1. Retry backlog of failed uploads
                        if let Err(err) = flush_audit_log_backlog(&audit_log_path, &s3_clone).await
                        {
                            warn!("Failed to flush KMS audit log backlog: {}", err);
                        }

                        // 2. Archive current active log
                        if let Err(err) = archive_audit_log_once(&audit_log_path, &s3_clone).await {
                            warn!("Failed to archive current KMS audit log: {}", err);
                        }
                    }
                }));
            }

            let srv = HttpServer::bind(port).await?;
            let handler = ApiHandler::with_integrations(
                Box::new(NsmAttestationProvider::new(nsm.clone())),
                Some(nsm),
                s3_proxy,
                nova_kms,
            )?;

            Some(tokio::task::spawn(async move {
                _ = srv.serve(handler).await;
            }))
        } else {
            None
        };

        Ok(Self {
            task,
            audit_archive_task,
        })
    }

    pub async fn stop(self) {
        if let Some(task) = self.audit_archive_task {
            task.abort();
            _ = task.await;
        }
        if let Some(task) = self.task {
            task.abort();
            _ = task.await;
        }
    }
}

async fn archive_audit_log_once(path: &std::path::Path, s3_proxy: &Arc<S3Proxy>) -> Result<()> {
    let rotate_path = format!("{}.upload.{}", path.display(), current_unix_timestamp());
    match tokio::fs::rename(path, &rotate_path).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    }

    let payload = tokio::fs::read(&rotate_path).await?;
    if payload.is_empty() {
        let _ = tokio::fs::remove_file(&rotate_path).await;
        return Ok(());
    }

    let key = format!(
        "kms-audit/{}-{}.jsonl",
        current_unix_timestamp(),
        Uuid::new_v4()
    );
    s3_proxy
        .put_raw(&key, payload, Some("application/x-ndjson".to_string()))
        .await?;
    tokio::fs::remove_file(&rotate_path).await?;
    Ok(())
}

async fn flush_audit_log_backlog(
    base_path: &std::path::Path,
    s3_proxy: &Arc<S3Proxy>,
) -> Result<()> {
    let parent = base_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/"));
    let base_name = base_path.file_name().unwrap_or_default().to_string_lossy();
    let prefix = format!("{}.upload.", base_name);

    let mut entries = match tokio::fs::read_dir(parent).await {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) {
            let path = entry.path();
            let payload = match tokio::fs::read(&path).await {
                Ok(p) => p,
                Err(_) => continue,
            };

            if payload.is_empty() {
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            }

            let key = format!(
                "kms-audit/{}-{}.jsonl",
                current_unix_timestamp(),
                Uuid::new_v4()
            );

            match s3_proxy
                .put_raw(&key, payload, Some("application/x-ndjson".to_string()))
                .await
            {
                Ok(_) => {
                    info!("Successfully archived backlog audit log {}", path.display());
                    let _ = tokio::fs::remove_file(&path).await;
                }
                Err(err) => {
                    warn!(
                        "Failed to archive backlog audit log {}: {}",
                        path.display(),
                        err
                    );
                    // Leave it on disk for next retry
                }
            }
        }
    }
    Ok(())
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}
