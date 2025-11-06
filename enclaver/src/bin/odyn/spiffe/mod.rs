mod channel;
mod spire_client;
pub(crate) mod trust_bundle;
mod workload_api;

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Result, bail, anyhow};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use hyper::Uri;
use ignore_result::Ignore;
use log::{error, info};
use rustls::pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio_util::sync::CancellationToken;

use self::channel::ServerIdentity;
use self::spire_client::{SpireAgentClient, SpireAgentProtocol};
use self::trust_bundle::TrustBundles;
use self::workload_api::{SpiffeWorkloadApiServer, SpiffeWorkloadService};
use enclaver::keypair::KeyPair;
use enclaver::nsm::{AttestationParams, AttestationProvider};

const SPIFFE_WORKLOAD_API_DEFAULT_ADDR: &str = "127.0.0.1:5000";

pub struct SpiffeService {
    trust_bundle_refresh_task: tokio::task::JoinHandle<()>,
    workload_task: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl SpiffeService {
    pub async fn start(
        config: &enclaver::manifest::Spire,
        keypair: &KeyPair,
        attestations: &dyn AttestationProvider,
        proxy_uri: Option<Uri>,
    ) -> Result<Self> {
        let ca_cert = CertificateDer::from_pem_file(&config.ca_cert)?;
        let server_addr = Uri::from_str(&config.server_addr)?;
        let agent_svc: Arc<dyn SpireAgentProtocol + Send + Sync> = Arc::new(
            SpireAgentClient::connect(
                server_addr,
                ServerIdentity::spire_server(ca_cert.clone(), &config.trust_domain),
                &attestations.attestation(AttestationParams::default())?,
                keypair,
                proxy_uri,
            )
            .await?,
        );

        info!("Authenticated with SPIRE server");
        let trust_bundles = TrustBundles::new();
        acquire_svid(config, keypair, agent_svc.as_ref()).await?;
        info!("Acquired X.509 SVID");
        acquire_trust_bundle(agent_svc.as_ref(), &trust_bundles).await?;
        info!("Acquired trust bundle");

        let cancel = CancellationToken::new();

        let trust_bundle_refresh_task = {
            let cancel = cancel.clone();
            let agent_svc = agent_svc.clone();
            let trust_bundles = trust_bundles.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                            if let Err(err) = acquire_trust_bundle(agent_svc.as_ref(), &trust_bundles).await {
                                error!("failed to refresh the trust bundle: {err}");
                            }
                        }
                        _ = cancel.cancelled() => {
                            break;
                        }
                    }
                }
            })
        };

        let api_svc = SpiffeWorkloadService::new(
            agent_svc,
            keypair.clone(),
            config.trust_domain.clone(),
            trust_bundles,
        );

        let api_addr = config
            .workload_api_addr
            .as_deref()
            .unwrap_or(SPIFFE_WORKLOAD_API_DEFAULT_ADDR)
            .parse()?;

        unsafe {
            std::env::set_var("SPIFFE_ENDPOINT_SOCKET", format!("tcp://{}", api_addr));
        }

        let workload_task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                log::info!("Serving SPIFFE workload API on {api_addr}");
                tonic::transport::Server::builder()
                    .add_service(SpiffeWorkloadApiServer::new(api_svc))
                    .serve_with_shutdown(api_addr, cancel.cancelled())
                    .await
                    .inspect_err(|e| error!("Failed to serve SPIFFE workload API: {}", e))
                    .ignore();
            })
        };

        Ok(Self {
            workload_task,
            trust_bundle_refresh_task,
            cancel,
        })
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        self.workload_task.await.ignore();
        self.trust_bundle_refresh_task.await.ignore();
    }
}

pub async fn acquire_svid(
    config: &enclaver::manifest::Spire,
    keypair: &KeyPair,
    agent_svc: &dyn SpireAgentProtocol,
) -> Result<()> {
    let entries = agent_svc.entries().await?;
    if entries.is_empty() {
        bail!("No entries found");
    }

    let entry = entries.first().unwrap();
    let x509_svid = agent_svc.x509_svid(&entry.id, keypair).await?;

    info!("Fetched X.509 SVID: {:?}", x509_svid.id);

    let cert_chain = x509_svid
        .cert_chain
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();

    std::fs::create_dir_all(&config.svid_dir)?;
    let svid_path = config.svid_dir.join("svid.pem");
    write_certificate_chain_to_pem(&cert_chain, &svid_path)
        .map_err(|e| anyhow!("writing cert chain to {} failed: {e}", svid_path.display()))?;

    Ok(())
}

fn write_certificate_chain_to_pem(
    certs: &[CertificateDer<'static>],
    file_path: &std::path::Path,
) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(file_path)?;

    for cert_der in certs {
        // Write the PEM header
        file.write_all(b"-----BEGIN CERTIFICATE-----\n")?;

        // Base64 encode the DER certificate and write it
        let encoded = BASE64_STANDARD.encode(cert_der.as_ref());
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;

        // Write the PEM footer
        file.write_all(b"-----END CERTIFICATE-----\n")?;
    }

    Ok(())
}

async fn acquire_trust_bundle(
    agent_svc: &(dyn SpireAgentProtocol + Send + Sync),
    trust_bundles: &TrustBundles,
) -> Result<()> {
    let bundle = agent_svc.get_bundle().await?;
    trust_bundles.x509.extend(
        bundle
            .x509_authorities
            .into_iter()
            .filter_map(|cert| {
                if cert.tainted {
                    None
                } else {
                    Some(CertificateDer::from(cert.asn1))
                }
            })
            .collect(),
    );

    for jwt_key in bundle.jwt_authorities {
        if !jwt_key.tainted {
            trust_bundles
                .jwt
                .add_der(jwt_key.key_id, &jwt_key.public_key)?;
        }
    }

    Ok(())
}
