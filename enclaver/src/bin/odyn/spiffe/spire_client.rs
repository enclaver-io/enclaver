pub mod pb {
    #[allow(clippy::enum_variant_names)]
    #[allow(clippy::doc_lazy_continuation)]
    pub mod spire {
        pub mod api {
            pub mod server {
                pub mod agent {
                    pub mod v1 {
                        tonic::include_proto!("spire.api.server.agent.v1");
                    }
                }
                pub mod entry {
                    pub mod v1 {
                        tonic::include_proto!("spire.api.server.entry.v1");
                    }
                }
                pub mod svid {
                    pub mod v1 {
                        tonic::include_proto!("spire.api.server.svid.v1");
                    }
                }
            }
            pub mod types {
                tonic::include_proto!("spire.api.types");
            }
        }
    }
}

use anyhow::{Result, bail};

use pb::spire::api::server::agent::v1::agent_client::AgentClient;
use pb::spire::api::server::agent::v1::attest_agent_request::{Params, Step};
use pb::spire::api::server::agent::v1::attest_agent_response::Step as AttestAgentResponseStep;
use pb::spire::api::server::agent::v1::{AgentX509svidParams, AttestAgentRequest};
use pb::spire::api::server::entry::v1::GetAuthorizedEntriesRequest;
use pb::spire::api::server::entry::v1::entry_client::EntryClient;
use pb::spire::api::server::svid::v1::svid_client::SvidClient;
use pb::spire::api::server::svid::v1::{BatchNewX509svidRequest, NewX509svidParams};
pub use pb::spire::api::types::{AttestationData, Entry, EntryMask, X509svid};

use futures::StreamExt;
use futures::stream;
use hyper::Uri;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_cert::builder::Builder;

use super::channel::{ClientIdentity, ServerIdentity};
use enclaver::keypair::KeyPair;

pub struct SpireAgentClient {
    channel: tonic::transport::Channel,
}

impl SpireAgentClient {
    pub async fn connect(
        addr: Uri,
        server_ident: ServerIdentity<'_>,
        attestation_doc: &[u8],
        keypair: &KeyPair,
        proxy_uri: Option<Uri>,
    ) -> Result<Self> {
        let svid = Self::authenticate(
            addr.clone(),
            server_ident.clone(),
            attestation_doc,
            keypair,
            proxy_uri.clone(),
        )
        .await?;

        let cert_chain = svid
            .cert_chain
            .into_iter()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();

        let client_ident = ClientIdentity::new(cert_chain, keypair)?;
        let ch = super::channel::channel(addr, server_ident, Some(client_ident), proxy_uri).await?;

        Ok(Self { channel: ch })
    }

    async fn authenticate(
        addr: Uri,
        server_ident: ServerIdentity<'_>,
        attestation_doc: &[u8],
        keypair: &KeyPair,
        proxy_uri: Option<Uri>,
    ) -> Result<X509svid> {
        log::info!("Connecting to SPIRE server at {addr}");
        let ch = super::channel::channel(addr, server_ident, None, proxy_uri).await?;

        log::info!("Connected to SPIRE server");

        let csr = create_csr(keypair)?;

        let request = AttestAgentRequest {
            step: Some(Step::Params(Params {
                data: Some(AttestationData {
                    r#type: "nitro_enclave".to_string(),
                    payload: attestation_doc.to_vec(),
                }),
                params: Some(AgentX509svidParams { csr }),
            })),
        };

        let mut client = AgentClient::new(ch.clone());

        log::debug!("Attesting as SPIRE agent");
        let mut stream = client
            .attest_agent(stream::once(async { request }))
            .await?
            .into_inner();
        log::info!("Attestation successful");

        // Process the streaming response
        while let Some(response) = stream.next().await {
            let response = response?;
            if let Some(AttestAgentResponseStep::Result(result)) = response.step {
                if let Some(svid) = result.svid {
                    return Ok(svid);
                }
            }
        }

        bail!("No result from attest agent");
    }

    pub async fn entries(&self) -> Result<Vec<Entry>> {
        let request = GetAuthorizedEntriesRequest {
            output_mask: Some(EntryMask {
                spiffe_id: true,
                ..Default::default()
            }),
        };

        let mut client = EntryClient::new(self.channel.clone());
        let response = client.get_authorized_entries(request).await?.into_inner();

        Ok(response.entries)
    }

    pub async fn x509_svid(&self, entry_id: &str, keypair: &KeyPair) -> Result<X509svid> {
        let csr = create_csr(keypair)?;

        let req = BatchNewX509svidRequest {
            params: vec![NewX509svidParams {
                entry_id: entry_id.to_string(),
                csr,
            }],
        };

        let mut client = SvidClient::new(self.channel.clone());
        let mut response = client.batch_new_x509svid(req).await?.into_inner();
        if let Some(result) = response.results.pop() {
            if let Some(svid) = result.svid {
                return Ok(svid.clone());
            }
        }

        bail!("No result from batch new x509 svid");
    }
}

fn create_csr(keypair: &KeyPair) -> Result<Vec<u8>> {
    let subj = x509_cert::name::Name::default();
    let signing_key = keypair.signing_key();
    let builder = x509_cert::builder::RequestBuilder::new(subj, &signing_key)?;
    let cert_req = builder.build()?;
    Ok(x509_cert::der::Encode::to_der(&cert_req)?)
}
