mod channel;
mod spire_client;

use anyhow::{Result, bail};
use hyper::Uri;
use log::info;
use rustls::pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::str::FromStr;

use self::channel::ServerIdentity;
use self::spire_client::SpireAgentClient;
use enclaver::keypair::KeyPair;
use enclaver::nsm::{AttestationParams, AttestationProvider};

pub async fn acquire_svid(
    config: &enclaver::manifest::Spire,
    keypair: &KeyPair,
    attestations: &dyn AttestationProvider,
    proxy_uri: Option<Uri>,
) -> Result<()> {
    let ca_cert = CertificateDer::from_pem_file(&config.ca_cert)?;
    let server_addr = Uri::from_str(&config.server_addr)?;
    let agent_svc = SpireAgentClient::connect(
        server_addr,
        ServerIdentity::spire_server(ca_cert, &config.trust_domain),
        &attestations.attestation(AttestationParams::default())?,
        keypair,
        proxy_uri,
    )
    .await?;

    info!("Authenticated with SPIRE server");

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

    write_certificate_chain_to_pem(&cert_chain, &config.svid_dir.join("svid.pem"))?;

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
        let encoded = base64::encode(cert_der.as_ref());
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;

        // Write the PEM footer
        file.write_all(b"-----END CERTIFICATE-----\n")?;
    }

    Ok(())
}
