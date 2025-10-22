use std::sync::Arc;

use anyhow::Result;
use rustls::{
    SignatureScheme,
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    server::ParsedCertificate,
};

use hyper::Uri;
use hyper_rustls::HttpsConnectorBuilder;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    {ClientConfig, RootCertStore},
};

use enclaver::keypair::KeyPair;

#[derive(Debug, Clone)]
pub struct ServerIdentity<'a> {
    ca_cert: CertificateDer<'a>,
    spiffe_id: String,
}

impl<'a> ServerIdentity<'a> {
    #[allow(dead_code)]
    pub fn new(ca_cert: CertificateDer<'a>, spiffe_id: String) -> Self {
        Self { ca_cert, spiffe_id }
    }

    pub fn spire_server(ca_cert: CertificateDer<'a>, td: &str) -> Self {
        Self {
            ca_cert,
            spiffe_id: format!("spiffe://{td}/spire/server"),
        }
    }
}

#[derive(Debug)]
pub struct ClientIdentity<'a> {
    cert_chain: Vec<CertificateDer<'a>>,
    key: PrivateKeyDer<'a>,
}

impl<'a> ClientIdentity<'a> {
    pub fn new(cert_chain: Vec<CertificateDer<'a>>, key: &KeyPair) -> Result<Self> {
        let key = PrivateKeyDer::Pkcs1(key.as_pkcs1()?);
        Ok(Self { cert_chain, key })
    }
}

pub async fn channel(
    addr: Uri,
    server_ident: ServerIdentity<'_>,
    client_ident: Option<ClientIdentity<'static>>,
    proxy_uri: Option<Uri>,
) -> Result<tonic::transport::Channel> {
    let roots = {
        let mut roots = RootCertStore::empty();
        roots.add(server_ident.ca_cert)?;
        Arc::new(roots)
    };

    let tls = ClientConfig::builder().with_root_certificates(roots.clone());

    let mut tls = match client_ident {
        Some(id) => tls.with_client_auth_cert(id.cert_chain, id.key)?,
        None => tls.with_no_client_auth(),
    };

    tls.dangerous()
        .set_certificate_verifier(Arc::new(SpiffeCertificateVerifier::new(
            roots,
            server_ident.spiffe_id,
        )?));

    let endpoint = tonic::transport::Endpoint::from_shared(addr.to_string())?;
    if let Some(proxy_uri) = proxy_uri {
        let proxy_connector = enclaver::http_client::new_http_proxy_connector(proxy_uri);
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_only()
            .enable_http2()
            .wrap_connector(proxy_connector);
        Ok(tonic::transport::Channel::connect(connector, endpoint).await?)
    } else {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http2()
            .build();

        Ok(tonic::transport::Channel::connect(connector, endpoint).await?)
    }
}

#[derive(Debug)]
struct SpiffeCertificateVerifier {
    roots: Arc<RootCertStore>,
    spiffe_id: String,
}

impl SpiffeCertificateVerifier {
    pub fn new(roots: Arc<RootCertStore>, spiffe_id: String) -> Result<Self> {
        Ok(Self { roots, spiffe_id })
    }

    pub fn verify_spiffe_id(&self, cert_der: &[u8]) -> std::result::Result<(), rustls::Error> {
        use x509_cert::der::oid::AssociatedOid;

        let cert: x509_cert::Certificate =
            x509_cert::der::Decode::from_der(cert_der).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;

        if let Some(extensions) = cert.tbs_certificate.extensions {
            if let Some(san) = extensions
                .iter()
                .find(|e| e.extn_id == x509_cert::ext::pkix::SubjectAltName::OID)
            {
                let san: x509_cert::ext::pkix::SubjectAltName =
                    x509_cert::der::Decode::from_der(san.extn_value.as_bytes()).map_err(|_| {
                        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                    })?;

                if let Some(san_uri) = find_san_uri(&san) {
                    if san_uri == self.spiffe_id {
                        return Ok(());
                    }
                }
            }
        }

        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ))
    }

    fn sig_algos() -> WebPkiSupportedAlgorithms {
        rustls::crypto::CryptoProvider::get_default()
            .expect("default crypto provider")
            .signature_verification_algorithms
    }
}

fn find_san_uri(san: &x509_cert::ext::pkix::SubjectAltName) -> Option<String> {
    san.0.iter().find_map(|n| {
        if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) = n {
            Some(uri.to_string())
        } else {
            None
        }
    })
}

impl rustls::client::danger::ServerCertVerifier for SpiffeCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        log::info!("Verifying server cert");

        let cert = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            CryptoProvider::get_default()
                .unwrap()
                .signature_verification_algorithms
                .all,
        )
        .inspect_err(|e| log::error!("Failed to verify server cert: {e}"))?;

        log::debug!("Server cert is signed by trust anchor");

        if !ocsp_response.is_empty() {
            log::debug!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        self.verify_spiffe_id(end_entity)?;
        log::debug!("Server cert is valid for SPIFFE ID");
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &Self::sig_algos())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &Self::sig_algos())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::sig_algos().supported_schemes()
    }
}
