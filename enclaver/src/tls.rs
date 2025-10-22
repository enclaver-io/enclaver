use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig, SignatureScheme,
};

static CRYPTO_PROVIDER_INIT: LazyLock<()> =
    LazyLock::new(|| aws_lc_rs::default_provider().install_default().unwrap());

fn init_crypto_provider() {
    LazyLock::force(&CRYPTO_PROVIDER_INIT);
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))?;
    Ok(key)
}

pub fn load_server_config<P1: AsRef<Path>, P2: AsRef<Path>>(
    key: P1,
    cert: P2,
) -> Result<Arc<ServerConfig>> {
    init_crypto_provider();

    let certs = load_certs(cert.as_ref())?;
    let key = load_key(key.as_ref())?;

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}

pub fn load_client_config(cert: impl AsRef<Path> + 'static) -> Result<Arc<ClientConfig>> {
    init_crypto_provider();

    let mut roots = RootCertStore::empty();
    let mut certs = load_certs(cert.as_ref())?;
    roots.add(certs.remove(0))?;

    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

// from rustls example code
#[derive(Debug)]
pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Just say that we support all schemes
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub fn load_insecure_client_config() -> Result<Arc<ClientConfig>> {
    let roots = RootCertStore::empty();

    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    Ok(Arc::new(cfg))
}

#[cfg(test)]
fn data_file(name: &str) -> Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(file!()).canonicalize()?;
    path.pop(); // pop the filename of the .rs file
    path.push(name);
    Ok(path)
}

#[cfg(test)]
pub fn test_server_config() -> Result<Arc<ServerConfig>> {
    load_server_config(data_file("test.key")?, data_file("test.crt")?)
}
