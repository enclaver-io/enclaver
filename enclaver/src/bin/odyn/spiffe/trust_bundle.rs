use anyhow::{Ok, Result};
use jsonwebtoken::jwk::Jwk;
use spki::der::Decode;
use spki::der::oid::db;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_rustls::rustls::pki_types::CertificateDer;

#[derive(Clone)]
pub struct X509TrustBundle {
    roots: Arc<Mutex<Vec<CertificateDer<'static>>>>,
}

impl X509TrustBundle {
    pub fn new() -> Self {
        Self {
            roots: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn extend(&self, certs: Vec<CertificateDer<'static>>) {
        self.roots.lock().unwrap().extend(certs);
    }

    pub fn as_concatenated_der(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for root in self.roots.lock().unwrap().iter() {
            r.extend_from_slice(root);
        }
        r
    }
}
#[derive(Clone)]
pub struct JWTTrustBundle {
    keys: Arc<Mutex<HashMap<String, jsonwebtoken::DecodingKey>>>,
}

impl JWTTrustBundle {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_der(&self, key_id: String, der_bytes: &[u8]) -> Result<()> {
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(der_bytes)?;
        let key = match spki.algorithm.oid {
            db::rfc5912::RSA_ENCRYPTION => jsonwebtoken::DecodingKey::from_rsa_der(der_bytes),
            db::rfc5912::ID_EC_PUBLIC_KEY => jsonwebtoken::DecodingKey::from_ec_der(der_bytes),
            db::rfc8410::ID_ED_25519 | db::rfc8410::ID_ED_448 => {
                jsonwebtoken::DecodingKey::from_ed_der(der_bytes)
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };
        self.keys.lock().unwrap().insert(key_id, key);
        Ok(())
    }

    pub fn get(&self, key_id: &str) -> Option<jsonwebtoken::DecodingKey> {
        self.keys.lock().unwrap().get(key_id).cloned()
    }

    pub fn any(&self) -> Option<jsonwebtoken::DecodingKey> {
        self.keys.lock().unwrap().values().next().cloned()
    }

    pub fn as_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet> {
        let mut jwks = jsonwebtoken::jwk::JwkSet { keys: Vec::new() };

        for (key_id, key) in self.keys.lock().unwrap().iter() {
            let mut jwk = Jwk::from_decoding_key(key, None)?;
            jwk.common.key_id = Some(key_id.clone());
            jwks.keys.push(jwk);
        }
        Ok(jwks)
    }
}

#[derive(Clone)]
pub struct TrustBundles {
    pub x509: X509TrustBundle,
    pub jwt: JWTTrustBundle,
}

impl TrustBundles {
    pub fn new() -> Self {
        Self {
            x509: X509TrustBundle::new(),
            jwt: JWTTrustBundle::new(),
        }
    }
}
