use std::sync::Arc;

use anyhow::{Result, anyhow};
use serde_bytes::ByteBuf;

pub use aws_nitro_enclaves_nsm_api::api::{Request, Response};

pub struct AttestationParams {
    pub nonce: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

pub struct Nsm {
    fd: i32,
}

impl Nsm {
    pub fn new() -> Self {
        Self {
            fd: aws_nitro_enclaves_nsm_api::driver::nsm_init(),
        }
    }

    pub fn get_random(&self) -> Result<Vec<u8>> {
        match self.process_request(Request::GetRandom {})? {
            Response::GetRandom { random } => Ok(random),

            _ => Err(anyhow!("unexpected response for GetRandom")),
        }
    }

    pub fn attestation(&self, params: AttestationParams) -> Result<Vec<u8>> {
        let req = Request::Attestation {
            nonce: params.nonce.map(ByteBuf::from),
            user_data: params.user_data.map(ByteBuf::from),
            public_key: params.public_key.map(ByteBuf::from),
        };

        match self.process_request(req)? {
            Response::Attestation { document } => Ok(document),
            _ => Err(anyhow!("unexpected response for Attestation")),
        }
    }

    fn process_request(&self, req: Request) -> Result<Response> {
        match aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, req) {
            Response::Error(err) => Err(anyhow!("nsm request failed with: {:?}", err)),
            resp => Ok(resp),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.fd);
    }
}

pub trait AttestationProvider {
    fn attestation(&self, params: AttestationParams) -> Result<Vec<u8>>;
}

pub struct NsmAttestationProvider {
    nsm: Arc<Nsm>,
}

impl NsmAttestationProvider {
    pub fn new(nsm: Arc<Nsm>) -> Self {
        Self { nsm }
    }
}

impl AttestationProvider for NsmAttestationProvider {
    fn attestation(&self, params: AttestationParams) -> Result<Vec<u8>> {
        self.nsm.attestation(params)
    }
}

// Always returns the same document, useful to tests
pub struct StaticAttestationProvider {
    doc: Vec<u8>,
}

impl StaticAttestationProvider {
    pub fn new(doc: Vec<u8>) -> Self {
        Self { doc }
    }
}

impl AttestationProvider for StaticAttestationProvider {
    fn attestation(&self, _params: AttestationParams) -> Result<Vec<u8>> {
        Ok(self.doc.clone())
    }
}
