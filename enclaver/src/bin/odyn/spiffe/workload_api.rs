use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use prost_types::Struct;
use tonic::Status;

use crate::spiffe::trust_bundle::JWTTrustBundle;
use crate::spiffe::workload_api::pb::spiffe::workload::{JwtsvidResponse, X509svidResponse};
use enclaver::keypair::KeyPair;

pub use super::spire_client::{SpireAgentProtocol, pb::spire::api::types::Spiffeid};
pub use super::trust_bundle::TrustBundles;

pub mod pb {
    #[allow(clippy::enum_variant_names)]
    #[allow(clippy::doc_lazy_continuation)]
    pub mod spiffe {
        pub mod workload {
            tonic::include_proto!("workload");
        }
    }
}

pub use pb::spiffe::workload::spiffe_workload_api_server::SpiffeWorkloadApiServer;

use pb::spiffe::workload::spiffe_workload_api_server::SpiffeWorkloadApi;
use pb::spiffe::workload::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svidRequest,
};

type TonicResult<T> = std::result::Result<tonic::Response<T>, tonic::Status>;

pub struct SpiffeWorkloadService {
    agent_client: Arc<dyn SpireAgentProtocol + Send + Sync>,
    keypair: KeyPair,
    td: String,
    roots: TrustBundles,
}

impl SpiffeWorkloadService {
    pub fn new(
        agent_client: Arc<dyn SpireAgentProtocol + Send + Sync>,
        keypair: KeyPair,
        td: String,
        roots: TrustBundles,
    ) -> Self {
        Self {
            agent_client,
            keypair,
            td,
            roots,
        }
    }

    async fn any_entry_id(&self) -> tonic::Result<String> {
        let entries = self
            .agent_client
            .entries()
            .await
            .map_err(|e| tonic::Status::unknown(e.to_string()))?;

        Ok(entries
            .first()
            .ok_or_else(|| tonic::Status::not_found("No entries found"))?
            .id
            .clone())
    }

    async fn find_entry_id(&self, spiffe_id: &str) -> tonic::Result<String> {
        let id = self
            .agent_client
            .entries()
            .await
            .map_err(|e| tonic::Status::unknown(e.to_string()))?
            .into_iter()
            .find(|entry| {
                entry.spiffe_id.as_ref().map(stringify_spiffe_id).as_deref() == Some(spiffe_id)
            })
            .ok_or_else(|| tonic::Status::not_found("No entry found"))?
            .id
            .clone();

        Ok(id)
    }
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for SpiffeWorkloadService {
    type FetchX509SVIDStream =
        futures::stream::BoxStream<'static, Result<X509svidResponse, Status>>;
    type FetchX509BundlesStream =
        futures::stream::BoxStream<'static, Result<X509BundlesResponse, Status>>;
    type FetchJWTBundlesStream =
        futures::stream::BoxStream<'static, Result<JwtBundlesResponse, Status>>;

    async fn fetch_x509svid(
        &self,
        _request: tonic::Request<X509svidRequest>,
    ) -> TonicResult<Self::FetchX509SVIDStream> {
        let entry_id = self.any_entry_id().await?;

        let x509_svid = self
            .agent_client
            .x509_svid(&entry_id, &self.keypair)
            .await
            .map(|svid| pb::spiffe::workload::X509svid {
                spiffe_id: svid
                    .id
                    .as_ref()
                    .map(stringify_spiffe_id)
                    .unwrap_or_default(),
                x509_svid: svid.cert_chain.into_iter().flatten().collect(),
                x509_svid_key: self.keypair.as_pkcs8().unwrap().secret_pkcs8_der().to_vec(),
                bundle: self.roots.x509.as_concatenated_der(),
                hint: svid.hint,
            })
            .map_err(|e| tonic::Status::unknown(e.to_string()))?;

        let response = X509svidResponse {
            svids: vec![x509_svid],
            crl: Vec::new(),
            federated_bundles: HashMap::new(),
        };

        Ok(tonic::Response::new(Box::pin(futures::stream::once(
            async { Ok(response) },
        ))))
    }

    async fn fetch_x509_bundles(
        &self,
        _request: tonic::Request<X509BundlesRequest>,
    ) -> TonicResult<Self::FetchX509BundlesStream> {
        let response = X509BundlesResponse {
            crl: Vec::new(),
            bundles: [(self.td.clone(), self.roots.x509.as_concatenated_der())].into(),
        };

        Ok(tonic::Response::new(Box::pin(futures::stream::once(
            async { Ok(response) },
        ))))
    }

    async fn fetch_jwtsvid(
        &self,
        request: tonic::Request<JwtsvidRequest>,
    ) -> TonicResult<JwtsvidResponse> {
        let request = request.into_inner();

        let entry_id = if !request.spiffe_id.is_empty() {
            self.find_entry_id(&request.spiffe_id).await?
        } else {
            self.any_entry_id().await?
        };

        let svid = self
            .agent_client
            .jwt_svid(&entry_id, request.audience)
            .await
            .map_err(|e| tonic::Status::unknown(e.to_string()))?;

        let response = JwtsvidResponse {
            svids: vec![pb::spiffe::workload::Jwtsvid {
                spiffe_id: svid
                    .id
                    .as_ref()
                    .map(stringify_spiffe_id)
                    .unwrap_or_default(),
                svid: svid.token,
                hint: svid.hint,
            }],
        };

        Ok(tonic::Response::new(response))
    }

    async fn fetch_jwt_bundles(
        &self,
        _request: tonic::Request<JwtBundlesRequest>,
    ) -> TonicResult<Self::FetchJWTBundlesStream> {
        let jwks = self
            .roots
            .jwt
            .as_jwks()
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let bundle =
            serde_json::to_vec(&jwks).map_err(|e| tonic::Status::internal(e.to_string()))?;

        let response = JwtBundlesResponse {
            bundles: [(self.td.clone(), bundle)].into(),
        };

        Ok(tonic::Response::new(Box::pin(futures::stream::once(
            async { Ok(response) },
        ))))
    }

    async fn validate_jwtsvid(
        &self,
        request: tonic::Request<ValidateJwtsvidRequest>,
    ) -> TonicResult<ValidateJwtsvidResponse> {
        let request = request.into_inner();

        if request.svid.is_empty() {
            return Err(tonic::Status::invalid_argument("svid is required"));
        }

        if request.audience.is_empty() {
            return Err(tonic::Status::invalid_argument("audience is required"));
        }

        // Get JWKS from trust bundle
        let jwks = &self.roots.jwt;

        let jwt = Jwt::decode(&request.svid, jwks, &request.audience)
            .map_err(|e| tonic::Status::permission_denied(e.to_string()))?;

        let claims = jwt.into_claims();

        let response = ValidateJwtsvidResponse {
            spiffe_id: claims.sub().unwrap_or_default().to_string(),
            claims: Some(claims.into_protobuf_struct()),
        };

        Ok(tonic::Response::new(response))
    }
}

fn stringify_spiffe_id(spiffe_id: &Spiffeid) -> String {
    format!("spiffe://{}/{}", spiffe_id.trust_domain, spiffe_id.path)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Claims(serde_json::Map<String, serde_json::Value>);

impl Claims {
    fn sub(&self) -> Option<&str> {
        self.0.get("sub").and_then(|s| s.as_str())
    }

    fn into_protobuf_struct(self) -> Struct {
        let v = json_value_to_prost_value(serde_json::Value::Object(self.0));
        if let Some(prost_types::value::Kind::StructValue(s)) = v.kind {
            s
        } else {
            panic!("unexpected non-struct value")
        }
    }
}

fn json_value_to_prost_value(v: serde_json::Value) -> prost_types::Value {
    match v {
        serde_json::Value::Array(a) => {
            a.into_iter().map(json_value_to_prost_value).collect::<Vec<_>>().into()
        }
        serde_json::Value::Object(o) => {
            o
                .into_iter()
                .map(|(n, el)| (n, json_value_to_prost_value(el)))
                .collect::<BTreeMap<_, _>>()
                .into()
        }
        serde_json::Value::Bool(b) => b.into(),
        serde_json::Value::Number(n) => n.as_f64().unwrap().into(), // unwrap is safe b/c "arbitrary_precision" is not enabled
        serde_json::Value::String(s) => s.into(),
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0).into(),
    }
}

pub struct Jwt(jsonwebtoken::TokenData<Claims>);

impl Jwt {
    pub fn decode(token: &str, keys: &JWTTrustBundle, audience: &str) -> Result<Self> {
        let header = jsonwebtoken::decode_header(token)?;
        let key = match header.kid {
            Some(kid) => keys.get(&kid),
            None => keys.any(),
        }
        .ok_or_else(|| anyhow!("No matching key found for kid"))?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[&audience]);

        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)?;
        Ok(Self(claims))
    }

    pub fn into_claims(self) -> Claims {
        self.0.claims
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe::spire_client::pb::spire::api::types::{
        Bundle, Entry, Jwtsvid, Spiffeid, X509Certificate, X509svid,
    };
    use assert2::assert;
    use async_trait::async_trait;
    use rustls_pki_types::CertificateDer;

    const PUBLIC_KEY_DER: &[u8] = include_bytes!("testdata/public_key.der");

    struct MockSpireAgentProtocol;

    #[async_trait]
    impl SpireAgentProtocol for MockSpireAgentProtocol {
        async fn entries(&self) -> Result<Vec<Entry>> {
            Ok(vec![Entry {
                id: "entry-1".to_string(),
                spiffe_id: Some(Spiffeid {
                    trust_domain: "example.org".to_string(),
                    path: "workload/test".to_string(),
                }),
                parent_id: Some(Spiffeid {
                    trust_domain: "example.org".to_string(),
                    path: "spire/server".to_string(),
                }),
                selectors: vec![],
                x509_svid_ttl: 3600,
                federates_with: vec![],
                admin: false,
                downstream: false,
                expires_at: 1714857600,
                dns_names: vec![],
                revision_number: 1,
                store_svid: false,
                jwt_svid_ttl: 3600,
                hint: "test".to_string(),
                created_at: 1714857600,
            }])
        }

        async fn x509_svid(&self, _entry_id: &str, _keypair: &KeyPair) -> Result<X509svid> {
            Ok(X509svid {
                id: Some(Spiffeid {
                    trust_domain: "example.org".to_string(),
                    path: "workload/test".to_string(),
                }),
                cert_chain: vec![],
                expires_at: 1714857600,
                hint: "test".to_string(),
            })
        }

        async fn jwt_svid(&self, _entry_id: &str, _audience: Vec<String>) -> Result<Jwtsvid> {
            Ok(Jwtsvid {
                id: Some(Spiffeid {
                    trust_domain: "example.org".to_string(),
                    path: "workload/test".to_string(),
                }),
                token: include_str!("testdata/jwt_svid.txt").to_string(),
                expires_at: 2114857600,
                issued_at: 1714857600,
                hint: "test".to_string(),
            })
        }

        async fn get_bundle(&self) -> Result<Bundle> {
            Ok(Bundle {
                trust_domain: "example.org".to_string(),
                x509_authorities: vec![X509Certificate {
                    asn1: b"dummy_cert".to_vec(),
                    tainted: false,
                }],
                jwt_authorities: vec![],
                refresh_hint: 0,
                sequence_number: 0,
            })
        }
    }

    #[tokio::test]
    async fn test_workload_svc() {
        use futures::StreamExt;
        let expected_cert: Vec<u8> = b"dummy_cert".to_vec();

        let agent_client = Arc::new(MockSpireAgentProtocol {});

        let roots = TrustBundles::new();
        roots.x509.add(CertificateDer::from(expected_cert.clone()));
        roots
            .jwt
            .add_der("key-1".to_string(), PUBLIC_KEY_DER)
            .unwrap();

        let workload_svc = SpiffeWorkloadService::new(
            agent_client,
            KeyPair::generate().unwrap(),
            "example.org".to_string(),
            roots,
        );

        let actual_x509svids = workload_svc
            .fetch_x509svid(tonic::Request::new(X509svidRequest {}))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap()
            .svids;

        assert!(actual_x509svids.len() == 1);
        assert!(actual_x509svids[0].spiffe_id == "spiffe://example.org/workload/test");

        let actual_x509bundles = workload_svc
            .fetch_x509_bundles(tonic::Request::new(X509BundlesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap()
            .bundles;

        assert!(actual_x509bundles.len() == 1);
        assert!(actual_x509bundles["example.org"] == expected_cert);

        let actual_jwt_svid = workload_svc
            .fetch_jwtsvid(tonic::Request::new(JwtsvidRequest {
                audience: vec!["aud-1".to_string()],
                spiffe_id: String::default(),
            }))
            .await
            .unwrap()
            .into_inner()
            .svids;

        assert!(actual_jwt_svid.len() == 1);
        assert!(actual_jwt_svid[0].spiffe_id == "spiffe://example.org/workload/test");
        assert!(actual_jwt_svid[0].svid == include_str!("testdata/jwt_svid.txt"));
        assert!(actual_jwt_svid[0].hint == "test");

        let actual_jwt_bundles = workload_svc
            .fetch_jwt_bundles(tonic::Request::new(JwtBundlesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap()
            .bundles;

        assert!(actual_jwt_bundles.len() == 1);

        const EXPECTED_BUNDLE: &[u8] = include_bytes!("testdata/jwt_bundle.json");
        assert!(actual_jwt_bundles["example.org"] == EXPECTED_BUNDLE);

        let validate_resp = workload_svc
            .validate_jwtsvid(tonic::Request::new(ValidateJwtsvidRequest {
                audience: "aud-1".to_string(),
                svid: include_str!("testdata/jwt_svid.txt").to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(validate_resp.spiffe_id == "spiffe://example.org/workload/test");
    }
}
