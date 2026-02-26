//! Helios Ethereum/OP Stack Light Client RPC Service
//!
//! Provides a trustless Ethereum/OP Stack JSON-RPC endpoint inside the enclave.
//! All execution data is cryptographically verified using Light Client proofs.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{Result, anyhow};
use enclaver::manifest::HeliosRpcKind;
use helios::ethereum::config::networks::Network;
use helios::ethereum::database::ConfigDB;
use helios::ethereum::{EthereumClient, EthereumClientBuilder};
use helios::opstack::config::Network as OpNetwork;
use helios::opstack::config::NetworkConfig as OpNetworkConfig;
use helios::opstack::{OpStackClient, OpStackClientBuilder};
use log::{info, warn};
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::config::{Configuration, HeliosRuntimeConfig};

const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8192;
const CHECKPOINT_LOOKBACK_PERIODS: u64 = 4;
const CHECKPOINT_HTTP_TIMEOUT_SECS: u64 = 10;
const LOG_PREVIEW_CHARS: usize = 160;

/// Helios RPC Service for trustless Ethereum/OP Stack access
pub struct HeliosRpcService {
    tasks: Vec<JoinHandle<()>>,
    ready_rxs: Vec<(u16, tokio::sync::oneshot::Receiver<bool>)>,
}

impl HeliosRpcService {
    /// Start Helios RPC service in background (non-blocking).
    /// App can start immediately while Helios syncs.
    pub async fn start(config: &Configuration) -> Result<Self> {
        let helios_configs = config.helios_configs();
        if helios_configs.is_empty() {
            return Ok(Self {
                tasks: Vec::new(),
                ready_rxs: Vec::new(),
            });
        }

        let mut tasks = Vec::with_capacity(helios_configs.len());
        let mut ready_rxs = Vec::with_capacity(helios_configs.len());

        for helios_config in helios_configs {
            let HeliosRuntimeConfig {
                kind,
                network,
                execution_rpc,
                consensus_rpc,
                checkpoint,
                listen_port: port,
                chain_name,
            } = helios_config;

            info!(
                "Starting Helios RPC ({:?}) on port {} for network {} ({})",
                kind, port, network, chain_name
            );

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let task = tokio::task::spawn(async move {
                let result = match kind {
                    HeliosRpcKind::Ethereum => Self::run_helios_ethereum(
                        port,
                        &network,
                        &execution_rpc,
                        consensus_rpc.as_deref(),
                        checkpoint.as_deref(),
                    )
                    .await
                    .map(|_| ()),
                    HeliosRpcKind::Opstack => Self::run_helios_opstack(
                        port,
                        &network,
                        &execution_rpc,
                        consensus_rpc.as_deref(),
                    )
                    .await
                    .map(|_| ()),
                };

                match result {
                    Ok(()) => {
                        info!("Helios synced and ready on port {}", port);
                        let _ = ready_tx.send(true);

                        // Keep task alive — Helios client owns the RPC server
                        loop {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        }
                    }
                    Err(e) => {
                        warn!("Helios failed to start on {}: {}", port, e);
                        let _ = ready_tx.send(false);
                    }
                }
            });

            tasks.push(task);
            ready_rxs.push((port, ready_rx));
        }

        Ok(Self { tasks, ready_rxs })
    }

    async fn run_helios_ethereum(
        port: u16,
        network: &str,
        execution_rpc: &str,
        consensus_rpc: Option<&str>,
        checkpoint: Option<&str>,
    ) -> Result<EthereumClient> {
        let net = Self::parse_ethereum_network(network)?;

        // Bind only to localhost — internal enclave access only
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .parse()
            .map_err(|e| anyhow!("Invalid address: {}", e))?;

        info!("Building Helios Ethereum client for {} network", network);
        info!("Execution RPC: {}", execution_rpc);
        if let Some(consensus) = consensus_rpc {
            info!("Consensus RPC: {}", consensus);
        } else {
            info!("Consensus RPC: using network default");
        }

        let mut builder: EthereumClientBuilder<ConfigDB> = EthereumClientBuilder::new()
            .network(net)
            .execution_rpc(execution_rpc)
            .map_err(|e| anyhow!("Invalid execution RPC: {}", e))?
            .rpc_address(addr);

        if let Some(checkpoint) = checkpoint {
            let parsed = B256::from_str(checkpoint)
                .map_err(|e| anyhow!("Invalid checkpoint '{}': {}", checkpoint, e))?;
            builder = builder.checkpoint(parsed);
        } else if let Some(consensus) = consensus_rpc {
            match Self::resolve_ethereum_checkpoint(consensus).await {
                Ok(auto_checkpoint) => {
                    info!(
                        "Auto-selected ethereum checkpoint from consensus RPC: {:?}",
                        auto_checkpoint
                    );
                    builder = builder.checkpoint(auto_checkpoint);
                }
                Err(err) => {
                    warn!(
                        "Failed to auto-select checkpoint from consensus RPC {}: {}. Falling back to external checkpoint service.",
                        consensus, err
                    );
                    builder = builder.load_external_fallback();
                }
            }
        } else {
            // Auto-fetch checkpoint from fallback services when not provided
            builder = builder.load_external_fallback();
        }

        if let Some(consensus) = consensus_rpc {
            builder = builder
                .consensus_rpc(consensus)
                .map_err(|e| anyhow!("Invalid consensus RPC: {}", e))?;
        }

        let client = builder
            .build()
            .map_err(|e| anyhow!("Failed to build Helios client: {}", e))?;

        info!("Helios Ethereum client built, waiting for sync...");

        // Wait for initial sync
        client
            .wait_synced()
            .await
            .map_err(|e| anyhow!("Helios sync failed: {}", e))?;

        info!("Helios Ethereum sync complete");

        Ok(client)
    }

    async fn resolve_ethereum_checkpoint(consensus_rpc: &str) -> Result<B256> {
        let consensus_base = consensus_rpc.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(CHECKPOINT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                anyhow!(
                    "Failed to build HTTP client for checkpoint resolution: {}",
                    e
                )
            })?;

        let finality_update_url =
            format!("{consensus_base}/eth/v1/beacon/light_client/finality_update");
        let finality_update_body = Self::http_get_text(&client, &finality_update_url).await?;
        let finalized_slot =
            Self::extract_finalized_slot_from_finality_update(&finality_update_body)?;
        let current_period = finalized_slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD;

        info!(
            "Resolving ethereum checkpoint from finality slot {} (period {})",
            finalized_slot, current_period
        );

        for offset in 1..=CHECKPOINT_LOOKBACK_PERIODS {
            if current_period < offset {
                break;
            }

            let candidate_period = current_period - offset;
            let updates_url = format!(
                "{consensus_base}/eth/v1/beacon/light_client/updates?start_period={candidate_period}&count=1"
            );
            let updates_body = match Self::http_get_text(&client, &updates_url).await {
                Ok(body) => body,
                Err(err) => {
                    warn!(
                        "Failed to fetch light-client updates for period {}: {}",
                        candidate_period, err
                    );
                    continue;
                }
            };

            let Some(checkpoint_slot) =
                (match Self::extract_checkpoint_slot_from_updates(&updates_body) {
                    Ok(slot) => slot,
                    Err(err) => {
                        warn!(
                            "Failed to parse light-client updates for period {}: {}",
                            candidate_period, err
                        );
                        continue;
                    }
                })
            else {
                warn!(
                    "No light-client update available for period {}, trying earlier period",
                    candidate_period
                );
                continue;
            };

            let block_root_url =
                format!("{consensus_base}/eth/v1/beacon/blocks/{checkpoint_slot}/root");
            let block_root_body = match Self::http_get_text(&client, &block_root_url).await {
                Ok(body) => body,
                Err(err) => {
                    warn!(
                        "Failed to fetch block root for checkpoint slot {}: {}",
                        checkpoint_slot, err
                    );
                    continue;
                }
            };

            let checkpoint = match Self::extract_block_root(&block_root_body) {
                Ok(root) => root,
                Err(err) => {
                    warn!(
                        "Failed to parse block root for checkpoint slot {}: {}",
                        checkpoint_slot, err
                    );
                    continue;
                }
            };

            info!(
                "Derived ethereum checkpoint from consensus RPC: period={} slot={} checkpoint={:?}",
                candidate_period, checkpoint_slot, checkpoint
            );
            return Ok(checkpoint);
        }

        Err(anyhow!(
            "Unable to derive checkpoint from consensus RPC {} across last {} sync-committee periods",
            consensus_rpc,
            CHECKPOINT_LOOKBACK_PERIODS
        ))
    }

    async fn http_get_text(client: &reqwest::Client, url: &str) -> Result<String> {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("GET {} failed: {}", url, e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| anyhow!("reading response body from {} failed: {}", url, e))?;

        if !status.is_success() {
            return Err(anyhow!(
                "GET {} returned status {} body='{}'",
                url,
                status,
                Self::truncate_for_log(&body, LOG_PREVIEW_CHARS)
            ));
        }

        Ok(body)
    }

    fn extract_finalized_slot_from_finality_update(body: &str) -> Result<u64> {
        let parsed: Value = serde_json::from_str(body)
            .map_err(|e| anyhow!("invalid JSON for finality update: {}", e))?;
        let slot = parsed
            .pointer("/data/finalized_header/beacon/slot")
            .or_else(|| parsed.pointer("/data/attested_header/beacon/slot"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("finality update missing finalized/attested beacon slot"))?;
        slot.parse::<u64>()
            .map_err(|e| anyhow!("invalid finality slot '{}': {}", slot, e))
    }

    fn extract_checkpoint_slot_from_updates(body: &str) -> Result<Option<u64>> {
        let parsed: Value = serde_json::from_str(body)
            .map_err(|e| anyhow!("invalid JSON for light-client updates: {}", e))?;
        let entries = parsed
            .as_array()
            .ok_or_else(|| anyhow!("light-client updates response must be a JSON array"))?;
        let Some(first) = entries.first() else {
            return Ok(None);
        };
        let slot = first
            .pointer("/data/finalized_header/beacon/slot")
            .or_else(|| first.pointer("/data/attested_header/beacon/slot"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("light-client update missing finalized/attested beacon slot"))?;
        let parsed_slot = slot
            .parse::<u64>()
            .map_err(|e| anyhow!("invalid update slot '{}': {}", slot, e))?;
        Ok(Some(parsed_slot))
    }

    fn extract_block_root(body: &str) -> Result<B256> {
        let parsed: Value = serde_json::from_str(body)
            .map_err(|e| anyhow!("invalid JSON for block root: {}", e))?;
        let root = parsed
            .pointer("/data/root")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("block root response missing data.root"))?;
        B256::from_str(root).map_err(|e| anyhow!("invalid block root '{}': {}", root, e))
    }

    fn truncate_for_log(value: &str, max_chars: usize) -> String {
        let mut it = value.chars();
        let preview: String = it.by_ref().take(max_chars).collect();
        if it.next().is_some() {
            format!("{}...", preview)
        } else {
            preview
        }
    }

    async fn run_helios_opstack(
        port: u16,
        network: &str,
        execution_rpc: &str,
        consensus_rpc: Option<&str>,
    ) -> Result<OpStackClient> {
        let net = Self::parse_opstack_network(network)?;

        // Bind only to localhost — internal enclave access only
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .parse()
            .map_err(|e| anyhow!("Invalid address: {}", e))?;

        info!("Building Helios OP Stack client for {} network", network);
        info!("Execution RPC: {}", execution_rpc);

        let consensus_rpc = if let Some(value) = consensus_rpc {
            value.to_string()
        } else {
            OpNetworkConfig::from(net)
                .consensus_rpc
                .as_ref()
                .map(|url| url.as_str().to_string())
                .ok_or_else(|| {
                    anyhow!(
                        "Helios OP Stack network '{}' missing default consensus RPC",
                        net
                    )
                })?
        };

        info!("Consensus RPC: {}", consensus_rpc);

        let client = OpStackClientBuilder::new()
            .network(net)
            .consensus_rpc(consensus_rpc.as_str())
            .execution_rpc(execution_rpc)
            .rpc_socket(addr)
            .build()
            .map_err(|e| anyhow!("Failed to build Helios OP Stack client: {}", e))?;

        info!("Helios OP Stack client built, waiting for sync...");

        // Wait for initial sync
        client
            .wait_synced()
            .await
            .map_err(|e| anyhow!("Helios OP Stack sync failed: {}", e))?;

        info!("Helios OP Stack sync complete");

        Ok(client)
    }

    fn parse_ethereum_network(network: &str) -> Result<Network> {
        match network.to_lowercase().as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "sepolia" => Ok(Network::Sepolia),
            "holesky" => Ok(Network::Holesky),
            other => Err(anyhow!(
                "Unsupported ethereum network '{}'. Supported: mainnet, sepolia, holesky.",
                other
            )),
        }
    }

    fn parse_opstack_network(network: &str) -> Result<OpNetwork> {
        match network.to_lowercase().as_str() {
            "op-mainnet" => Ok(OpNetwork::OpMainnet),
            "base" => Ok(OpNetwork::Base),
            "base-sepolia" => Ok(OpNetwork::BaseSepolia),
            "worldchain" => Ok(OpNetwork::Worldchain),
            "zora" => Ok(OpNetwork::Zora),
            "unichain" => Ok(OpNetwork::Unichain),
            other => Err(anyhow!(
                "Unsupported opstack network '{}'. Supported: op-mainnet, base, base-sepolia, worldchain, zora, unichain.",
                other
            )),
        }
    }

    /// Check if Helios is ready (synced).
    /// Returns true if synced, false if failed, or true if Helios is not configured.
    #[allow(dead_code)]
    pub async fn wait_ready(&mut self) -> bool {
        if self.ready_rxs.is_empty() {
            return true;
        }

        let mut all_ready = true;
        for (_, rx) in self.ready_rxs.drain(..) {
            all_ready &= rx.await.unwrap_or(false);
        }

        all_ready
    }

    /// Wait for readiness of a specific Helios local RPC port.
    /// Returns false when the tracked port is missing or that Helios task fails.
    pub async fn wait_ready_for_port(&mut self, port: u16) -> bool {
        if self.ready_rxs.is_empty() {
            return true;
        }

        let Some(idx) = self
            .ready_rxs
            .iter()
            .position(|(tracked_port, _)| *tracked_port == port)
        else {
            warn!(
                "No Helios readiness tracker found for required local RPC port {}",
                port
            );
            return false;
        };

        let (_, rx) = self.ready_rxs.swap_remove(idx);
        rx.await.unwrap_or(false)
    }

    /// Stop the Helios service
    pub async fn stop(self) {
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that HeliosRpcService::start returns Ok with no task when config is None
    #[tokio::test]
    async fn test_helios_service_no_config() {
        // Create a minimal Configuration with no helios_rpc
        // Since we can't easily construct Configuration in tests,
        // we test the service's behavior by checking the struct fields
        let service = HeliosRpcService {
            tasks: Vec::new(),
            ready_rxs: Vec::new(),
        };

        // Should be ready immediately since no Helios is configured
        let mut service = service;
        assert!(service.wait_ready().await);
    }

    /// Test ethereum network name parsing - mainnet
    #[test]
    fn test_ethereum_network_name_mainnet() {
        assert!(matches!(
            HeliosRpcService::parse_ethereum_network("mainnet").unwrap(),
            Network::Mainnet
        ));
    }

    /// Test ethereum network name parsing - sepolia
    #[test]
    fn test_ethereum_network_name_sepolia() {
        assert!(matches!(
            HeliosRpcService::parse_ethereum_network("Sepolia").unwrap(),
            Network::Sepolia
        ));
    }

    /// Test ethereum network name parsing - holesky
    #[test]
    fn test_ethereum_network_name_holesky() {
        assert!(matches!(
            HeliosRpcService::parse_ethereum_network("HOLESKY").unwrap(),
            Network::Holesky
        ));
    }

    /// Test ethereum network name parsing - unsupported network
    #[test]
    fn test_ethereum_network_name_unsupported() {
        assert!(HeliosRpcService::parse_ethereum_network("op-mainnet").is_err());
    }

    #[test]
    fn test_opstack_network_supported_values() {
        let supported = [
            "op-mainnet",
            "base",
            "base-sepolia",
            "worldchain",
            "zora",
            "unichain",
        ];

        for value in supported {
            assert!(HeliosRpcService::parse_opstack_network(value).is_ok());
        }
    }

    #[test]
    fn test_opstack_network_rejects_unsupported_values() {
        // Previously documented, but not supported by the vendored Helios OP Stack implementation.
        assert!(HeliosRpcService::parse_opstack_network("optimism").is_err());
        assert!(HeliosRpcService::parse_opstack_network("worldchain-sepolia").is_err());
    }

    /// Test address parsing
    #[test]
    fn test_address_parsing() {
        let port = 8545u16;
        let addr: std::result::Result<std::net::SocketAddr, _> =
            format!("127.0.0.1:{}", port).parse();
        assert!(addr.is_ok());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 8545);
        assert!(addr.ip().is_loopback());
    }

    /// Test address parsing with custom port
    #[test]
    fn test_address_parsing_custom_port() {
        let port = 9999u16;
        let addr: std::result::Result<std::net::SocketAddr, _> =
            format!("127.0.0.1:{}", port).parse();
        assert!(addr.is_ok());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 9999);
    }

    #[test]
    fn test_extract_finalized_slot_from_finality_update_uses_finalized_slot() {
        let payload = r#"{
          "data": {
            "finalized_header": { "beacon": { "slot": "13762560" } },
            "attested_header": { "beacon": { "slot": "13762633" } }
          }
        }"#;
        let slot = HeliosRpcService::extract_finalized_slot_from_finality_update(payload).unwrap();
        assert_eq!(slot, 13_762_560);
    }

    #[test]
    fn test_extract_checkpoint_slot_from_updates_accepts_non_empty_array() {
        let payload = r#"[{
          "data": {
            "finalized_header": { "beacon": { "slot": "13762560" } }
          }
        }]"#;
        let slot = HeliosRpcService::extract_checkpoint_slot_from_updates(payload).unwrap();
        assert_eq!(slot, Some(13_762_560));
    }

    #[test]
    fn test_extract_checkpoint_slot_from_updates_handles_empty_array() {
        let slot = HeliosRpcService::extract_checkpoint_slot_from_updates("[]").unwrap();
        assert_eq!(slot, None);
    }

    #[test]
    fn test_extract_block_root_parses_b256() {
        let payload = r#"{"data":{"root":"0xc133dddd87f3b27c23af60e548de64cb88ab960993c62fe98ee75c620e6812e3"}}"#;
        let root = HeliosRpcService::extract_block_root(payload).unwrap();
        assert_eq!(
            format!("{root:?}"),
            "0xc133dddd87f3b27c23af60e548de64cb88ab960993c62fe98ee75c620e6812e3"
        );
    }

    /// Test service stop when no task is running
    #[tokio::test]
    async fn test_helios_service_stop_no_task() {
        let service = HeliosRpcService {
            tasks: Vec::new(),
            ready_rxs: Vec::new(),
        };

        // Should not panic
        service.stop().await;
    }

    #[tokio::test]
    async fn test_wait_ready_for_port_tracks_requested_port_only() {
        let (tx_auth, rx_auth) = tokio::sync::oneshot::channel();
        let (tx_optional, rx_optional) = tokio::sync::oneshot::channel();
        let mut service = HeliosRpcService {
            tasks: Vec::new(),
            ready_rxs: vec![(18545, rx_auth), (18546, rx_optional)],
        };

        tx_auth.send(true).unwrap();
        tx_optional.send(false).unwrap();

        assert!(service.wait_ready_for_port(18545).await);
    }

    #[tokio::test]
    async fn test_wait_ready_for_port_missing_port_returns_false() {
        let (_tx, rx) = tokio::sync::oneshot::channel();
        let mut service = HeliosRpcService {
            tasks: Vec::new(),
            ready_rxs: vec![(18545, rx)],
        };

        assert!(!service.wait_ready_for_port(19999).await);
    }
}
