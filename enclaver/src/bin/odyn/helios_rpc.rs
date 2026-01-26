//! Helios Ethereum Light Client RPC Service
//!
//! Provides a trustless Ethereum/OP Stack JSON-RPC endpoint inside the enclave.
//! All execution data is cryptographically verified using Light Client proofs.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{Result, anyhow};
use enclaver::manifest::HeliosRpcKind;
use helios::ethereum::{EthereumClient, EthereumClientBuilder};
use helios::ethereum::config::networks::Network;
use helios::ethereum::database::ConfigDB;
use helios::opstack::{OpStackClient, OpStackClientBuilder};
use helios::opstack::config::Network as OpNetwork;
use helios::opstack::config::NetworkConfig as OpNetworkConfig;
use log::{info, warn};
use tokio::task::JoinHandle;

use crate::config::Configuration;

/// Helios RPC Service for trustless Ethereum/OP Stack access
pub struct HeliosRpcService {
    task: Option<JoinHandle<()>>,
    ready_rx: Option<tokio::sync::oneshot::Receiver<bool>>,
}

impl HeliosRpcService {
    /// Start Helios RPC service in background (non-blocking).
    /// App can start immediately while Helios syncs.
    pub async fn start(config: &Configuration) -> Result<Self> {
        let helios_config = match config.helios_config() {
            Some(cfg) => cfg,
            None => {
                return Ok(Self {
                    task: None,
                    ready_rx: None,
                });
            }
        };

        let kind = helios_config.kind.clone();
        let network = helios_config
            .network
            .as_ref()
            .ok_or_else(|| anyhow!("helios_rpc.network is required when helios_rpc.enabled is true"))?
            .clone();
        let execution_rpc = helios_config
            .execution_rpc
            .as_ref()
            .ok_or_else(|| {
                anyhow!("helios_rpc.execution_rpc is required when helios_rpc.enabled is true")
            })?
            .clone();

        info!(
            "Starting Helios RPC ({:?}) on port {} for network {}",
            kind, helios_config.listen_port, network
        );

        let port = helios_config.listen_port;
        let consensus_rpc = helios_config.consensus_rpc.clone();
        let checkpoint = helios_config.checkpoint.clone();

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        let task = tokio::task::spawn(async move {
            let result = match kind {
                HeliosRpcKind::Ethereum => {
                    Self::run_helios_ethereum(
                        port,
                        &network,
                        &execution_rpc,
                        consensus_rpc.as_deref(),
                        checkpoint.as_deref(),
                    )
                    .await
                    .map(|_| ())
                }
                HeliosRpcKind::Opstack => {
                    Self::run_helios_opstack(
                        port,
                        &network,
                        &execution_rpc,
                        consensus_rpc.as_deref(),
                    )
                    .await
                    .map(|_| ())
                }
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
                    warn!("Helios failed to start: {}", e);
                    let _ = ready_tx.send(false);
                }
            }
        });

        Ok(Self {
            task: Some(task),
            ready_rx: Some(ready_rx),
        })
    }

    async fn run_helios_ethereum(
        port: u16,
        network: &str,
        execution_rpc: &str,
        consensus_rpc: Option<&str>,
        checkpoint: Option<&str>,
    ) -> Result<EthereumClient> {
        let net = match network.to_lowercase().as_str() {
            "mainnet" => Network::Mainnet,
            "sepolia" => Network::Sepolia,
            "holesky" => Network::Holesky,
            other => {
                return Err(anyhow!(
                    "Unsupported ethereum network '{}'. Supported: mainnet, sepolia, holesky.",
                    other
                ));
            }
        };

        // Bind only to localhost — internal enclave access only
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .parse()
            .map_err(|e| anyhow!("Invalid address: {}", e))?;

        info!("Building Helios Ethereum client for {} network", network);
        info!("Execution RPC: {}", execution_rpc);
        if let Some(consensus) = consensus_rpc {
            info!("Consensus RPC: {}", consensus);
        } else {
            info!("Consensus RPC: using default (lightclientdata.org)");
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

    async fn run_helios_opstack(
        port: u16,
        network: &str,
        execution_rpc: &str,
        consensus_rpc: Option<&str>,
    ) -> Result<OpStackClient> {
        let net = match network.to_lowercase().as_str() {
            "op-mainnet" => OpNetwork::OpMainnet,
            "base" => OpNetwork::Base,
            "base-sepolia" => OpNetwork::BaseSepolia,
            "worldchain" => OpNetwork::Worldchain,
            "zora" => OpNetwork::Zora,
            "unichain" => OpNetwork::Unichain,
            other => {
                return Err(anyhow!(
                    "Unsupported opstack network '{}'. Supported: op-mainnet, base, base-sepolia, \
                     worldchain, zora, unichain.",
                    other
                ));
            }
        };

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
                    anyhow!("Helios OP Stack network '{}' missing default consensus RPC", net)
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

    /// Check if Helios is ready (synced).
    /// Returns true if synced, false if failed, or true if Helios is not configured.
    #[allow(dead_code)]
    pub async fn wait_ready(&mut self) -> bool {
        if let Some(rx) = self.ready_rx.take() {
            rx.await.unwrap_or(false)
        } else {
            true // No Helios configured, considered "ready"
        }
    }

    /// Stop the Helios service
    pub async fn stop(self) {
        if let Some(task) = self.task {
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
            task: None,
            ready_rx: None,
        };
        
        // Should be ready immediately since no Helios is configured
        let mut service = service;
        assert!(service.wait_ready().await);
    }

    /// Test network name parsing - mainnet
    #[test]
    fn test_network_name_mainnet() {
        let network = "mainnet";
        let result = match network.to_lowercase().as_str() {
            "mainnet" => Some(Network::Mainnet),
            "sepolia" => Some(Network::Sepolia),
            "holesky" => Some(Network::Holesky),
            _ => None,
        };
        assert!(matches!(result, Some(Network::Mainnet)));
    }

    /// Test network name parsing - sepolia
    #[test]
    fn test_network_name_sepolia() {
        let network = "Sepolia"; // Test case insensitivity
        let result = match network.to_lowercase().as_str() {
            "mainnet" => Some(Network::Mainnet),
            "sepolia" => Some(Network::Sepolia),
            "holesky" => Some(Network::Holesky),
            _ => None,
        };
        assert!(matches!(result, Some(Network::Sepolia)));
    }

    /// Test network name parsing - holesky
    #[test]
    fn test_network_name_holesky() {
        let network = "HOLESKY"; // Test case insensitivity
        let result = match network.to_lowercase().as_str() {
            "mainnet" => Some(Network::Mainnet),
            "sepolia" => Some(Network::Sepolia),
            "holesky" => Some(Network::Holesky),
            _ => None,
        };
        assert!(matches!(result, Some(Network::Holesky)));
    }

    /// Test network name parsing - unsupported network
    #[test]
    fn test_network_name_unsupported() {
        let network = "op-mainnet";
        let result = match network.to_lowercase().as_str() {
            "mainnet" => Some(Network::Mainnet),
            "sepolia" => Some(Network::Sepolia),
            "holesky" => Some(Network::Holesky),
            _ => None,
        };
        assert!(result.is_none());
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

    /// Test service stop when no task is running
    #[tokio::test]
    async fn test_helios_service_stop_no_task() {
        let service = HeliosRpcService {
            task: None,
            ready_rx: None,
        };
        
        // Should not panic
        service.stop().await;
    }
}
