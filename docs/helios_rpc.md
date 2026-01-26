# Helios Ethereum Light Client Integration

Enclaver provides an optional **Helios light client** integration that gives enclave applications access to a **trustless Ethereum RPC endpoint**. This allows your application to query blockchain data without trusting external RPC providers — all responses are cryptographically verified using Ethereum's consensus mechanism.

---

## Overview

### Why Use Helios?

When your enclave application needs to interact with Ethereum (query balances, read contract state, submit transactions), it typically relies on external RPC providers like Alchemy or Infura. However, these providers must be trusted:

| Approach | Trust Model |
|----------|-------------|
| **External RPC** | ❌ Must trust the provider returns correct data |
| **Full Node** | ✅ Trustless, but requires 1TB+ storage and hours to sync |
| **Helios Light Client** | ✅ Trustless, syncs in seconds, minimal resources |

Helios verifies all execution data using Light Client proofs from the Ethereum consensus layer, ensuring your enclave receives authentic blockchain data.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AWS Nitro Enclave                       │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                 Odyn Supervisor                     │   │
│   │                                                     │   │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐   │   │
│   │  │ Ingress │ │ Egress  │ │   API   │ │  Helios  │   │   │
│   │  │  Proxy  │ │  Proxy  │ │ Server  │ │   RPC    │   │   │
│   │  └─────────┘ └─────────┘ └─────────┘ └──────────┘   │   │
│   │                                           │         │   │
│   │                                           ▼         │   │
│   │  ┌─────────────────────────────────────────────┐   │   │
│   │  │              Your Application               │   │   │
│   │  │         http://127.0.0.1:8545              │   │   │
│   │  └─────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────┘   │
│                              │                              │
└──────────────────────────────│──────────────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │   External RPCs     │
                    │  (Verified by       │
                    │   Light Client)     │
                    └─────────────────────┘
```

---

## Supported Networks

### Ethereum (kind: ethereum)

| Network | Config Value | Status |
|---------|--------------|--------|
| Ethereum Mainnet | `mainnet` | ✅ Supported |
| Ethereum Sepolia | `sepolia` | ✅ Supported |
| Ethereum Holesky | `holesky` | ✅ Supported |

### OP Stack (kind: opstack)

| Network | Config Value | Status |
|---------|--------------|--------|
| OP Mainnet | `op-mainnet` | ✅ Supported |
| Base Mainnet | `base` | ✅ Supported |
| Base Sepolia | `base-sepolia` | ✅ Supported |
| Worldchain Mainnet | `worldchain` | ✅ Supported |
| Zora Mainnet | `zora` | ✅ Supported |
| Unichain Mainnet | `unichain` | ✅ Supported |

---

## Configuration

Enable Helios in your `enclaver.yaml`:

### Ethereum Example

```yaml
version: v1
name: "my-defi-app"
target: "my-defi-app:enclave"

sources:
  app: "my-defi-app:latest"

# Enable Helios light client for Ethereum
helios_rpc:
  enabled: true
  kind: ethereum           # Required: "ethereum" or "opstack"
  listen_port: 8545
  network: mainnet
  execution_rpc: "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY"

# Egress must allow Helios to reach external RPCs
egress:
  allow:
    - "*.lightclientdata.org"      # Default consensus RPC
    - "eth-mainnet.g.alchemy.com"  # Your execution RPC
    - "*.beaconcha.in"             # Checkpoint fallback services

api:
  listen_port: 9000
```

### OP Stack Example (Base Sepolia)

```yaml
version: v1
name: "my-l2-app"
target: "my-l2-app:enclave"

sources:
  app: "my-l2-app:latest"

# Enable Helios light client for OP Stack
helios_rpc:
  enabled: true
  kind: opstack            # Required: "ethereum" or "opstack"
  listen_port: 8545
  network: base-sepolia
  execution_rpc: "https://rpc.ankr.com/base_sepolia"

# Egress must allow Helios to reach external RPCs
egress:
  allow:
    - "rpc.ankr.com"
    - "*.operationsolarstorm.org"   # Default OP Stack consensus RPC

api:
  listen_port: 9000
```

### Configuration Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `enabled` | No | `false` | Enable/disable Helios |
| `kind` | **Yes** | — | Client type: `ethereum` or `opstack` |
| `listen_port` | No | `8545` | Port for JSON-RPC server (internal only) |
| `network` | Yes | — | Network to connect to (see tables above) |
| `execution_rpc` | Yes | — | Untrusted execution RPC URL |
| `consensus_rpc` | No | Depends on `kind` | Consensus RPC URL (ethereum: `lightclientdata.org`; opstack: per-network `operationsolarstorm.org`) |
| `checkpoint` | No | Auto-fetched | Weak subjectivity checkpoint (ethereum only) |

---

## Usage in Your Application

### Python (web3.py)

```python
from web3 import Web3
import time

# Connect to Helios RPC inside the enclave
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# Optional: wait for Helios to sync (usually <30 seconds)
while not w3.is_connected():
    print("Waiting for Helios to sync...")
    time.sleep(2)

print(f"Connected! Block: {w3.eth.block_number}")

# All queries are cryptographically verified
balance = w3.eth.get_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
print(f"Balance: {w3.from_wei(balance, 'ether')} ETH")

# Read contract state
result = w3.eth.call({
    "to": "0x...",
    "data": "0x..."
})

# Send signed transactions
tx_hash = w3.eth.send_raw_transaction(signed_tx)
```

### JavaScript (ethers.js)

```javascript
const { ethers } = require("ethers");

// Trustless provider inside enclave
const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");

async function main() {
    // Wait for connection
    await provider.ready;
    
    const blockNumber = await provider.getBlockNumber();
    console.log(`Connected! Block: ${blockNumber}`);
    
    // All queries verified by light client
    const balance = await provider.getBalance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    console.log(`Balance: ${ethers.formatEther(balance)} ETH`);
}

main();
```

### Rust (alloy)

```rust
use alloy::providers::{Provider, ProviderBuilder};
use alloy::primitives::address;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Connect to Helios inside enclave
    let provider = ProviderBuilder::new()
        .on_http("http://127.0.0.1:8545".parse()?);
    
    let block = provider.get_block_number().await?;
    println!("Block: {}", block);
    
    let balance = provider.get_balance(
        address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
    ).await?;
    println!("Balance: {} wei", balance);
    
    Ok(())
}
```

---

## Supported RPC Methods

Helios supports the standard Ethereum JSON-RPC API:

### Account Methods
- `eth_getBalance` — Get account balance
- `eth_getTransactionCount` — Get account nonce
- `eth_getCode` — Get contract bytecode
- `eth_getStorageAt` — Get storage slot value
- `eth_getProof` — Get Merkle proof

### Block Methods
- `eth_blockNumber` — Get latest block number
- `eth_getBlockByNumber` — Get block by number
- `eth_getBlockByHash` — Get block by hash
- `eth_getBlockReceipts` — Get all receipts in block

### Transaction Methods
- `eth_call` — Execute read-only call
- `eth_estimateGas` — Estimate gas for transaction
- `eth_sendRawTransaction` — Submit signed transaction
- `eth_getTransactionByHash` — Get transaction details
- `eth_getTransactionReceipt` — Get transaction receipt

### Other Methods
- `eth_chainId` — Get chain ID
- `eth_gasPrice` — Get current gas price
- `eth_maxPriorityFeePerGas` — Get priority fee
- `eth_getLogs` — Query event logs
- `eth_subscribe` — Subscribe to events (newHeads only)

---

## Startup Behavior

Helios starts in the **background** and syncs while your application starts:

1. Enclave boots, Odyn starts services
2. Helios begins syncing (fetches checkpoint, verifies headers)
3. **Your app starts immediately** — doesn't wait for sync
4. Helios becomes ready after ~10-30 seconds
5. RPC requests are queued until sync completes

> [!TIP]
> If your app needs guaranteed blockchain access at startup, add a connection check loop (see examples above).

---

## Egress Requirements

Helios needs to reach external services through the egress proxy. Add these domains to your `egress.allow` list:

| Domain | Purpose |
|--------|---------|
| `*.lightclientdata.org` | Default consensus RPC |
| Your execution RPC domain | Execution queries |
| `*.beaconcha.in` | Checkpoint fallback |
| `beaconstate.info` | Checkpoint fallback |

Example for Ethereum Mainnet with Alchemy:

```yaml
egress:
  allow:
    - "*.lightclientdata.org"
    - "eth-mainnet.g.alchemy.com"
    - "*.beaconcha.in"
```

---

## Security Considerations

### Trust Model

| Component | Trust Level |
|-----------|-------------|
| Execution RPC (Alchemy, etc.) | ❌ Untrusted — all data verified |
| Consensus RPC | ⚠️ Semi-trusted for header delivery |
| Initial Checkpoint | ⚠️ Trusted (weak subjectivity) |
| Verification | ✅ Cryptographic proofs |

### Weak Subjectivity

Helios requires an initial checkpoint (a recent finalized block hash) to start syncing. This is the "root of trust" for the light client. By default, Helios fetches this from trusted fallback services.

> [!CAUTION]
> If using a custom checkpoint, ensure it's from a trusted source. A malicious checkpoint could cause Helios to sync to the wrong chain.

### Network Isolation

The Helios RPC server binds to `127.0.0.1` only — it's **not accessible from outside the enclave**. External clients cannot query your Helios instance.

---

## Troubleshooting

### Helios won't sync

1. Check egress allowlist includes consensus RPC domain
2. Verify execution RPC URL is correct and accessible
3. Check enclave logs for specific error messages

### Slow initial sync

Normal — Helios needs to fetch and verify headers. Should complete in 10-30 seconds.

### RPC requests timeout

Helios queues requests until synced. If your app starts making calls immediately, add retry logic or wait for connection.

### Checkpoint too old warning

Helios will warn if checkpoint is >2 weeks old but will still sync. For production, consider updating checkpoints regularly.

---

## Related Documentation

- [Odyn Supervisor](odyn.md) — Overview of all enclave services
- [Internal API](internal_api.md) — Other enclave APIs (attestation, signing)
- [Helios GitHub](https://github.com/sparsity-xyz/helios) — Helios source code
