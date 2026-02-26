# Helios RPC Integration

Enclaver supports running one or more Helios light clients inside the enclave through `helios_rpc.chains`.
Each configured chain exposes a local JSON-RPC endpoint on `127.0.0.1:<local_rpc_port>`.

## Why this matters

Helios verifies execution data with consensus proofs, so your app can read on-chain data without trusting an external execution RPC response.

## Supported chain kinds and networks

### `kind: ethereum`
- `mainnet`
- `sepolia`
- `holesky`

### `kind: opstack`
- `op-mainnet`
- `base`
- `base-sepolia`
- `worldchain`
- `zora`
- `unichain`

## Manifest configuration

```yaml
helios_rpc:
  enabled: true
  chains:
    - name: "L2-base-sepolia"
      network_id: "84532"
      kind: "opstack"
      network: "base-sepolia"
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545

    - name: "ethereum-mainnet"
      network_id: "1"
      kind: "ethereum"
      network: "mainnet"
      execution_rpc: "https://eth.llamarpc.com"
      local_rpc_port: 18546
```

## Field reference

### `helios_rpc`

| Field | Required | Description |
|---|---|---|
| `enabled` | No | Enables Helios services when `true`. |
| `chains` | Yes (when enabled) | List of chain-specific Helios instances. |

### `helios_rpc.chains[]`

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Human-readable chain config name used in logs/UI. |
| `network_id` | No | Chain id for display/reference. |
| `kind` | Yes | `ethereum` or `opstack`. |
| `network` | Yes | Network slug valid for the selected `kind`. |
| `execution_rpc` | Yes | Upstream execution RPC URL used by Helios. |
| `local_rpc_port` | Yes | Local port exposed inside enclave (`127.0.0.1`). |
| `consensus_rpc` | No | Custom consensus RPC endpoint. |
| `checkpoint` | No | Weak subjectivity checkpoint (ethereum). |

When `kind=ethereum` and `checkpoint` is omitted, odyn will try to derive a recent checkpoint from `consensus_rpc` at startup.  
If derivation fails, it falls back to Helios external checkpoint discovery.

## Application usage

Use the chain's `local_rpc_port` from `helios_rpc.chains`.

### Python

```python
from web3 import Web3

base = Web3(Web3.HTTPProvider("http://127.0.0.1:18545"))
eth = Web3(Web3.HTTPProvider("http://127.0.0.1:18546"))

print(base.eth.chain_id)
print(eth.eth.block_number)
```

### JavaScript

```javascript
import { ethers } from "ethers";

const baseProvider = new ethers.JsonRpcProvider("http://127.0.0.1:18545");
const ethProvider = new ethers.JsonRpcProvider("http://127.0.0.1:18546");

console.log(await baseProvider.getBlockNumber());
console.log(await ethProvider.getNetwork());
```

## Startup behavior

- Odyn starts Helios in the background for each configured chain.
- Your app can start immediately.
- Helios endpoints become fully ready after initial sync.
- If registry-backed KMS mode is enabled (`kms_app_id` + `nova_app_registry`),
  one chain must use `local_rpc_port: 18545` so Nova KMS registry discovery can
  use the built-in local RPC endpoint.

## Egress requirements

For each chain entry, allow egress to:
- The domain used by `execution_rpc`.
- The corresponding consensus/checkpoint services (default or custom).

Example:

```yaml
egress:
  allow:
    - "sepolia.base.org"
    - "eth.llamarpc.com"
    - "*.lightclientdata.org"
    - "*.operationsolarstorm.org"
```

## Security notes

- Helios endpoints bind to `127.0.0.1` only.
- External clients cannot directly access these local endpoints unless you explicitly expose the ports via `ingress`.
- Treat checkpoint sources as trusted inputs.
