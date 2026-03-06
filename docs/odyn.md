# Odyn — Enclave Supervisor

Odyn is the supervisor process that runs inside the AWS Nitro Enclave. It acts as the bridge between your application and the enclave's secure hardware features, providing essential services that make enclave development straightforward.

---

## What is Odyn?

**Odyn** (named after the Norse god Odin) is automatically injected into your application's Docker image during the `enclaver build` process. When your enclave starts, Odyn runs as PID 1 (the init process) and is responsible for:

1. **Bootstrapping the enclave environment** — Setting up networking and secure random number generation
2. **Launching your application** — Starting and supervising your application process
3. **Providing platform services** — Attestation, signing, encryption, storage, and KMS/app-wallet routes via the Internal API
4. **Managing runtime plumbing** — Ingress, egress, clock sync, and optional Helios RPC
5. **Streaming logs and status** — Making application logs available to the host

```text
┌──────────────────────────────────────────────────────────────────────┐
│                        AWS Nitro Enclave                             │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                   Odyn Supervisor (PID 1)                     │  │
│  │                                                                │  │
│  │  Runtime services                                              │  │
│  │  ┌─────────┐ ┌─────────┐ ┌────────────┐ ┌─────────┐ ┌────────┐ │  │
│  │  │ Ingress │ │ Egress  │ │ Clock Sync │ │ Helios  │ │Console │ │  │
│  │  │ Proxy   │ │ Proxy   │ │            │ │ RPC     │ │ / Logs │ │  │
│  │  └─────────┘ └─────────┘ └────────────┘ └─────────┘ └────────┘ │  │
│  │                                                                │  │
│  │  Internal API (`/v1/*`)                                        │  │
│  │  - attestation / signing / random                              │  │
│  │  - encryption (`/v1/encryption/*`)                             │  │
│  │  - storage (`/v1/s3/*`)                                        │  │
│  │  - kms + app-wallet (`/v1/kms/*`, `/v1/app-wallet/*`)          │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │                  Your Application                        │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## How Odyn Works with Your Application

### Startup Sequence

When the enclave starts, Odyn performs the following steps in order:

```mermaid
sequenceDiagram
    participant Enclave
    participant Odyn
    participant App as Your Application

    Enclave->>Odyn: Start (as PID 1)
    Odyn->>Odyn: Bootstrap (loopback, RNG seed)
    Odyn->>Odyn: Start Egress Proxy (if configured)
    Odyn->>Odyn: Start Clock Sync (default; unless disabled)
    Odyn->>Odyn: Start Helios RPC (if configured)
    Odyn->>Odyn: Wait for Helios :18545 if registry-backed KMS is enabled
    Odyn->>Odyn: Start Internal API + Aux API
    Odyn->>Odyn: Start Ingress Proxies
    Odyn->>App: Launch your application
    
    loop Runtime
        App->>Odyn: Use API (attestation, signing, etc.)
        App->>Odyn: Outbound HTTP (via egress proxy)
        Odyn->>App: Inbound connections (via ingress proxy)
    end
    
    App-->>Odyn: Exit
    Odyn->>Odyn: Cleanup and report status
```

### Environment Variables Set by Odyn

Odyn automatically sets the following environment variables for your application:

| Environment Variable | Value | Condition |
|---------------------|-------|-----------|
| `http_proxy` | `http://127.0.0.1:<proxy_port>` | If egress is enabled |
| `https_proxy` | `http://127.0.0.1:<proxy_port>` | If egress is enabled |
| `HTTP_PROXY` | `http://127.0.0.1:<proxy_port>` | If egress is enabled |
| `HTTPS_PROXY` | `http://127.0.0.1:<proxy_port>` | If egress is enabled |
| `no_proxy` | `localhost,127.0.0.1` | If egress is enabled |
| `NO_PROXY` | `localhost,127.0.0.1` | If egress is enabled |

> [!TIP]
> **Recommended Convention**: Use an `IN_ENCLAVE` environment variable in your Dockerfile to help your application detect whether it's running inside an enclave:
> ```dockerfile
> # Set to false in your base Dockerfile
> ENV IN_ENCLAVE=false
> ```
> Then in your application's layer (added during `enclaver build`), this can be overridden. Or, your application can detect the enclave environment by checking if the Odyn API is available at `http://127.0.0.1:<api_port>/v1/eth/address`.

---

## Odyn Modules

Odyn consists of several configurable modules, each providing specific functionality:

Standalone runtime services include ingress, egress, clock sync, console/log streaming, and optional Helios RPC. Encryption, storage, and KMS/app-wallet features are exposed through the Internal API rather than running as peer daemons.

### 1. Ingress Proxy

**Purpose**: Allows external clients to connect to your application inside the enclave.

**How it works**:
- Listens on configured TCP ports inside the enclave
- Receives connections forwarded from the host via VSOCK
- Forwards traffic to your application's localhost port

> **Recommendation**: Use the built-in E2E encryption endpoints (`/v1/encryption/encrypt`, `/v1/encryption/decrypt`) for tee-pubkey-based client-to-enclave encrypted transport.

**Configuration**:
```yaml
ingress:
  - listen_port: 8080        # Your app listens on 127.0.0.1:8080
```

**For your app**: Simply bind to `127.0.0.1:<listen_port>` — Odyn handles the rest.

---

### 2. Egress Proxy

**Purpose**: Allows your application to make outbound HTTP/HTTPS requests to approved destinations.

**How it works**:
- Runs a local HTTP proxy inside the enclave
- Sets `http_proxy` and `https_proxy` environment variables
- Enforces an allow/deny list for security
- Routes traffic through VSOCK to the host, which makes the actual network requests

**Configuration**:
```yaml
egress:
  proxy_port: 10000          # Default port for the proxy
  allow:
    - "api.example.com"      # Exact domain
    - "*.amazonaws.com"      # Wildcard subdomain
    - "169.254.169.254"      # IMDS (required for KMS)
  deny:
    - "*.internal.com"       # Block specific patterns
```

**For your app**: Most HTTP libraries automatically use `http_proxy`/`https_proxy` environment variables. No code changes needed.

---

### 3. Clock Synchronization

**Purpose**: Keeps the enclave wall clock close to host time so long-running enclaves do not accumulate drift.

**How it works**:
- Enabled by default, even when `clock_sync` is omitted from `enclaver.yaml`
- Performs an initial sync during Odyn startup, then repeats periodically
- Uses a host-side VSOCK time server plus an RTT/offset estimate before updating `CLOCK_REALTIME`

**Configuration**:
```yaml
# Omit this block to keep defaults (enabled, every 300 seconds)
clock_sync:
  interval_secs: 300
  # enabled: false          # Optional: disable clock sync entirely
```

**For your app**: No integration is required. This improves operational correctness for JWT/TLS/expiry checks, but it still follows host wall-clock time and should not be treated as a cryptographic trust root.

---

### 4. Internal API Server

**Purpose**: Provides enclave-specific functionality to your application via HTTP endpoints.

**How it works**:
- Runs an HTTP server on a configured port
- Provides attestation, signing, encryption, and random number generation
- Uses the Nitro Secure Module (NSM) for hardware-backed security
- Optionally exposes Nova KMS routes when `kms_integration` is enabled, and app-wallet routes when `kms_integration.use_app_wallet=true`

**Configuration**:
```yaml
api:
  listen_port: 18000         # Internal API port
```

**Available Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/eth/address` | GET | Get enclave's Ethereum address |
| `/v1/eth/sign` | POST | Sign message (EIP-191) |
| `/v1/eth/sign-tx` | POST | Sign Ethereum transaction |
| `/v1/random` | GET | Get 32 random bytes from NSM |
| `/v1/attestation` | POST | Generate attestation document |
| `/v1/encryption/public_key` | GET | Get P-384 encryption public key |
| `/v1/encryption/encrypt` | POST | Encrypt data for client |
| `/v1/encryption/decrypt` | POST | Decrypt data from client |
| `/v1/s3/get` | POST | Get object from S3 storage |
| `/v1/s3/put` | POST | Put object to S3 storage |
| `/v1/s3/list` | POST | List objects in S3 storage |
| `/v1/s3/delete` | POST | Delete object from S3 storage |
| `/v1/kms/derive` | POST | Derive key material from Nova KMS (`kms_integration`) |
| `/v1/kms/kv/get` | POST | Read KMS-backed KV value (`kms_integration`) |
| `/v1/kms/kv/put` | POST | Write KMS-backed KV value (`kms_integration`) |
| `/v1/kms/kv/delete` | POST | Delete KMS-backed KV value (`kms_integration`) |
| `/v1/app-wallet/address` | GET | Get app-local wallet metadata (`kms_integration`) |
| `/v1/app-wallet/sign` | POST | Sign EIP-191 message with app wallet (`kms_integration`) |
| `/v1/app-wallet/sign-tx` | POST | Sign Ethereum tx with app wallet (`kms_integration`) |
Instances that map to the same KMS app namespace share one app-wallet.

**For your app**: Make HTTP requests to `http://127.0.0.1:<api_port>/v1/...`

📖 **See [Internal API Reference](internal_api.md) for complete endpoint documentation.**

📖 **See [Internal API Mock Service](internal_api_mockup.md) for guidance on external mock endpoints and compatibility caveats.**

---

### 5. Auxiliary API

**Purpose**: Provides a restricted subset of the Internal API for sidecar processes or untrusted components.

**How it works**:
- Starts automatically whenever the Internal API is enabled
- Proxies requests to the Internal API
- Sanitizes attestation requests (removes `public_key` to prevent key spoofing; `user_data` is forwarded)
- Only exposes safe, read-only endpoints

**Configuration**:
```yaml
aux_api:
  listen_port: 18001         # Optional override; otherwise defaults to api_port + 1
```

**Available Endpoints**:

| Endpoint | Method | Restrictions |
|----------|--------|--------------|
| `/v1/eth/address` | GET | Same as Internal API |
| `/v1/attestation` | POST | `public_key` is removed; `user_data` is forwarded |
| `/v1/encryption/public_key` | GET | Same as Internal API |

---

### 6. S3 Storage

**Purpose**: Provides automated persistent storage for enclave applications.

**How it works**:
- Proxies S3 requests to a dedicated S3 bucket
- Enforces key isolation (app-specific prefix)
- Uses IMDS-based credentials via the egress proxy
- Accessible via the Internal API

**Configuration**:
```yaml
storage:
  s3:
    enabled: true
    bucket: "my-app-data"
    prefix: "apps/my-service/"
    region: "us-east-1"
    encryption:              # Optional
      mode: "kms"            # plaintext | kms
      key_scope: "object"    # app | object
      aad_mode: "key"        # none | key | key+version
      key_version: "v1"
      accept_plaintext: true
```

**For your app**: Use the Internal API `/v1/s3/...` endpoints.

**Requirements**:
- Egress must allow `169.254.169.254` (IMDS)
- Egress must allow your S3 endpoint (e.g., `s3.us-east-1.amazonaws.com` or `s3.amazonaws.com`)
- If `storage.s3.encryption.mode=kms`, `kms_integration.enabled=true` is required.
- If `/v1/kms/*` registry mode is used (`kms_app_id` + `nova_app_registry`),
  `helios_rpc.enabled=true` is required and `helios_rpc.chains[]` must include
  `local_rpc_port: 18545` (used for registry discovery).

---

### 7. Console & Log Streaming

**Purpose**: Captures your application's stdout/stderr and streams it to the host.

**How it works**:
- Redirects stdout/stderr to a ring buffer
- Exposes logs over VSOCK for the host to consume
- Reports application status (running, exited, error)

**VSOCK Ports** (used by Sleeve/host):

| Port | Purpose |
|------|---------|
| 17000 | Status stream (JSON) |
| 17001 | Application logs |

**For your app**: Just print to stdout/stderr as normal — Odyn captures everything automatically.

---

## Complete Configuration Example

Here's a complete `enclaver.yaml` showing all Odyn-related configuration:

```yaml
version: v1
name: "my-secure-app"
target: "my-secure-app:latest"

sources:
  app: "my-app:latest"

# Ingress: allow inbound connections on port 8080
ingress:
  - listen_port: 8080

# Egress: allow outbound HTTPS to specific domains
egress:
  proxy_port: 10000
  allow:
    - "api.openai.com"
    - "169.254.169.254"        # Required for IMDS-backed AWS access (e.g. S3)

# Clock sync is enabled by default; include this block only to tune or disable it.
clock_sync:
  interval_secs: 300

# Internal API for attestation and signing
api:
  listen_port: 18000

# Aux API port override (the service also starts by default when API is enabled)
aux_api:
  listen_port: 18001

# Nova KMS integration (optional)
kms_integration:
  enabled: true
  use_app_wallet: true        # app-wallet local mode can use only these two fields
  kms_app_id: 49              # optional; required only for registry-backed /v1/kms/*
  nova_app_registry: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8" # optional; required only for /v1/kms/*

# Helios light-client RPC (required only when registry-backed /v1/kms/* is enabled)
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

# S3 Storage (optional)
storage:
  s3:
    enabled: true
    bucket: "my-app-data"
    prefix: "apps/my-service/"
```

---

## Summary

| Module | Port Config | Purpose | Your App Usage |
|--------|-------------|---------|----------------|
| **Ingress** | `ingress[].listen_port` | Accept external connections | Bind to `127.0.0.1:<port>` |
| **Egress** | `egress.proxy_port` | Make outbound HTTP requests | Automatic via `http_proxy` env var |
| **Clock Sync** | `clock_sync.interval_secs` / `clock_sync.enabled` | Keep enclave wall clock aligned with host time | Automatic; no app changes |
| **Internal API** | `api.listen_port` | Attestation, signing, encryption, KMS/app-wallet, storage | HTTP to `http://127.0.0.1:<port>` |
| **Aux API** | `aux_api.listen_port` | Restricted API for sidecars; defaults to `api_port + 1` | HTTP to `http://127.0.0.1:<port>` |
| **Storage** | `storage.s3.*` | Persistent S3 storage exposed via the Internal API | HTTP to `/v1/s3/...` |
| **Helios RPC** | `helios_rpc.chains[].local_rpc_port` | Trustless multi-chain RPC | HTTP to `http://127.0.0.1:<chain_port>` |
| **Console** | N/A (automatic) | Log streaming | Print to stdout/stderr |

---

## Related Documentation

- [Internal API Reference](internal_api.md) — Complete API endpoint documentation
- [Internal API Mock Service](internal_api_mockup.md) — External mock endpoint guidance and compatibility caveats
- [Helios RPC Integration](helios_rpc.md) — Trustless multi-chain light client
- [enclaver.yaml Reference](enclaver.yaml) — Complete manifest configuration
- [Architecture Overview](architecture.md) — System architecture and component relationships
- [Odyn Implementation Details](odyn_details.md) — Deep dive into code structure (for contributors)
