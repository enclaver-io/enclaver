<img src="docs/img/enclaver-logo-color.png" width="350" />

Enclaver is an open source toolkit that simplifies packaging and running applications inside [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). It handles the complexity of enclave networking (ingress/egress proxies), cryptographic attestation, secure key management (KMS integration), and application lifecycle management — so you can focus on building your application.

This is the **Sparsity edition** of Enclaver, which adds support for Ethereum signing, P-384 ECDH encryption, S3 persistent storage, and an Internal API for enclave-based applications. See [enclaver-io/enclaver](https://github.com/enclaver-io/enclaver) for the original project.

## Installation

Run this command to install the latest version of the `enclaver` CLI tool:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/sparsity-xyz/enclaver/refs/heads/sparsity/install.sh)"
```

## Quick Start

See [examples/hn-fetcher/readme.md](examples/hn-fetcher/readme.md) for a quick start example of building and running an enclave application with Enclaver.

## Documentation

### Architecture
- [Runtime Architecture](docs/architecture.md) — Component overview, build/runtime flows, and what's inside vs outside the EIF
- [Detailed Architecture](docs/enclaver-architecture.md) — Module-level code architecture reference

### Odyn Supervisor
- [Odyn User Guide](docs/odyn.md) — User-focused guide to Odyn modules and configuration
- [Odyn Implementation Details](docs/odyn_details.md) — Deep dive into Odyn internals (for contributors)

### Internal API
- [Internal API Reference](docs/internal_api.md) — Complete API endpoint documentation for attestation, signing, encryption
- [Internal API Mock Service](docs/internal_api_mockup.md) — Local development without an enclave, includes Python wrapper

### Configuration
- [enclaver.yaml Reference](docs/enclaver.yaml) — Complete manifest configuration with parameter usage annotations


## Container and EIF Layout

The diagram below shows how the release Docker image runs as a single container, what layers it contains, and how the EIF (enclave) is structured inside with Odyn and its modules.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Docker Image (release) - runs as a single container                          │
│                                                                              │
│  entrypoint: /usr/local/bin/enclaver-run                                     │
│  includes:                                                                   │
│    - /bin/nitro-cli                                                          │
│    - /enclave/enclaver.yaml   (unified config)                               │
│    - /enclave/application.eif                                                │
│                                                                              │
│  Image layers (top -> bottom):                                               │
│    [L3] /enclave/application.eif                                             │
│    [L2] /enclave/enclaver.yaml                                               │
│    [L1] Sleeve image (contains enclaver-run, nitro-cli)       │
│                                                                              │
│  Runtime control flow:                                                       │
│    enclaver-run --> nitro-cli run-enclave --eif /enclave/application.eif     │
│                  \-> passes config from /enclave/enclaver.yaml to enclave    │
└──────────────────────────────────────────────────────────────────────────────┘

                     | launches enclave with EIF
                     v
┌─────────────────────────── Enclave (application.eif) ────────────────────────┐
│ /etc/enclaver/enclaver.yaml (config, also inside EIF)                        │
│                                                                              │
│ /sbin/odyn (supervisor)                                                      │
│   - launcher: start/monitor App                                              │
│   - ingress:  inbound traffic --> App                                        │
│   - egress:   App --> outbound traffic                                       │
│   - kms-proxy: talk to external KMS over network                             │
│   - encryption: ECDH (P-384) encrypt/decrypt for secure client communication │
│   - storage:  S3 persistent storage integration via Internal API             │
│   - helios:   trustless Ethereum/OP Stack light client RPC                   │
│   - console:  collect App stdout/stderr --> container logs                   │
│   - api:      internal API for attestation, signing, encryption, storage     │
│                                                                              │
│ [User Application] (started and supervised by odyn)                          │
└──────────────────────────────────────────────────────────────────────────────┘

Data paths overview:

  External clients --> Container networking --> odyn.ingress --> App
  App --> odyn.egress --> Container networking --> External services
  odyn.kms-proxy <--> External KMS (network)
  App stdout/stderr --> odyn.console --> Docker container logs
```
