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

## Important: HTTP(S) Proxy Support for Enclave Apps

Applications running **inside the enclave** have no direct outbound network access. Any external HTTP/HTTPS traffic must go through Enclaver/Odyn's egress proxy.

- Your application (and the HTTP client library it uses) **must** support proxy routing via `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` (or be explicitly configured to use a proxy).
- Some popular client APIs intentionally **ignore** these environment variables by default (e.g. Node.js `fetch` / undici without a proxy agent). In that case the app may work outside the enclave but **fail inside**.

See [docs/http_proxy_support_guidance_for_enclave_applications.md](docs/http_proxy_support_guidance_for_enclave_applications.md) for language/library-specific guidance and common pitfalls.

## Documentation

### Architecture
- [Runtime Architecture](docs/architecture.md) — Component overview, build/runtime flows, and what's inside vs outside the EIF
- [Detailed Architecture](docs/enclaver-architecture.md) — Module-level code architecture reference

### Odyn Supervisor
- [Odyn User Guide](docs/odyn.md) — User-focused guide to Odyn modules and configuration
- [Odyn Implementation Details](docs/odyn_details.md) — Deep dive into Odyn internals (for contributors)
- [Clock Drift & Time Sync](docs/nitro_enclave_clock_drift.md) — Nitro Enclave clock behavior and Enclaver's default synchronization strategy

### Internal API
- [Internal API Reference](docs/internal_api.md) — Complete API endpoint documentation for attestation, signing, encryption
- [Internal API Mock Service](docs/internal_api_mockup.md) — Local development without an enclave, includes Python wrapper

### Usage
- [Enclaver CLI Reference](docs/enclaver-cli.md) — CLI commands, flags, and runtime override behavior
- [Helios RPC Integration](docs/helios_rpc.md) — Trustless Ethereum / OP Stack light-client RPC inside the enclave
- [Port Handling](docs/port_handling.md) — End-to-end port flow across build, sleeve, odyn, and ingress

### Configuration
- [enclaver.yaml Reference](docs/enclaver.yaml) — Complete manifest configuration with parameter usage annotations

### Development
- [Base Images](docs/base-images.md) — What the odyn / sleeve base images contain and how to inspect them
- [Building Images](docs/BUILDING_IMAGES.md) — Local build flow for odyn, sleeve, and nitro-cli images
- [CI and Release Workflows](docs/ci.md) — How repository CI and release pipelines are structured


## Container and EIF Layout

The diagram below shows the runtime component relationships across the host container, the enclave, Odyn, and the main integrations.

![Enclaver runtime architecture](docs/img/diagram-enclaver-components.svg)

The ASCII view below keeps the original file/layout-oriented perspective: what the release image contains, how `enclaver-run` launches the EIF, and what is embedded inside the enclave image.

```text
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
│    [L1] Sleeve image (contains enclaver-run, nitro-cli)                      │
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
│   Runtime services                                                           │
│   - launcher:   start and monitor the application                            │
│   - ingress:    inbound traffic --> app                                      │
│   - egress:     app --> outbound traffic                                     │
│   - clock-sync: keep enclave wall clock aligned with host time               │
│   - helios:     trustless Ethereum / OP Stack light client RPC               │
│   - console:    collect app stdout/stderr --> container logs                 │
│                                                                              │
│   Internal API (`/v1/*`)                                                     │
│   - core:       attestation, signing, random                                 │
│   - encryption: `/v1/encryption/*` (P-384 ECDH)                              │
│   - storage:    `/v1/s3/*` persistent storage integration                    │
│   - kms:        `/v1/kms/*` + `/v1/app-wallet/*` backed by Nova KMS          │
│                                                                              │
│ [User Application] (started and supervised by odyn)                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

Data paths overview:

- External clients -> container networking -> `odyn.ingress` -> app
- App -> `odyn.egress` -> container networking -> external services
- `odyn.clock-sync` <-> host vsock time server <-> host wall clock
- `odyn` Internal API (`/v1/kms/*`) <-> Nova KMS cluster via registry discovery
- App stdout/stderr -> `odyn.console` -> Docker container logs
