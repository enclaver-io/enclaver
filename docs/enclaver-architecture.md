## Enclaver — Architecture and Module Reference

Date: 2026-02-23 (updated)

This document describes the key modules in the `enclaver` crate, how they interact, and the Docker image / layer layout used when building and running Enclaver packages.

Overview
--------
- Enclaver packages a user application Docker image into an AWS Nitro Enclaves-compatible EIF, then wraps that EIF into a "sleeve" OCI image for deployment and local runtime.
- Main concerns:
  - Build-time pipeline: amend app image, produce EIF via `nitro-cli`, package EIF into release image.
  - Runtime: run the release image (sleeve), start an enclave with `nitro-cli`, provide vsock proxying for ingress/egress, and monitor enclave status/logs.
  - Supporting services: egress/ingress proxies, optional KMS attestation proxy.

Repository layout (important files)
----------------------------------
- `enclaver/src/lib.rs` — crate module list.
- `enclaver/src/build.rs` — build pipeline, `EnclaveArtifactBuilder`.
- `enclaver/src/images.rs` — Docker image operations and layer builder.
- `enclaver/src/nitro_cli_container.rs` — run `nitro-cli` inside a container (build -> EIF).
- `enclaver/src/nitro_cli.rs` — run `nitro-cli` on the host (runtime control).
- `enclaver/src/manifest.rs` — `enclaver.yaml` schema and loader.
- `enclaver/src/run.rs` — enclave runtime orchestration (feature `run_enclave`).
- `enclaver/src/run_container.rs` — start and stream the sleeve container image on the host.
- `enclaver/src/api.rs` — Primary Internal API handler (all `/v1/*` routes).
- `enclaver/src/aux_api.rs` — Auxiliary API handler (restricted subset, proxies to Primary API).
- `enclaver/src/eth_key.rs` — secp256k1 key management for Ethereum signing.
- `enclaver/src/eth_tx.rs` — EIP-1559 transaction building and RLP encoding.
- `enclaver/src/encryption_key.rs` — P-384 ECDH key pair for client-enclave encryption.
- `enclaver/src/http_util.rs` — HTTP server infrastructure and response helpers.
- `enclaver/src/http_client.rs` — Shared HTTP client type.
- `enclaver/src/keypair.rs` — Generic key pair trait abstraction.
- `enclaver/src/proxy/` — network proxy implementations: `ingress.rs`, `egress_http.rs`.
- `enclaver/src/integrations/` — external service integrations:
  - `nova_kms.rs` — Nova KMS proxy (derive, KV, node discovery).
  - `nova_kms/app_wallet.rs` — App wallet lifecycle backed by KMS KV (create/read/sign).
  - `s3.rs` — S3 storage proxy with optional KMS-derived encryption.
  - `aws_util.rs` — AWS credential and region resolution via IMDS.
- `enclaver/src/policy/` — egress allow/deny (domain/ip pattern filters).
- `enclaver/src/vsock.rs` — vsock helper wrappers.
- `enclaver/src/bin/odyn/` — Odyn supervisor binary:
  - `main.rs` — bootstrap, service startup, and shutdown orchestration.
  - `config.rs` — manifest-to-runtime configuration mapping.
  - `api.rs` — Internal API service startup.
  - `aux_api.rs` — Auxiliary API service startup.
  - `helios_rpc.rs` — Helios Ethereum/OP Stack light client RPC service.
  - `console.rs` — stdout/stderr capture, ring buffer, VSOCK log streaming.
  - `ingress.rs` — Ingress proxy service startup.
  - `egress.rs` — Egress proxy service startup.
  - `launcher.rs` — Entrypoint process launch and supervision.
  - `enclave.rs` — Enclave bootstrap (loopback, RNG seed).
- `dockerfiles/` and `scripts/build-docker-images.sh` — Dockerfiles & scripts used to prepare runtime/dev images.

Top-level modules and responsibilities
-------------------------------------

- build (`src/build.rs`)
  - Orchestrates building a release image from a manifest.
  - Steps: resolve sources (app, odyn, sleeve), amend the app image by adding manifest and `odyn`, convert amended image to EIF (via `nitro-cli` inside container), package EIF into sleeve image.
  - Types: `EnclaveArtifactBuilder`, `ResolvedSources`.

- images (`src/images.rs`)
  - Abstraction over Docker operations using `bollard`.
  - Key types: `ImageManager`, `ImageRef`, `LayerBuilder` and `FileBuilder`.
  - `append_layer` streams a docker build context and returns resulting image id.

- nitro_cli_container (`src/nitro_cli_container.rs`)
  - Runs `nitro-cli` inside a dedicated container image to produce EIFs.
  - Provides helpers to create container, stream stdout/stderr, wait and remove container.

- nitro_cli (`src/nitro_cli.rs`)
  - Runs `nitro-cli` on the host (used by runtime `enclaver-run`).
  - Builds CLI args, parses JSON outputs (e.g., `EnclaveInfo`, `EIFInfo`).

- run_container (`src/run_container.rs`)
  - Host-side helper to start the final sleeve image (mounts `/dev/nitro_enclaves`), stream logs, and cleanup.
  - Type: `Sleeve`.

- run (`src/run.rs`) (feature `run_enclave`)
  - Enclave runtime orchestrator: starts egress proxy, runs enclave with `nitro-cli`, attaches debug console, streams logs, starts ingress proxies, monitors enclave status port and cleans up.
  - Types: `Enclave`, `EnclaveOpts`, `EnclaveExitStatus`.

- proxy (`src/proxy/*`)
  - `ingress.rs`: `EnclaveProxy` (vsock listener inside enclave) and `HostProxy` (host listener forwarding to vsock).
  - `egress_http.rs`: inside-enclave HTTP proxy + host-side vsock proxy for outbound HTTP(S); supports CONNECT and normal proxying; enforces `policy::EgressPolicy`.

- integrations (`src/integrations/*`) (feature `odyn`)
  - `nova_kms.rs`: Nova KMS integration used by the internal API (`/v1/kms/*`, `/v1/app-wallet/*`), including registry-backed authorization/discovery, node failover, and mutual signature verification.
  - `nova_kms/app_wallet.rs`: App wallet lifecycle backed by Nova KMS KV.
  - `s3.rs`: S3-backed storage APIs with optional KMS-derived AES-256-GCM encryption.
  - `aws_util.rs`: AWS IMDS-based credential and region resolution.

- policy (`src/policy/*`)
  - `domain_filter.rs`: domain pattern matching with `*` and `**` semantics.
  - `ip_filter.rs`: CIDR/IP matching using `ipnetwork`.
  - `EgressPolicy` composes domain/IP allow/deny lists and exposes `is_host_allowed(host: &str)`.

- nsm (`src/nsm.rs`) (feature `odyn`)
  - Wrapper around AWS Nitro Enclaves NSM driver. Exposes `AttestationProvider` trait and `NsmAttestationProvider` plus a `StaticAttestationProvider` used in tests.

- api (`src/api.rs`) (feature `odyn`)
  - HTTP handler exposing all `/v1/*` routes: `/v1/attestation`, `/v1/eth/*`, `/v1/encryption/*`, `/v1/random`, `/v1/s3/*`, `/v1/kms/*`, and `/v1/app-wallet/*`.

- aux_api (`src/aux_api.rs`) (feature `odyn`)
  - Restricted auxiliary HTTP handler that proxies a subset of endpoints (`/v1/eth/address`, `/v1/attestation`, `/v1/encryption/public_key`) to the Primary API with input sanitization.

- eth_key (`src/eth_key.rs`)
  - secp256k1 key pair management: Ethereum address derivation, EIP-191 message signing, and DER public key export.

- eth_tx (`src/eth_tx.rs`) (feature `odyn`)
  - EIP-1559 transaction building, RLP encoding/decoding, keccak256 hashing, and signature recovery.

- encryption_key (`src/encryption_key.rs`) (feature `odyn`)
  - P-384 ECDH key pair management for secure client-enclave encryption. Provides DER/PEM encoding, shared key derivation via ECDH + HKDF, and AES-256-GCM encrypt/decrypt operations.

- http_util (`src/http_util.rs`)
  - HTTP server infrastructure, `HttpHandler` trait, and response helpers (`ok_json`, `bad_request`, `not_found`, `method_not_allowed`).

- keypair (`src/keypair.rs`)
  - Generic key pair trait abstraction shared by `eth_key` and `encryption_key`.

- helios_rpc (`src/bin/odyn/helios_rpc.rs`)
  - Trustless Ethereum/OP Stack light client RPC service that runs inside the enclave and verifies execution data via consensus proofs.

- encryption_key (`src/encryption_key.rs`) (feature `odyn`)
  - P-384 ECDH key pair management for secure client-enclave encryption. Provides DER/PEM encoding, shared key derivation via ECDH + HKDF, and AES-256-GCM encrypt/decrypt operations.


- utils (`src/utils.rs`)
  - Logging init, spawn macro, path helpers, reading logs from streams and shutdown signal registration.

Call relationships and runtime flows
----------------------------------

Build-time flow (high level):

1. CLI `enclaver build` -> `build::EnclaveArtifactBuilder::build_release(manifest)`.
2. `manifest::load_manifest` reads `enclaver.yaml`.
3. `images::ImageManager` resolves `sources.app` image (pulls if necessary).
4. `amend_source_image` appends a layer to the app image containing the manifest and the `odyn` binary and sets ENTRYPOINT to run `/sbin/odyn --config-dir /etc/enclaver -- <app-entrypoint+cmd>`.
5. `image_to_eif` tags the amended image with a temporary tag and runs `nitro-cli build-enclave` inside a `nitro-cli` container (via `nitro_cli_container::NitroCLIContainer`) to produce `application.eif`.
6. `package_eif` appends the `application.eif` and `enclaver.yaml` into the `sleeve` base image to form the final release image (tagged with `manifest.target`).

Runtime flow (running a release image locally)

1. Host `enclaver run` -> `run_container::Sleeve` creates and starts the sleeve container, mapping `/dev/nitro_enclaves` into the container.
2. Inside the sleeve image, the `enclaver-run` binary (`src/bin/enclaver-run`) is the container entrypoint; it constructs `Enclave` and calls `Enclave::run`.
3. `Enclave::run` starts the host-side egress proxy (`HostHttpProxy` -> vsock listener on host), then calls `nitro-cli run-enclave` to start the enclave.
4. After enclave start, `Enclave`:
   - attaches debug console if requested;
   - starts a log stream by connecting to vsock `APP_LOG_PORT` for application logs;
   - starts ingress proxies for any `ingress` entries in the manifest; the host provides `HostProxy` listening on host ports and forwarding to the enclave vsock; inside the enclave `EnclaveProxy` accepts connections and forwards to local app TCP sockets;
   - monitors the status vsock `STATUS_PORT` for process status updates (exited/signaled/fatal).

Egress (HTTP) topology
----------------------

- Inside enclave: application -> local HTTP proxy (`EnclaveHttpProxy`) listening on localhost.
- `EnclaveHttpProxy` opens a vsock to the host at `HTTP_EGRESS_VSOCK_PORT` and requests the host connect to the remote host:port.
- Host: `HostHttpProxy` receives the request, connects to remote endpoint and pipes data back/forth over vsock.
- `EgressPolicy` enforces allow/deny lists from `enclaver.yaml` (domain and/or IP rules).

Ingress topology
----------------

- Host listens on configured host TCP ports (via `HostProxy`), accepts incoming connections and forwards them over vsock to the enclave.
- Inside the enclave, `EnclaveProxy` accepts vsock connections and forwards to the enclave-local app TCP socket.

KMS integration (feature `odyn`)
--------------------------------

- `integrations::nova_kms` serves internal API KMS/app-wallet endpoints; `/v1/kms/*` uses registry discovery/authz via `kms_integration` (`kms_app_id`, `nova_app_registry`) and built-in Helios registry RPC, while app-wallet routes run in enclave-local mode.
- `integrations::nova_kms` maintains a background-refreshed KMS node cache (wallet + URL + reachability) and uses it for node selection and mutual signature verification.
- `integrations::nova_kms::app_wallet` manages app-wallet key material in KMS KV when `use_app_wallet=true`.
- When `storage.s3.encryption.mode=kms`, `odyn` wires `integrations::s3::S3Proxy` to `NovaKmsProxy`.

Ports and constants
-------------------
- `STATUS_PORT` = 17000 (vsock) — enclave status messages.
- `APP_LOG_PORT` = 17001 (vsock) — application logs.
- `HTTP_EGRESS_VSOCK_PORT` = 17002 (vsock) — egress proxy port for HTTP.
- `HTTP_EGRESS_PROXY_PORT` = 10000 (default inside enclave for egress proxying).
- `OUTSIDE_HOST` = "host" — special hostname used inside the enclave to refer to the host (mapped to `127.0.0.1` on host side).

Docker images and layer structure (build-time & runtime)
------------------------------------------------------

Important base images (defaults in `src/build.rs`):
- Nitro CLI image: `public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest` — provides `nitro-cli` binary and runtime libs used during EIF creation and runtime base.
- ODYN image: `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest` — supervisor binary inserted into enclave image overlay.
- Sleeve: `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest` — runtime base image that receives `application.eif` and `enclaver.yaml`.

Layer sequence when building a release image:

1. Start from the user `app` image (`manifest.sources.app`).
2. Append a layer that:
   - adds `/etc/enclaver/enclaver.yaml` (manifest),
   - copies `odyn` binary to `/sbin/odyn` (from the `odyn` source image),
   - sets `ENTRYPOINT` to run the supervisor `/sbin/odyn --config-dir /etc/enclaver -- <app entrypoint+cmd>`.
   Result: amended (intermediate) image.
3. Convert amended image to an EIF: tag it temporarily and run `nitro-cli build-enclave` inside a `nitro-cli` container (this produces `application.eif`).
4. Append a layer to the `sleeve` base image that copies:
   - `RELEASE_BUNDLE_DIR/enclaver.yaml` (manifest),
   - `RELEASE_BUNDLE_DIR/application.eif` (the EIF file),
   Result: final release image containing the EIF and manifest.

Notes about Dockerfiles in `dockerfiles/`
-- `sleeve-release.dockerfile` / `sleeve-dev.dockerfile` are multi-stage Dockerfiles that extract the `nitro-cli` binary and necessary system libraries from the `nitro-cli` image and add the `enclaver-run` binary. The final runtime image entrypoint is `enclaver-run`.
- `odyn-dev.dockerfile` and `odyn-release.dockerfile` place the `odyn` binary into `/usr/local/bin/odyn` for dev/release flows.

CLI entrypoints
---------------
- `src/bin/enclaver/main.rs` — user-facing CLI with `build` and `run` commands.
- `src/bin/enclaver-run/main.rs` — container entrypoint that runs inside the sleeve image to orchestrate enclave creation and proxy startup.

Important files to inspect quickly
---------------------------------
- `enclaver/src/build.rs` — build pipeline and image amendment logic.
- `enclaver/src/images.rs` — image append and tar/context builder.
- `enclaver/src/nitro_cli_container.rs` — containerized `nitro-cli` invocation.
- `enclaver/src/api.rs` — Primary Internal API handler (all `/v1/*` endpoints).
- `enclaver/src/aux_api.rs` — Auxiliary API handler (restricted subset with sanitization).
- `enclaver/src/proxy/egress_http.rs` — HTTP proxying logic and CONNECT handling.
- `enclaver/src/integrations/nova_kms.rs` — Nova KMS integration and node lifecycle.
- `enclaver/src/integrations/nova_kms/app_wallet.rs` — App wallet lifecycle backed by KMS KV.
- `enclaver/src/integrations/s3.rs` — S3 storage proxy with KMS encryption.
- `enclaver/src/integrations/aws_util.rs` — AWS IMDS credential/region helpers.

Assumptions and notes
---------------------
- Several modules are feature-gated (`run_enclave`, `odyn`, `proxy`, `vsock`); the repo builds different artifacts depending on feature flags.
- The build flow uses a temporary tag workaround to avoid `nitro-cli` attempting to pull an image by name.
- `package_eif` currently lists TODOs about file permissions and exact image layout; the current flow packages the EIF and manifest into the sleeve base image's `RELEASE_BUNDLE_DIR` (default `/enclave`).

Next steps & optional extras
-----------------------------
- If you'd like I can add a mermaid diagram showing module relationships and vsock flows.
- I can also add a short `docs/README.md` with quick commands to build dev images using `scripts/build-docker-images.sh`.

Verification
------------
- This document was created by reading the implementation files under `enclaver/src` and `dockerfiles/` in the repository. It is saved to `docs/enclaver-architecture.md`.

References
----------
- Source code: `enclaver/src/*`
- Dockerfiles & scripts: `dockerfiles/`, `scripts/build-docker-images.sh`

---
Updated 2026-02-23 (originally generated 2025-10-27).
