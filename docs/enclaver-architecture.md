## Enclaver — Architecture and Module Reference

Date: 2025-10-27

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
- `enclaver/src/bin/odyn/helios_rpc.rs` — Helios Ethereum/OP Stack light client RPC service.
- `enclaver/src/proxy/` — network proxy implementations: `ingress`, `egress_http`, (optionally) `kms`, `pkcs7`.
- `enclaver/src/policy/` — egress allow/deny (domain/ip pattern filters).
- `enclaver/src/vsock.rs` — vsock helper wrappers and TLS-on-vsock helpers.
- `enclaver/src/tls.rs` — rustls config helpers and test helpers.
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
  - `ingress.rs`: `EnclaveProxy` (vsock listener inside enclave; TLS termination) and `HostProxy` (host listener forwarding to vsock).
  - `egress_http.rs`: inside-enclave HTTP proxy + host-side vsock proxy for outbound HTTP(S); supports CONNECT and normal proxying; enforces `policy::EgressPolicy`.
  - `kms.rs` (feature `odyn`): KMS request proxy that inserts attestation and decrypts `CiphertextForRecipient` using PKCS#7.
  - `pkcs7.rs`: parsing and decrypting PKCS#7 EnvelopedData.

- policy (`src/policy/*`)
  - `domain_filter.rs`: domain pattern matching with `*` and `**` semantics.
  - `ip_filter.rs`: CIDR/IP matching using `ipnetwork`.
  - `EgressPolicy` composes domain/IP allow/deny lists and exposes `is_host_allowed(host: &str)`.

- nsm (`src/nsm.rs`) (feature `odyn`)
  - Wrapper around AWS Nitro Enclaves NSM driver. Exposes `AttestationProvider` trait and `NsmAttestationProvider` plus a `StaticAttestationProvider` used in tests.

- api (`src/api.rs`) (feature `odyn`)
  - Small HTTP handler exposing `/v1/attestation` (POST) to return attestation docs, `/v1/encryption/*` endpoints for ECDH-based encryption/decryption, and `/v1/eth/*` for Ethereum key operations.

- helios_rpc (`src/bin/odyn/helios_rpc.rs`)
  - Trustless Ethereum/OP Stack light client RPC service that runs inside the enclave and verifies execution data via consensus proofs.

- encryption_key (`src/encryption_key.rs`) (feature `odyn`)
  - P-384 ECDH key pair management for secure client-enclave encryption. Provides DER/PEM encoding, shared key derivation via ECDH + HKDF, and AES-256-GCM encrypt/decrypt operations.

- tls (`src/tls.rs`) (feature `proxy`)
  - rustls config loaders and `NoCertificateVerification` test helper.

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
   - starts ingress proxies for any `ingress` entries in the manifest; the host provides `HostProxy` listening on host ports and forwarding to the enclave vsock; inside the enclave `EnclaveProxy` terminates TLS and forwards to local app TCP sockets;
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
- Inside the enclave, `EnclaveProxy` accepts vsock connections (optionally TLS-terminated) and forwards to the enclave-local app TCP socket.

KMS attestation / special handling (feature `odyn`)
--------------------------------------------------

- `proxy::kms` inspects KMS requests that require attestation (Decrypt, GenerateDataKey, GenerateDataKeyPair, DeriveSharedSecret, GenerateRandom).
- For attesting actions it requests an attestation document from `nsm` (or `StaticAttestationProvider` in tests), inserts a `Recipient` structure into the request body, re-signs the request (SigV4) with AWS credentials, forwards to KMS, and on response decrypts `CiphertextForRecipient` using PKCS#7 logic in `proxy::pkcs7`.

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
- `enclaver/src/proxy/egress_http.rs` — HTTP proxying logic and CONNECT handling.
- `enclaver/src/proxy/kms.rs` & `enclaver/src/proxy/pkcs7.rs` — KMS attestation and PKCS#7 decrypt logic.

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
Generated by code inspection on 2025-10-27.
