# Enclaver Architecture and Module Reference

This document maps repository files to the build and runtime behavior implemented today.

## Top-level concerns

The codebase has three execution domains:

1. build time
   - turn an app image into an amended image
   - convert that image into an EIF
   - package the EIF into a Sleeve image

2. host/container runtime
   - run the Sleeve image
   - launch the enclave with `nitro-cli`
   - provide host-side ingress, egress, log, status, and clock-sync plumbing

3. enclave runtime
   - run `odyn` as PID 1
   - provide local platform services
   - launch the user process

## Key modules

### Build path

- `enclaver/src/build.rs`
  - main build orchestration
  - resolves default images
  - injects `/sbin/odyn` and `/etc/enclaver/enclaver.yaml`
  - packages `/enclave/application.eif` and `/enclave/enclaver.yaml`

- `enclaver/src/images.rs`
  - Docker image operations and layer append logic

- `enclaver/src/nitro_cli_container.rs`
  - runs `nitro-cli build-enclave` inside a container

- `enclaver/src/manifest.rs`
  - manifest schema
  - validation rules
  - effective defaults such as default-on `clock_sync`

### Host/runtime path

- `enclaver/src/run_container.rs`
  - Docker wrapper for running the Sleeve image
  - mounts `/dev/nitro_enclaves`
  - sets `privileged: true`
  - wires `-p/--publish` host port mappings

- `enclaver/src/run.rs`
  - runtime orchestrator inside the Sleeve container
  - starts host-side egress proxy
  - starts host-side clock-sync server
  - launches the enclave with `nitro-cli`
  - attaches debug console if requested
  - streams status/logs
  - starts host-side ingress proxies

- `enclaver/src/nitro_cli.rs`
  - host-side `nitro-cli` wrapper for `run-enclave`, `terminate-enclave`, `describe-eif`, and console access

### Odyn path

- `enclaver/src/bin/odyn/main.rs`
  - startup and shutdown order

- `enclaver/src/bin/odyn/config.rs`
  - runtime configuration helpers
  - important detail: if `api` is enabled, Aux API also starts by default on `api.listen_port + 1`

- `enclaver/src/bin/odyn/enclave.rs`
  - loopback setup and RNG seeding from NSM

- `enclaver/src/bin/odyn/egress.rs`
  - enclave-side HTTP proxy
  - sets uppercase and lowercase proxy env vars

- `enclaver/src/bin/odyn/clock_sync.rs`
  - default-on clock sync client
  - initial sync plus periodic sync

- `enclaver/src/bin/odyn/helios_rpc.rs`
  - Helios Ethereum/OP Stack light-client RPC services
  - background startup, with readiness wait on port `18545` only for registry-backed KMS

- `enclaver/src/bin/odyn/api.rs`
  - starts the Internal API server
  - wires S3 and Nova KMS integrations

- `enclaver/src/bin/odyn/aux_api.rs`
  - starts the restricted proxy API

- `enclaver/src/bin/odyn/ingress.rs`
  - enclave-side ingress listeners

- `enclaver/src/bin/odyn/console.rs`
  - stdout/stderr capture
  - status and log VSOCK services

- `enclaver/src/bin/odyn/launcher.rs`
  - launches the user process
  - reaps children

## Shared library modules used by Odyn

- `enclaver/src/api.rs`
  - Internal API route implementation

- `enclaver/src/aux_api.rs`
  - Aux API proxy and sanitization implementation

- `enclaver/src/encryption_key.rs`
  - P-384 ECDH keypair management

- `enclaver/src/eth_key.rs`
  - enclave Ethereum key management

- `enclaver/src/eth_tx.rs`
  - EIP-1559 transaction parsing/signing helpers

- `enclaver/src/http_util.rs`
  - localhost HTTP server helpers

- `enclaver/src/proxy/ingress.rs`
  - host and enclave ingress proxy implementations

- `enclaver/src/proxy/egress_http.rs`
  - host and enclave egress proxy implementations

- `enclaver/src/policy/*`
  - egress allow/deny rules for domain/IP matching

- `enclaver/src/integrations/nova_kms.rs`
  - Nova KMS registry discovery, authz, node selection, end-to-end request protection

- `enclaver/src/integrations/nova_kms/app_wallet.rs`
  - app-wallet material lifecycle in KMS KV

- `enclaver/src/integrations/s3.rs`
  - S3-backed storage proxy with optional KMS-derived encryption

- `enclaver/src/integrations/aws_util.rs`
  - IMDS-based AWS config and credential loading via egress proxy

## Runtime order that matters

### Host side (`enclaver-run`)

1. load `/enclave/enclaver.yaml`
2. start host-side egress proxy when `egress` is present
3. start host-side clock-sync server unless `clock_sync.enabled=false`
4. call `nitro-cli run-enclave`
5. after enclave startup:
   - attach debug console if requested
   - start log stream
   - start ingress proxies
   - wait for status stream

### Enclave side (`odyn`)

1. open status and log listeners first
2. load manifest from `/etc/enclaver/enclaver.yaml`
3. bootstrap loopback and RNG unless `--no-bootstrap`
4. start egress service
5. start clock sync
6. start Helios background tasks
7. if registry-backed KMS is enabled, wait for Helios readiness on `18545`
8. start Internal API and Aux API
9. start ingress
10. launch user process

Shutdown is the reverse order of service startup.

## Image and layout facts

Default images from `enclaver/src/build.rs`:

- Nitro CLI: `public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest`
- Odyn: `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest`
- Sleeve: `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest`

Release image layout:

```text
Sleeve base
|- /usr/local/bin/enclaver-run
|- /bin/nitro-cli
|- /enclave/enclaver.yaml
`- /enclave/application.eif
```

Amended app image before EIF conversion:

```text
original app image
|- /sbin/odyn
`- /etc/enclaver/enclaver.yaml
```

## Important constants

- status VSOCK port: `17000`
- app log VSOCK port: `17001`
- egress VSOCK port: `17002`
- clock-sync VSOCK port: `17003`
- default enclave egress proxy port: `10000`

## Related documents

- `docs/architecture.md`
- `docs/odyn.md`
- `docs/odyn_details.md`
- `docs/internal_api.md`
