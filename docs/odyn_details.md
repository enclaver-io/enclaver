# Odyn Detailed Reference

This document focuses on the implementation behavior of `enclaver/src/bin/odyn/*`.

For the user-facing overview, see `docs/odyn.md`.

## What Odyn is

Odyn runs as PID 1 inside the enclave and is responsible for:

- enclave bootstrap
- starting local platform services
- launching and supervising the user process
- exposing status and logs over VSOCK

## Actual startup order

There are two layers of startup logic:

### `run()`

Before the main launch sequence, `run()` starts the VSOCK-facing status and log listeners as early as possible so startup failures can still be reported to the host:

- status stream on `17000`
- log stream on `17001` unless `--no-console`

### `launch()`

The service startup order in `main.rs` is:

1. load manifest via `Configuration::load()`
2. initialize NSM handle
3. bootstrap loopback and RNG unless `--no-bootstrap`
4. start egress service
5. start clock-sync service
6. start Helios background services
7. if registry-backed KMS is enabled, wait for Helios readiness on port `18545`
8. start Internal API and Aux API together
9. start ingress listeners
10. launch the user entrypoint

Shutdown order is the reverse:

1. Aux API
2. Primary API
3. clock sync
4. Helios
5. ingress
6. egress

## Important implementation details

### Egress

- egress starts before API/S3/KMS initialization because those integrations may need outbound access immediately
- Odyn sets all of:
  - `http_proxy`
  - `https_proxy`
  - `HTTP_PROXY`
  - `HTTPS_PROXY`
  - `no_proxy`
  - `NO_PROXY`
- `NO_PROXY` and `no_proxy` are currently `localhost,127.0.0.1`

### Clock sync

- clock sync is default-on when omitted from the manifest
- it starts before API/app launch, but it runs asynchronously
- it performs an initial sync attempt, then periodic sync
- it talks to the host over VSOCK port `17003`
- both sides use timeouts to avoid hanging forever on a stalled request

### Helios

- Helios starts in the background for each configured chain
- in the normal case, the app is not blocked on full Helios sync
- when registry-backed KMS is enabled, Odyn waits specifically for the Helios RPC on local port `18545` before continuing

### Internal API and Aux API

- Primary API starts only when `api.listen_port` is configured
- Aux API currently starts whenever Primary API starts
- if `aux_api.listen_port` is omitted, Aux API uses `api.listen_port + 1`
- Aux API does not have an independent enable or disable flag
- Aux API attestation sanitization removes only `public_key`
- Aux API preserves `nonce` and `user_data`
- `OPTIONS /v1/attestation` on Aux API returns CORS preflight headers

### KMS and app-wallet

- `/v1/kms/*` routes require registry discovery config, not just `kms_integration.enabled=true`
- app-wallet routes require `use_app_wallet=true`
- current app-wallet APIs run in enclave-local mode and report `app_id: 0`
- transient registry/authz failures are surfaced as `503 Service Unavailable` with `Retry-After: 10`

### S3

- S3 startup requires egress access to IMDS and S3
- `storage.s3.encryption.mode=kms` requires `kms_integration.enabled=true`
- keys are namespace-prefixed and reject path traversal (`..`) and absolute paths

## Module notes

### `config.rs`

Main helpers:

- `egress_proxy_uri()`
- `api_port()`
- `aux_api_port()`
- `s3_config()`
- `kms_integration_config()`
- `helios_configs()`
- `clock_sync_config()`

`clock_sync_config()` applies the manifest's effective default-on clock-sync behavior.

### `console.rs`

- captures stdout and stderr into an in-memory ring buffer
- exposes logs and status over VSOCK
- heavy log volume drops oldest buffered bytes

### `launcher.rs`

- launches the user entrypoint with UID/GID 0
- reaps children through blocking `waitpid` logic wrapped in `spawn_blocking`

### `api.rs`

The service startup code:

- constructs `NovaKmsProxy` when KMS integration is enabled
- constructs `S3Proxy` when S3 is enabled
- loads AWS config through IMDS via the local egress proxy
- attaches Nova KMS to S3 when `storage.s3.encryption.mode=kms`

### `clock_sync.rs`

The client side:

- requests host receive/transmit timestamps
- estimates RTT and offset
- calls `clock_settime(CLOCK_REALTIME, ...)`

This is operational synchronization, not a trusted time source.

## VSOCK ports used by Odyn

| Port | Purpose |
|------|---------|
| `17000` | status stream |
| `17001` | application log stream |
| `17003` | clock-sync requests |

Ingress uses configured listen ports rather than a single fixed VSOCK port.

Host-side egress uses port `17002`, but that listener is owned by `enclaver-run`, not Odyn.

## Common failure modes

- missing or invalid manifest: fatal startup failure
- loopback/RNG bootstrap failure: fatal startup failure
- S3 enabled without reachable IMDS: API startup failure
- registry-backed KMS without Helios `18545`: startup failure
- ingress bind failure: startup failure
- child process spawn failure: fatal status reported to host

## Related files

- `enclaver/src/bin/odyn/main.rs`
- `enclaver/src/bin/odyn/config.rs`
- `enclaver/src/bin/odyn/clock_sync.rs`
- `enclaver/src/bin/odyn/helios_rpc.rs`
- `enclaver/src/bin/odyn/api.rs`
- `enclaver/src/bin/odyn/aux_api.rs`
- `enclaver/src/bin/odyn/egress.rs`
- `enclaver/src/bin/odyn/ingress.rs`
- `enclaver/src/bin/odyn/console.rs`
- `enclaver/src/bin/odyn/launcher.rs`
