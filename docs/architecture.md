# Enclaver Architecture

This is the high-level architecture view. For code-level module mapping, see `docs/enclaver-architecture.md`.

## Build-time flow

`enclaver build` does four things:

1. loads `enclaver.yaml`
2. amends the source app image by adding:
   - `/sbin/odyn`
   - `/etc/enclaver/enclaver.yaml`
3. runs `nitro-cli build-enclave` in a Nitro CLI container to produce `application.eif`
4. appends `application.eif` and `enclaver.yaml` to the Sleeve base image

Result:

```text
release image
|- /usr/local/bin/enclaver-run
|- /bin/nitro-cli
|- /enclave/application.eif
`- /enclave/enclaver.yaml
```

## Runtime flow

Host/container side:

1. `enclaver run` starts the Sleeve image as a privileged Docker container and mounts `/dev/nitro_enclaves`
2. `enclaver-run` loads `/enclave/enclaver.yaml`
3. it starts the host-side egress proxy if `egress` is present
4. it starts the host-side clock-sync time server when clock sync is effectively enabled
5. it launches the enclave with `nitro-cli run-enclave`
6. after the enclave is up, it starts host-side ingress proxies and streams logs/status

Enclave side:

1. `/sbin/odyn` starts as PID 1
2. it brings up loopback and seeds RNG from NSM
3. it starts the enclave-side egress proxy if enabled
4. it starts the clock-sync client service; clock sync is default-on unless explicitly disabled
5. it starts Helios in the background when configured
6. if registry-backed KMS is enabled, it waits for the Helios auth-chain RPC on port `18545`
7. it starts the Internal API and Aux API
8. it starts ingress listeners
9. it launches the user application

## Inside vs outside the EIF

| Component | Inside EIF | Outside EIF |
|-----------|:----------:|:-----------:|
| User application | yes | no |
| Odyn supervisor | yes | no |
| Embedded `/etc/enclaver/enclaver.yaml` | yes | no |
| `enclaver-run` | no | yes |
| `nitro-cli` | no | yes |
| `/enclave/application.eif` | no | yes |
| `/enclave/enclaver.yaml` | no | yes |
| Host ingress proxy | no | yes |
| Host egress proxy | no | yes |
| Host clock-sync time server | no | yes |

## Odyn service model

Inside the enclave, Odyn runs two kinds of things:

Standalone runtime services:

- ingress proxy
- egress proxy
- clock sync
- console/log streaming
- optional Helios RPC

Internal API capabilities exposed on `/v1/*`:

- attestation
- Ethereum signing
- random bytes
- P-384 encryption/decryption
- optional S3 storage
- optional Nova KMS
- optional app-wallet routes

`kms_integration`, `storage`, and encryption are not separate peer daemons. They are capabilities behind the Internal API.

## Traffic paths

Ingress:

```text
host client
-> docker published port
-> Sleeve host proxy
-> vsock
-> Odyn enclave proxy
-> 127.0.0.1:<listen_port> inside enclave
```

Egress:

```text
application
-> local HTTP proxy inside enclave
-> vsock
-> host HTTP proxy
-> remote network
```

Clock sync:

```text
Odyn clock-sync client
-> vsock port 17003
-> host time server in enclaver-run
```

## Important VSOCK ports

| Port | Direction | Purpose |
|------|-----------|---------|
| `17000` | enclave -> host | app status stream |
| `17001` | enclave -> host | app log stream |
| `17002` | enclave -> host | egress proxy traffic |
| `17003` | enclave -> host | clock-sync requests |

Ingress uses the configured `ingress[].listen_port` values rather than a single fixed VSOCK port.

## Related documents

- `docs/odyn.md`
- `docs/port_handling.md`
- `docs/internal_api.md`
- `docs/helios_rpc.md`
- `docs/nitro_enclave_clock_drift.md`
