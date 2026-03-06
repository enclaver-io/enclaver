# Enclaver Port Handling

This document explains how Enclaver handles ports end-to-end, within Enclaver itself.

Scope:
- Included: `enclaver build`, `enclaver run`, `enclaver-run` (sleeve), `odyn`, `ingress`, API/Aux API/Helios listeners.
- Excluded: external reverse proxies and platform-specific ingress layers.

## Port Layers

Enclaver networking has three relevant layers:

1. Host -> Sleeve container (`docker` port publishing)
   - Controlled by `enclaver run -p HOST_PORT:CONTAINER_PORT`.

2. Sleeve container TCP -> Enclave vsock (`HostProxy`)
   - Controlled by `manifest.ingress[].listen_port`.
   - Started by `enclaver-run` inside the sleeve container.

3. Enclave vsock -> Enclave localhost TCP (`EnclaveProxy`)
   - Controlled by `manifest.ingress[].listen_port`.
   - Started by `odyn` inside the enclave.

For inbound traffic to work, all required layers must align.

## Who Reads Which Config

### `enclaver build`

- Reads `enclaver.yaml`.
- Packages the manifest into the release image (`/enclave/enclaver.yaml`) for sleeve.
- Also injects manifest into the enclave app layer (`/etc/enclaver/enclaver.yaml`) for odyn.

### `enclaver run` (CLI)

- `-f/--file` is used only to resolve `manifest.target` when image name is not provided.
- `--publish/-p` is the only source of Docker host port publishing.
- It does not auto-publish ports from `manifest.ingress`.

### `enclaver-run` (sleeve runtime in container)

- Loads packaged manifest.
- Starts host-side ingress proxies for each `manifest.ingress[].listen_port`.
- Each proxy listens on container `0.0.0.0:<listen_port>` and forwards to enclave vsock `<listen_port>`.

### `odyn` (inside enclave)

- Loads manifest from `/etc/enclaver/enclaver.yaml`.
- Starts enclave-side ingress listeners for each `manifest.ingress[].listen_port`.
- For each incoming vsock stream, forwards to `127.0.0.1:<listen_port>` in enclave.

## Service Ports vs Ingress Ports

Application services are typically localhost listeners inside enclave:

- App service: usually your app port (example `8080`)
- Internal API: `api.listen_port` (example `18000`)
- Aux API: `aux_api.listen_port` if set, otherwise `api.listen_port + 1`
  - Current implementation detail: if `api` is enabled, Aux API also starts by default on that derived port when it fits in `u16`
- Helios RPC: `helios_rpc.chains[].local_rpc_port` (per-chain port, often `18545` for Nova registry discovery)

These are not externally reachable by default. They become reachable only if:

1. The same port is listed in `ingress`.
2. The port is published via `enclaver run -p host:container`.

## Practical Example

Manifest:

```yaml
ingress:
  - listen_port: 8080
  - listen_port: 18001

api:
  listen_port: 18000
aux_api:
  listen_port: 18001
```

Run:

```bash
enclaver run my-image:latest \
  -p 8000:8080 \
  -p 8001:18001
```

Result:

- Host `:8000` -> container `:8080` -> enclave app `127.0.0.1:8080`
- Host `:8001` -> container `:18001` -> enclave aux API `127.0.0.1:18001`
- Internal API `18000` is still not externally reachable (not in `ingress` and not published)

## Common Pitfalls

1. Added `ingress` entry but forgot `-p`
   - Proxy exists in sleeve, but host cannot reach container port.

2. Added `-p` but port not in `ingress`
   - Docker forwards to container port, but no `HostProxy` is listening there.

3. Added `ingress` and `-p`, but service is not listening in enclave
   - `EnclaveProxy` forwards to `127.0.0.1:<port>` and connection fails.

4. Protocol mismatch on ingress port
   - Example: sending REST-style requests to a JSON-RPC endpoint.

## Validation Checklist

To expose a new port safely:

1. Service inside enclave listens on `127.0.0.1:<PORT>`.
2. `ingress` includes `listen_port: <PORT>`.
3. `enclaver run` includes `-p HOST_PORT:<PORT>`.
4. Endpoint/protocol test matches service behavior (for example JSON-RPC vs REST path style).
