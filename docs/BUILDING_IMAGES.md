# Building Enclaver Images

This document covers the image-building paths that exist in the repository today:

- local developer images via `scripts/build-docker-images.sh`
- release-style images via `dockerfiles/*-release.dockerfile`
- optional Nitro CLI image rebuilds

## Prerequisites

- Docker with `buildx`
- Rust toolchain
- `cross` for musl cross-compilation

Typical setup:

```bash
cargo install cross
docker buildx create --use
```

If `cargo install cross` fails because `cc` is missing, install a C toolchain first.

## One-command local builds

From the repository root:

```bash
./scripts/build-docker-images.sh
```

This default mode:

- detects the host architecture
- builds `odyn` and `enclaver-run` for the matching musl target
- uses `dockerfiles/odyn-dev.dockerfile`
- uses `dockerfiles/sleeve-dev.dockerfile`
- produces:
  - `odyn-dev:latest`
  - `sleeve-dev:latest`

Release-style local tags:

```bash
./scripts/build-docker-images.sh --release
```

This produces:

- `odyn:latest`
- `sleeve:latest`

## What the helper script actually does

`scripts/build-docker-images.sh`:

1. maps host architecture to:
   - `x86_64` -> `x86_64-unknown-linux-musl`
   - `aarch64` -> `aarch64-unknown-linux-musl`
2. runs:
   ```bash
   cross build --target <target> --features run_enclave,odyn [--release]
   ```
3. copies `odyn` and `enclaver-run` into a temporary Docker build context
4. builds Odyn and Sleeve images from the selected Dockerfiles

## Manual developer-image build

Example for `x86_64` debug builds:

```bash
cd enclaver
cross build --target x86_64-unknown-linux-musl --features run_enclave,odyn

tmpdir="$(mktemp -d)"
cp target/x86_64-unknown-linux-musl/debug/odyn "$tmpdir/"
docker buildx build -f ../dockerfiles/odyn-dev.dockerfile -t odyn-dev:latest "$tmpdir"

cp target/x86_64-unknown-linux-musl/debug/enclaver-run "$tmpdir/"
docker buildx build -f ../dockerfiles/sleeve-dev.dockerfile -t sleeve-dev:latest "$tmpdir"

rm -rf "$tmpdir"
```

For release binaries, switch `debug` to `release` and add `--release` to `cross build`.

## Release Dockerfiles

The release Dockerfiles are designed around the layout used by `.github/workflows/release.yaml`.

Expected artifact layout before building images:

```text
./amd64/odyn
./amd64/enclaver-run
./arm64/odyn
./arm64/enclaver-run
```

Local release-image build example:

```bash
docker buildx build \
  --file dockerfiles/odyn-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64,linux/arm64 \
  -t odyn:local .

docker buildx build \
  --file dockerfiles/sleeve-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64,linux/arm64 \
  -t sleeve:local .
```

How those Dockerfiles work:

- `odyn-release.dockerfile` copies `${TARGETARCH}/odyn` from the `artifacts` build context
- `sleeve-release.dockerfile` copies `${TARGETARCH}/enclaver-run` from the `artifacts` build context
- `sleeve-release.dockerfile` also copies `nitro-cli` and required runtime libraries from the default Nitro CLI image

## Nitro CLI image

This repository includes `dockerfiles/nitro-cli.dockerfile` and `scripts/build-and-publish-nitro-cli.sh`.

Build it locally:

```bash
docker buildx build -f dockerfiles/nitro-cli.dockerfile -t nitro-cli:latest .
```

Or use the helper script:

```bash
./scripts/build-and-publish-nitro-cli.sh --tag latest
```

Enclaver does not automatically switch to that rebuilt image. If you want to consume it by default, update the Nitro CLI source used by your build flow.

## Troubleshooting

- Missing `cross`: `cargo install cross`
- Missing `buildx`: `docker buildx create --use`
- Missing `protoc` during cross builds: provide `PROTOC` or use a build image that includes it
- On macOS, remember these images target Linux musl; build and runtime validation should happen on Linux

## Related files

- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `.github/workflows/release.yaml`
