# CI and Release Workflows

This repository has two GitHub Actions workflows:

- `.github/workflows/ci.yaml`
- `.github/workflows/release.yaml`

This document describes the workflows as they exist in the repository today.

## CI

`ci.yaml` runs on:

- `push` to `sparsity`
- `pull_request` targeting `sparsity`

Shared behavior:

- concurrency group: `${{ github.workflow }}-${{ github.ref }}`
- `cancel-in-progress: true`
- `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`

Jobs:

1. `fmt-check`
   - installs the MSRV from `enclaver/Cargo.toml`
   - installs `rustfmt`
   - runs:
     ```bash
     cargo fmt --manifest-path enclaver/Cargo.toml --all -- --check
     ```

2. `clippy-check`
   - installs the MSRV
   - installs `clippy`
   - caches `enclaver/target`
   - runs:
     ```bash
     RUSTFLAGS="-Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml

     RUSTFLAGS="-Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml \
       --features=run_enclave,odyn

     RUSTFLAGS="--cfg=tokio_unstable -Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml \
       --features=run_enclave,odyn,tracing
     ```

3. `test`
   - installs the MSRV
   - caches `enclaver/target`
   - runs `cargo test` across this feature matrix:
     - default
     - `run_enclave`
     - `odyn`
     - `run_enclave,odyn`

Local reproduction:

```bash
rustup toolchain install "$(sed -n 's/^rust-version = \"\\(.*\\)\"$/\\1/p' enclaver/Cargo.toml)"
rustup component add rustfmt clippy

cargo fmt --manifest-path enclaver/Cargo.toml --all -- --check

RUSTFLAGS="-Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml

RUSTFLAGS="-Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml \
  --features=run_enclave,odyn

RUSTFLAGS="--cfg=tokio_unstable -Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path enclaver/Cargo.toml \
  --features=run_enclave,odyn,tracing

cargo test --quiet --manifest-path enclaver/Cargo.toml
cargo test --quiet --manifest-path enclaver/Cargo.toml --features=run_enclave
cargo test --quiet --manifest-path enclaver/Cargo.toml --features=odyn
cargo test --quiet --manifest-path enclaver/Cargo.toml --features=run_enclave,odyn
```

## Release

`release.yaml` runs on:

- `push` to `sparsity`
- `push` tags matching `v*`
- `workflow_dispatch`

Manual workflow inputs:

- `publish_images`
- `upload_artifacts`
- `repo` (defaults to `sparsity-xyz/enclaver`)

Jobs:

1. `build-release-binaries`
   - targets:
     - `x86_64-unknown-linux-musl`
     - `aarch64-unknown-linux-musl`
   - builds with `--features=run_enclave,odyn`
   - uses `./.github/actions/cargo-zigbuild` for musl builds
   - uploads three binaries per target:
     - `enclaver`
     - `enclaver-run`
     - `odyn`
   - emits SLSA build provenance for `enclaver`

2. `publish-images`
   - runs when either:
     - the repo is exactly `sparsity-xyz/enclaver` and the ref is `sparsity` or a tag
     - a manual dispatch sets `publish_images=true`
   - downloads build artifacts
   - renames target directories to Docker architecture names:
     - `x86_64-unknown-linux-musl` -> `amd64`
     - `aarch64-unknown-linux-musl` -> `arm64`
   - publishes only these images:
     - `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn`
     - `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve`
   - authenticates to AWS via OIDC and pushes image provenance

3. `upload-release-artifact`
   - runs when either:
     - the repo is `sparsity-xyz/enclaver` and the ref is a tag
     - a manual dispatch sets `upload_artifacts=true`
   - packages only the `enclaver` binary into release tarballs
   - uploads draft GitHub Release assets plus matching SHA256 files

Notably:

- the release workflow does not publish a `nitro-cli` image
- it does not upload `odyn` or `enclaver-run` as standalone GitHub Release tarballs

## Local release reproduction

Build musl release binaries locally:

```bash
cargo install cargo-zigbuild

cargo zigbuild --release \
  --target x86_64-unknown-linux-musl \
  --manifest-path enclaver/Cargo.toml \
  --features=run_enclave,odyn
```

Build release images locally after arranging `amd64/` and `arm64/` artifact directories:

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

## AWS prerequisites for `publish-images`

The repository includes AWS infrastructure definitions in `aws/cloudformation/infrastructure.yml`.
To run the official publish flow, you need:

- an OIDC trust relationship for GitHub Actions
- the IAM role referenced by `release.yaml`
- public ECR repositories for `sparsity-ai/odyn` and `sparsity-ai/sleeve`

## References

- workflow definitions: `.github/workflows/ci.yaml`, `.github/workflows/release.yaml`
- custom build action: `./.github/actions/cargo-zigbuild`
- local helper: `scripts/build-docker-images.sh`
- AWS infra: `aws/cloudformation/infrastructure.yml`
