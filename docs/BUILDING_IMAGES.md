## Building the base images (nitro-cli/sleeve, odyn, sleeve)

This document shows the exact local steps used by the repository to build the development base images used by Enclaver: the `odyn` supervisor image and the `sleeve` dev image. It also explains how the release Dockerfiles are intended to be used in a multi-stage pipeline.

Prerequisites
- Docker with BuildKit / buildx enabled (or an alternative builder that supports multi-arch and build stages).
- `cross` installed (the helper script uses cross to build Rust artifacts for musl targets).
- A C compiler/linker on the host (required to install `cross`).

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install build-essential (provides C compiler needed by cargo install)
sudo apt-get update
sudo apt-get install -y build-essential

# Install cross for cross-compilation
cargo install cross

# Install Docker (if not already installed)
./scripts/install-docker.sh
```

Quick (one-command) local build

Run this from the repository root to build debug images (default):

```bash
./scripts/build-docker-images.sh
```

Or build optimized release images:

```bash
./scripts/build-docker-images.sh --release
```

For help and available options:

```bash
./scripts/build-docker-images.sh --help
```

What the script does
- Requires `cross` to be installed and Docker to be running.
- Compiles `odyn` and `enclaver-run` for your machine architecture using musl targets.
  - Debug mode (default): faster compilation, larger binaries with debug symbols.
  - Release mode (`--release`): optimized binaries, slower compilation.
- Creates a temporary docker build context containing the compiled binaries.
- Builds the dev images using these Dockerfiles:
  - `dockerfiles/odyn-dev.dockerfile`
  - `dockerfiles/sleeve-dev.dockerfile`

After running the helper, you will have these images locally:

- `odyn-dev:latest` — development odyn image that contains the compiled `odyn` binary at `/usr/local/bin/odyn`.
- `sleeve:latest` — development sleeve image that contains `enclaver-run` as the container entrypoint and uses the upstream `nitro-cli` image as the source for runtime libs and `/usr/bin/nitro-cli`.

Manual steps (if you want to run each step yourself)

1) Build the Rust binaries with `cross` (example for x86_64, debug mode):

```bash
cd enclaver
cross build --target x86_64-unknown-linux-musl --features run_enclave,odyn
```

For release mode:

```bash
cross build --target x86_64-unknown-linux-musl --features run_enclave,odyn --release
```

2) Build `odyn-dev` (create a small context and build):

Debug binaries:

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/debug/odyn "${docker_build_dir}/"
docker buildx build \
  -f dockerfiles/odyn-dev.dockerfile \
  -t odyn-dev:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

Release binaries:

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/release/odyn "${docker_build_dir}/"
docker buildx build \
  -f dockerfiles/odyn-dev.dockerfile \
  -t odyn-dev:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

3) Build `sleeve` (dev):

Debug binaries:

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/debug/enclaver-run "${docker_build_dir}/"
docker buildx build \
  -f dockerfiles/sleeve-dev.dockerfile \
  -t sleeve:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

Release binaries:

```bash
docker_build_dir=$(mktemp -d)
cp ./target/x86_64-unknown-linux-musl/release/enclaver-run "${docker_build_dir}/"
docker buildx build \
  -f dockerfiles/sleeve-dev.dockerfile \
  -t sleeve:latest \
  "${docker_build_dir}"
rm -rf "${docker_build_dir}"
```

Notes about release Dockerfiles
- The release Dockerfiles are written for multi-stage CI builds where an `artifacts` stage provides `${TARGETARCH}/odyn` and `${TARGETARCH}/enclaver-run`.
  - `dockerfiles/sleeve-release.dockerfile` uses `FROM public.ecr.aws/.../nitro-cli:latest AS nitro_cli` to copy necessary runtime libraries and `/usr/bin/nitro-cli` into the final image stage. It then expects an `artifacts` stage with `${TARGETARCH}/enclaver-run`.
  - `dockerfiles/odyn-release.dockerfile` similarly expects `${TARGETARCH}/odyn` from the `artifacts` stage.

If you want to produce release images locally, you need to create a multi-stage build that defines the `artifacts` stage (for example, using a small Dockerfile or `docker buildx build` with an appropriate context and stages).

About nitro-cli
- The `nitro-cli` image is NOT included in this repository. The runtime Dockerfiles rely on the public image:

```
public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
```

If you need to rebuild nitro-cli from source, obtain the upstream sources and build/publish that image separately.

Tips & troubleshooting
- **Missing `cross`**: Install it with `cargo install cross`. If that fails with "linker `cc` not found", install `build-essential` first: `sudo apt-get install -y build-essential`.

- **Missing `protoc`** (prost-build errors): The `cross` build images usually include `protoc`, but if you encounter errors about missing protobuf compiler:
  - Place a prebuilt `protoc` binary under `enclaver/build/protoc/protoc` and set `PROTOC=/project/enclaver/build/protoc/protoc` before running `cross`.
  - Or use a custom cross image that has `protoc` pre-installed.

- **Docker buildx failures**: Ensure BuildKit is enabled. On Docker Desktop, enable experimental features or create a buildx builder:

```bash
docker buildx create --use
```

- **Build mode selection**:
  - Use `--debug` (or omit flag) for faster compilation with debug symbols (useful during development).
  - Use `--release` for optimized, smaller binaries (slower to compile, recommended for production-like testing).

- On macOS with Apple Silicon, ensure you build for the correct `--platform` or run the helper script from an x86_64 runner if you need x86 images.

Questions or next steps
- I can add CI-ready multi-arch Docker build examples or a release `Makefile` if you'd like.
