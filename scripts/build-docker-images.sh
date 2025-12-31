#!/bin/bash

set -eu

# ---------------------------------------------------------------------------
# build-docker-images.sh - developer helper to build dev Docker images with
#                          enclave binaries (odyn, enclaver-run)
#
# High-level goal:
#   Compile the enclave Rust artifacts for a musl target using `cross`, create
#   a temporary docker build context containing the produced binaries, and
#   build two development Docker images used by the project.
#
# Important change (script behavior):
#   This script now REQUIRES `cross` and will exit if it is not available.
#   It does not attempt to install system packages or fall back to `cargo`
#   (host builds). This keeps the script deterministic and avoids modifying
#   developer hosts.
#
# Steps (what the script does) and details
#  0) Preconditions
#     - Docker with BuildKit / buildx enabled and running.
#     - `cross` installed and accessible on PATH (the script will abort otherwise).
#     - If your project needs `protoc` (prost-build) or other native build tools
#       (nasm, libclang, cmake, pkg-config), ensure those tools are available in
#       the cross build image you use or provide them to the container (see tips).
#
#  1) Detect local architecture and map it to a Rust musl target.
#     - Command used: uname -m
#     - Example mapping: x86_64 -> x86_64-unknown-linux-musl
#     - Result: the variable $rust_target
#
#  2) Compute important paths and Docker tag names.
#     - Variables created:
#         enclaver_dir       -> project/enclaver directory
#         rust_target_dir    -> ./target/${rust_target}/{debug|release}
#         docker_build_dir   -> temporary directory used for docker build context
#         odyn_tag           -> odyn-dev:latest
#         sleeve_tag   -> sleeve:latest
#
#  3) Build Rust artifacts for the target (required: `cross`)
#     - The script invokes `cross build --target ${rust_target} --features run_enclave,odyn`.
#       Add `--release` to build optimized release artifacts.
#     - Artifacts produced:
#         ./target/${rust_target}/debug/<binary>
#         ./target/${rust_target}/release/<binary> (when --release used)
#
#  4) Copy built binaries into a temporary docker build context
#     - Example commands:
#         cp ${rust_target_dir}/odyn ${docker_build_dir}/
#         cp ${rust_target_dir}/enclaver-run ${docker_build_dir}/
#
#  5) Build Docker images using docker buildx
#     - Example commands used by the script:
#         docker buildx build -f ../dockerfiles/odyn-dev.dockerfile -t ${odyn_tag} ${docker_build_dir}
#         docker buildx build -f ../dockerfiles/runtimebase-dev.dockerfile -t ${sleeve_tag} ${docker_build_dir}
#
#  6) Output
#     - The script prints a snippet to merge into `enclaver.yaml` that references
#       the built dev images (odyn-dev:latest and sleeve:latest)
#
# Troubleshooting & tips
#  - Missing protoc/protobuf errors (prost-build):
#      * Ensure `protoc` is available inside the cross build environment. Two
#        common approaches:
#          1) Place a host `protoc` under `enclaver/build/protoc/protoc` and set
#             PROTOC=/project/enclaver/build/protoc/protoc before running `cross`.
#             cross mounts the project at /project inside the container.
#          2) Use or build a custom cross image that has `protoc` installed.
#      * Alternatively install `protobuf-compiler` on the host for non-cross builds
#        (not recommended for this script which requires cross).
#  - Additional native build tools (nasm, libclang, cmake, pkg-config): ensure
#    these are available in your cross image or provide a custom image for cross.
#
# Usage
#   ./scripts/build-docker-images.sh [--release|--debug] [--help]
#
#   Flags:
#     --release    Build optimized release binaries (default: debug)
#     --debug      Build debug binaries (default)
#     --help       Show this help message
#
#   Environment variables:
#     BUILD_MODE   Set to 'release' or 'debug' (flag overrides this)
# ---------------------------------------------------------------------------

# Parse command-line arguments
BUILD_MODE="${BUILD_MODE:-debug}"

show_help() {
    echo "Usage: $0 [--release|--debug] [--help]"
    echo ""
    echo "Build development Docker images with enclave binaries (odyn, enclaver-run)."
    echo ""
    echo "Options:"
    echo "  --release    Build optimized release binaries"
    echo "  --debug      Build debug binaries (default)"
    echo "  --help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  BUILD_MODE   Set to 'release' or 'debug' (command-line flag overrides)"
    echo ""
    echo "Examples:"
    echo "  $0                # Build debug images"
    echo "  $0 --release      # Build release images"
    echo "  BUILD_MODE=release $0  # Build release images via env var"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --debug)
            BUILD_MODE="debug"
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for usage information."
            exit 1
            ;;
    esac
done

local_arch=$(uname -m)
case $local_arch in
    x86_64)
        rust_target="x86_64-unknown-linux-musl"
        ;;
    aarch64)
        rust_target="aarch64-unknown-linux-musl"
        ;;
    *)
        echo "Unsupported architecture: $local_arch"
        exit 1
        ;;
esac

enclaver_dir="$(dirname $(dirname ${BASH_SOURCE[0]}))/enclaver"

odyn_tag="odyn-dev:latest"
sleeve_tag="sleeve-dev:latest"

# Dockerfile names (set per BUILD_MODE below)
odyn_dockerfile="odyn-dev.dockerfile"
runtimebase_dockerfile="runtimebase-dev.dockerfile"

# Set build mode-specific variables
if [ "$BUILD_MODE" = "release" ]; then
    rust_target_dir="./target/${rust_target}/release"
    CROSS_BUILD_FLAGS="--release"

    # update variables for release images
    odyn_tag="odyn:latest"
    sleeve_tag="sleeve:latest"
    odyn_dockerfile="odyn-release.dockerfile"
    runtimebase_dockerfile="runtimebase-release.dockerfile"
    echo "Build mode: RELEASE (optimized)"
else
    rust_target_dir="./target/${rust_target}/debug"
    CROSS_BUILD_FLAGS=""
    echo "Build mode: DEBUG (unoptimized, faster compile)"
fi


cd $enclaver_dir

docker_build_dir=$(mktemp -d)
trap "rm --force --recursive ${docker_build_dir}" EXIT

# Require 'cross' to perform the cross-compilation. Do not attempt to fall
# back to building on the host or auto-install host musl compilers. This keeps
# the script deterministic and avoids modifying the developer host.
if ! command -v cross >/dev/null 2>&1; then
    echo "'cross' is required but not found in PATH."
    echo "Install it with: cargo install cross"
    echo "Also ensure Docker is running and you have permission to use it."
    exit 1
fi

# Use 'cross' to perform the build (required earlier). This script will not
# fall back to building on the host.
echo "Building Rust artifacts with 'cross' for target: $rust_target"
echo "  Command: cross build --target $rust_target ${CROSS_BUILD_FLAGS} --features run_enclave,odyn"
cross build --target "$rust_target" ${CROSS_BUILD_FLAGS} --features run_enclave,odyn

echo "Copying built artifacts from: ${rust_target_dir}"
cp $rust_target_dir/odyn $docker_build_dir/
cp $rust_target_dir/enclaver-run $docker_build_dir/

echo "Building images using Dockerfiles: ${odyn_dockerfile}, ${runtimebase_dockerfile}"
docker buildx build \
    -f ../dockerfiles/${odyn_dockerfile} \
    -t ${odyn_tag} \
    ${docker_build_dir}

docker buildx build \
    -f ../dockerfiles/${runtimebase_dockerfile} \
    -t ${sleeve_tag} \
    ${docker_build_dir}

echo "To use dev images, merge the following into enclaver.yaml:"
echo ""
echo "sources:"
echo "   supervisor: \"${odyn_tag}\""
echo "   sleeve: \"${sleeve_tag}\""
