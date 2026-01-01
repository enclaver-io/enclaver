#!/bin/bash
# ---------------------------------------------------------------------------
# build-docker-images.sh - developer helper to build dev Docker images with
#                          enclave binaries (odyn, enclaver-run)
# ---------------------------------------------------------------------------

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

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
            log_error "Unknown option: $1"
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
        log_error "Unsupported architecture: $local_arch"
        exit 1
        ;;
esac

enclaver_dir="$(dirname "$(dirname "${BASH_SOURCE[0]}")")/enclaver"

# Default tags (debug)
odyn_tag="odyn-dev:latest"
sleeve_tag="sleeve-dev:latest"
odyn_dockerfile="odyn-dev.dockerfile"
sleeve_dockerfile="sleeve-dev.dockerfile"

# Set build mode-specific variables
if [ "$BUILD_MODE" = "release" ]; then
    rust_target_dir="./target/${rust_target}/release"
    CROSS_BUILD_FLAGS="--release"
    odyn_tag="odyn:latest"
    sleeve_tag="sleeve:latest"
    odyn_dockerfile="odyn-release.dockerfile"
    sleeve_dockerfile="sleeve-release.dockerfile"
    log_info "Build mode: RELEASE (optimized)"
else
    rust_target_dir="./target/${rust_target}/debug"
    CROSS_BUILD_FLAGS=""
    log_info "Build mode: DEBUG (unoptimized)"
fi

cd "$enclaver_dir"

docker_build_dir=$(mktemp -d)
trap "rm --force --recursive ${docker_build_dir}" EXIT

# Check for 'cross'
if ! command -v cross >/dev/null 2>&1; then
    log_error "'cross' is required but not found in PATH."
    echo "Install it with: cargo install cross"
    exit 1
fi

log_info "Building Rust artifacts with 'cross' for target: $rust_target"
cross build --target "$rust_target" ${CROSS_BUILD_FLAGS} --features run_enclave,odyn

log_info "Copying built artifacts from: ${rust_target_dir}"
cp "$rust_target_dir/odyn" "$docker_build_dir/"
cp "$rust_target_dir/enclaver-run" "$docker_build_dir/"

log_info "Building images using Dockerfiles: ${odyn_dockerfile}, ${sleeve_dockerfile}"
docker buildx build \
    -f ../dockerfiles/${odyn_dockerfile} \
    -t "${odyn_tag}" \
    "${docker_build_dir}"

docker buildx build \
    -f ../dockerfiles/${sleeve_dockerfile} \
    -t "${sleeve_tag}" \
    "${docker_build_dir}"

log_info "Build complete!"
log_info "To use dev images, merge the following into enclaver.yaml:"
echo ""
echo "sources:"
echo "   supervisor: \"${odyn_tag}\""
echo "   sleeve: \"${sleeve_tag}\""
