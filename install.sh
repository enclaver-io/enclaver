#!/usr/bin/env bash
# Enclaver installer script
# Usage: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/sparsity-xyz/enclaver/main/install.sh)"

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="sparsity-xyz/enclaver"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_RELEASES="https://github.com/${REPO}/releases/download"

# Helper functions
log_info() {
    # Print informational logs to stderr so function stdout can be used for machine output
    echo -e "${GREEN}==>${NC} $1" >&2
}

log_warn() {
    # Warnings also go to stderr
    echo -e "${YELLOW}Warning:${NC} $1" >&2
}

log_error() {
    echo -e "${RED}Error:${NC} $1" >&2
}

# Detect OS and architecture
detect_platform() {
    local os arch

    # Detect OS
    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        Darwin*)
            log_error "macOS is not supported by current releases (Linux-only artifacts)"
            exit 1
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Get latest release version from GitHub
get_latest_version() {
    local version
    log_info "Fetching latest release information..."
    
    if command -v curl > /dev/null 2>&1; then
        version=$(curl -fsSL "${GITHUB_API}" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget > /dev/null 2>&1; then
        version=$(wget -qO- "${GITHUB_API}" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$version" ]; then
        log_error "Failed to fetch latest release version"
        exit 1
    fi

    echo "$version"
}

# Download and extract release
download_release() {
    local version="$1"
    local platform="$2"
    local archive_name="enclaver-${platform}-${version}.tar.gz"
    local download_url="${GITHUB_RELEASES}/${version}/${archive_name}"

    # https://github.com/sparsity-xyz/enclaver/releases/download/v1.0.1/enclaver-linux-x86_64-v1.0.1.tar.gz
    local temp_dir
    
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT

    log_info "Downloading enclaver ${version} for ${platform} from ${download_url}..."
    
    if command -v curl > /dev/null 2>&1; then
        if ! curl -fsSL -o "${temp_dir}/${archive_name}" "${download_url}"; then
            log_error "Failed to download release from ${download_url}"
            exit 1
        fi
    elif command -v wget > /dev/null 2>&1; then
        if ! wget -q -O "${temp_dir}/${archive_name}" "${download_url}"; then
            log_error "Failed to download release from ${download_url}"
            exit 1
        fi
    fi

    tar -xzf "${temp_dir}/${archive_name}" -C "${temp_dir}"

    echo "${temp_dir}/enclaver-${platform}-${version}"
}

# Install binary
install_binary() {
    local temp_dir="$1"
    local binary_name="enclaver"
    log_info "Installing enclaver from ${temp_dir}"

    # Check if we need sudo for installation
    if [ ! -w "$INSTALL_DIR" ]; then
        SUDO="sudo"
    else
        SUDO=""
    fi
    
    # Install the binary
    if [ -f "${temp_dir}/${binary_name}" ]; then
        $SUDO install -m 755 "${temp_dir}/${binary_name}" "${INSTALL_DIR}/${binary_name}"
        log_info "Installed ${binary_name} to ${INSTALL_DIR}/${binary_name}"
    else
        log_error "Binary not found in archive"
        exit 1
    fi
    
    # Verify installation
    if command -v enclaver > /dev/null 2>&1; then
        enclaver --version
    else
        log_warn "enclaver is not in PATH. Add ${INSTALL_DIR} to your PATH"
    fi
}

# Main installation flow
main() {
    log_info "Enclaver Installer"
    
    # Check for required tools
    if ! command -v tar > /dev/null 2>&1; then
        log_error "tar is required but not installed"
        exit 1
    fi
    
    # Detect platform
    log_info "Detecting platform..."
    platform=$(detect_platform)
    log_info "Platform: ${platform}"
    
    # Get latest version
    version=$(get_latest_version)
    log_info "Version: ${version}"
    
    # Download and extract
    log_info "Downloading release..."
    temp_dir=$(download_release "$version" "$platform")
    log_info "Download complete"
    
    # Install
    log_info "Installing binary..."
    install_binary "$temp_dir"
    
    log_info "Installation complete! Run 'enclaver --help' to get started"
    log_info "Documentation: https://github.com/${REPO}"
}

# Run main installation
main "$@"
