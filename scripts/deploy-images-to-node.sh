#!/bin/bash

set -eu

# ---------------------------------------------------------------------------
# deploy-images-to-node.sh - Pack and deploy Docker images to a remote node
#
# This script:
#   1. Saves existing Docker images to tar files
#   2. Copies them to $APPNODE
#   3. Loads them into Docker on the remote node
#
# Prerequisites:
#   - Docker images must already exist (build them with build-docker-images.sh first)
#   - SSH access to $APPNODE without password prompts
#   - Docker running on $APPNODE
#
# Usage:
#   APPNODE_KEY=~/.ssh/key.pem APPNODE=user@host ./scripts/deploy-images-to-node.sh [--release|--debug] [--help]
#
# Environment variables:
#   APPNODE        Required: SSH target in format user@host or host (defaults to $USER@host)
#   APPNODE_KEY    Required: Path to SSH private key file
#   BUILD_MODE     Set to 'release' or 'debug' (flag overrides this)
# ---------------------------------------------------------------------------

BUILD_MODE="${BUILD_MODE:-debug}"

show_help() {
    echo "Usage: APPNODE_KEY=~/.ssh/key.pem APPNODE=user@host $0 [--release|--debug] [--help]"
    echo ""
    echo "Pack and deploy existing Docker images to a remote node for development."
    echo "Note: Images must be built first using build-docker-images.sh"
    echo ""
    echo "Options:"
    echo "  --release    Deploy release images (odyn:latest, sleeve:latest)"
    echo "  --debug      Deploy debug images (odyn-dev:latest, sleeve-dev:latest) (default)"
    echo "  --help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  APPNODE      Required: SSH target (e.g., ec2-user@54.177.250.78)"
    echo "  APPNODE_KEY  Required: Path to SSH private key file (e.g., ~/.ssh/ank.pem)"
    echo "  BUILD_MODE   Set to 'release' or 'debug' (command-line flag overrides)"
    echo ""
    echo "Examples:"
    echo "  APPNODE_KEY=~/.ssh/ank.pem APPNODE=ec2-user@54.177.250.78 $0                # Deploy debug images"
    echo "  APPNODE_KEY=~/.ssh/ank.pem APPNODE=ec2-user@54.177.250.78 $0 --release      # Deploy release images"
    echo "  BUILD_MODE=release APPNODE_KEY=~/.ssh/key.pem APPNODE=user@host $0           # Deploy via env var"
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

# Check if APPNODE is set
if [ -z "${APPNODE:-}" ]; then
    echo "Error: APPNODE environment variable is required"
    echo "Example: APPNODE=ec2-user@54.177.250.78 $0"
    exit 1
fi

# Check if APPNODE_KEY is set
if [ -z "${APPNODE_KEY:-}" ]; then
    echo "Error: APPNODE_KEY environment variable is required"
    echo "Example: APPNODE_KEY=~/.ssh/ank.pem APPNODE=ec2-user@54.177.250.78 $0"
    exit 1
fi

# Verify the key file exists
if [ ! -f "$APPNODE_KEY" ]; then
    echo "Error: SSH key file not found: $APPNODE_KEY"
    exit 1
fi

# Extract user and host from APPNODE
if [[ "$APPNODE" == *"@"* ]]; then
    APP_USER="${APPNODE%%@*}"
    APP_HOST="${APPNODE#*@}"
else
    APP_USER="${USER}"
    APP_HOST="$APPNODE"
fi

echo "Deploying to: $APP_USER@$APP_HOST"
echo "Build mode: $BUILD_MODE"
echo ""

# Determine image tags based on build mode
if [ "$BUILD_MODE" = "release" ]; then
    ODYN_TAG="odyn:latest"
    SLEEVE_TAG="sleeve:latest"
else
    ODYN_TAG="odyn-dev:latest"
    SLEEVE_TAG="sleeve-dev:latest"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1: Verify images exist
echo "Step 1: Verifying Docker images exist..."
if ! docker image inspect "$ODYN_TAG" >/dev/null 2>&1; then
    echo "Error: Image $ODYN_TAG not found"
    echo "Please build images first using: BUILD_MODE=$BUILD_MODE ./scripts/build-docker-images.sh"
    exit 1
fi

if ! docker image inspect "$SLEEVE_TAG" >/dev/null 2>&1; then
    echo "Error: Image $SLEEVE_TAG not found"
    echo "Please build images first using: BUILD_MODE=$BUILD_MODE ./scripts/build-docker-images.sh"
    exit 1
fi

echo "  ✓ Found $ODYN_TAG"
echo "  ✓ Found $SLEEVE_TAG"

# Step 2: Save images to tar files
echo ""
echo "Step 2: Saving Docker images to tar files..."
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

ODYN_TAR="$TEMP_DIR/odyn.tar"
SLEEVE_TAR="$TEMP_DIR/sleeve.tar"

echo "  Saving $ODYN_TAG to $ODYN_TAR"
docker save "$ODYN_TAG" -o "$ODYN_TAR" || {
    echo "Error: Failed to save $ODYN_TAG"
    exit 1
}

echo "  Saving $SLEEVE_TAG to $SLEEVE_TAR"
docker save "$SLEEVE_TAG" -o "$SLEEVE_TAR" || {
    echo "Error: Failed to save $SLEEVE_TAG"
    exit 1
}

# Get file sizes for progress indication
ODYN_SIZE=$(du -h "$ODYN_TAR" | cut -f1)
SLEEVE_SIZE=$(du -h "$SLEEVE_TAR" | cut -f1)
echo "  Images saved: odyn ($ODYN_SIZE), sleeve ($SLEEVE_SIZE)"

# Step 3: Copy files to remote node
echo ""
echo "Step 3: Copying images to $APP_USER@$APP_HOST..."
REMOTE_TEMP_DIR="/tmp/enclaver-images-$$"

ssh -i $APPNODE_KEY "$APP_USER@$APP_HOST" "mkdir -p $REMOTE_TEMP_DIR" || {
    echo "Error: Failed to create remote directory"
    exit 1
}

echo "  Copying odyn.tar ($ODYN_SIZE)..."
scp -i $APPNODE_KEY "$ODYN_TAR" "$APP_USER@$APP_HOST:$REMOTE_TEMP_DIR/" || {
    echo "Error: Failed to copy odyn.tar"
    exit 1
}

echo "  Copying sleeve.tar ($SLEEVE_SIZE)..."
scp -i $APPNODE_KEY "$SLEEVE_TAR" "$APP_USER@$APP_HOST:$REMOTE_TEMP_DIR/" || {
    echo "Error: Failed to copy sleeve.tar"
    exit 1
}

# Step 4: Load images on remote node
echo ""
echo "Step 4: Loading images into Docker on remote node..."
ssh -i $APPNODE_KEY "$APP_USER@$APP_HOST" <<EOF
    set -e
    echo "  Loading $ODYN_TAG..."
    docker load -i $REMOTE_TEMP_DIR/odyn.tar || {
        echo "Error: Failed to load odyn image"
        exit 1
    }
    
    echo "  Loading $SLEEVE_TAG..."
    docker load -i $REMOTE_TEMP_DIR/sleeve.tar || {
        echo "Error: Failed to load sleeve image"
        exit 1
    }
    
    echo "  Cleaning up remote temp files..."
    rm -rf $REMOTE_TEMP_DIR
    
    echo ""
    echo "Successfully loaded images:"
    docker images | grep -E "($ODYN_TAG|$SLEEVE_TAG)" | head -2
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Deployment complete!"
    echo ""
    echo "Images available on $APP_USER@$APP_HOST:"
    echo "  - $ODYN_TAG"
    echo "  - $SLEEVE_TAG"
else
    echo ""
    echo "✗ Deployment failed during image loading"
    exit 1
fi

