#!/bin/bash
# ---------------------------------------------------------------------------
# publish-docker-images.sh
#
# Authenticate and publish odyn and sleeve images to AWS Public ECR.
#
# High-level goal:
#   1. Authenticate Docker to Public ECR
#   2. Tag local images with the remote registry URI
#   3. Push images to Public ECR
# ---------------------------------------------------------------------------

set -euo pipefail

# Configuration
REGISTRY="public.ecr.aws/d4t4u8d2"
REPO_PREFIX="sparsity-ai"
TAG="${TAG:-latest}"
DEFAULT_REGION="us-east-1"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Authenticate Docker to public ECR
log_info "Authenticating with AWS Public ECR..."
aws ecr-public get-login-password --region "$DEFAULT_REGION" | \
    docker login --username AWS --password-stdin public.ecr.aws

# 2. Push each image
for REPO in odyn sleeve; do
    log_info "Processing repository: $REPO"

    # Define the repository name (sparsity-ai/odyn, etc.)
    ECR_REPO_NAME="${REPO_PREFIX}/${REPO}"

    # Ensure repository exists
    if ! aws ecr-public describe-repositories --repository-names "$ECR_REPO_NAME" --region "$DEFAULT_REGION" &>/dev/null; then
        log_info "Creating repository: $ECR_REPO_NAME"
        aws ecr-public create-repository --repository-name "$ECR_REPO_NAME" --region "$DEFAULT_REGION"
    fi

    # Get the repository URI
    REPO_URI=$(aws ecr-public describe-repositories \
        --repository-names "$ECR_REPO_NAME" \
        --region "$DEFAULT_REGION" \
        --query "repositories[0].repositoryUri" \
        --output text)

    log_info "Tagging and pushing $REPO:latest -> $REPO_URI:$TAG"
    
    # Check if local image exists
    if ! docker image inspect "$REPO:latest" &>/dev/null; then
        log_error "Local image $REPO:latest not found. Please build it first."
        continue
    fi

    docker tag "$REPO:latest" "$REPO_URI:$TAG"
    docker push "$REPO_URI:$TAG"
    
    log_info "Successfully pushed: $REPO_URI:$TAG"
done

log_info "Published all images to $REGISTRY"
