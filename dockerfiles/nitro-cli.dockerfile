# Dockerfile for building the nitro-cli image
# This image provides the AWS Nitro CLI toolchain for building and running enclaves.
#
# Usage:
#   docker buildx build -f nitro-cli.dockerfile -t nitro-cli:latest .
#
# The image contains:
#   - nitro-cli binary (AWS Nitro Enclaves CLI)
#   - Docker and containerd for building EIF images
#   - Enclave kernel (bzImage), init, and linuxkit tools
#   - Runtime libraries needed by sleeve images

FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install AWS Nitro Enclaves CLI and development package
# The aws-nitro-enclaves-cli package provides:
#   - /usr/bin/nitro-cli
#   - /usr/bin/nitro-enclaves-allocator
#   - /usr/bin/vsock-proxy
#   - /etc/nitro_enclaves/*.yaml configs
#
# The aws-nitro-enclaves-cli-devel package provides:
#   - /usr/share/nitro_enclaves/blobs/* (bzImage, init, linuxkit, nsm.ko)
#   - /usr/include/nitro_enclaves/*.h headers
RUN dnf install -y \
        aws-nitro-enclaves-cli \
        aws-nitro-enclaves-cli-devel \
    && dnf clean all \
    && rm -rf /var/cache/yum /var/cache/dnf

# Set working directory for build operations
WORKDIR /build

# Default entrypoint is the nitro-cli
ENTRYPOINT ["nitro-cli"]
