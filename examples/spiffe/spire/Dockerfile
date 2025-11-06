# A SPIRE server that can attest Nitro Enclaves.
#
# The stock ghcr.io/spiffe/spire-server image has no node attestor that
# understands a Nitro attestation document, so this adds the external
# nitro_enclave attestor plugin to it. That plugin verifies the attestation
# document odyn sends and derives the enclave's agent SPIFFE ID from PCR0.
#
#   docker build -t spiffe-example-spire-server:latest spire/

ARG SPIRE_VERSION=1.12.5

FROM golang:1.25 AS plugin

ARG PLUGIN_REPO=https://github.com/enclaver-io/spire-nitro-enclave-plugin
ARG PLUGIN_REF=main

RUN git clone --depth 1 --branch "${PLUGIN_REF}" "${PLUGIN_REPO}" /src

WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -o /out/spire-nitro-enclave-plugin ./cmd/spire-nitro-enclave-plugin

# The data directory has to exist and be owned by the uid the server runs as,
# so that the volume mounted over it at run time inherits that ownership.
RUN mkdir -p /out/data

FROM ghcr.io/spiffe/spire-server:${SPIRE_VERSION}

COPY --from=plugin /out/spire-nitro-enclave-plugin /opt/spire/bin/spire-nitro-enclave-plugin
COPY --from=plugin --chown=1000:1000 /out/data /opt/spire/data
COPY --chown=1000:1000 server.conf /opt/spire/conf/server/server.conf
