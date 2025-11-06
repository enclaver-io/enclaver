#!/usr/bin/env bash
#
# Registers one enclave with the SPIRE server.
#
#   ./register.sh <PCR0> <workload-name>
#
# for example:
#
#   ./register.sh 8f7e...c2 server
#
# PCR0 is the enclave measurement that "enclaver build" prints. The
# nitro_enclave attestor derives the enclave's agent SPIFFE ID from it, so the
# entry's parent ID is what ties this identity to that exact enclave image: an
# enclave built from any other image measures differently and gets nothing.
#
# Register exactly one entry per enclave. odyn hands the app the first entry the
# SPIRE server authorizes it for, so a second entry under the same parent makes
# the app's identity depend on ordering.

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <PCR0> <workload-name>" >&2
    exit 1
fi

pcr0="$1"
workload="$2"

trust_domain="${TRUST_DOMAIN:-example.org}"
container="${SPIRE_CONTAINER:-spire-server}"

agent_id="spiffe://${trust_domain}/spire/agent/nitro-enclave/${pcr0}"
workload_id="spiffe://${trust_domain}/workload/${workload}"

echo "registering ${workload_id}"
echo "  under agent ${agent_id}"

# odyn does not do workload attestation -- the enclave is the workload -- so the
# selector is not what gates this entry; the parent ID is. SPIRE requires at
# least one selector, so record the measurement in it.
docker exec "${container}" /opt/spire/bin/spire-server entry create \
    -parentID "${agent_id}" \
    -spiffeID "${workload_id}" \
    -selector "nitro_enclave:pcr0:${pcr0}"
