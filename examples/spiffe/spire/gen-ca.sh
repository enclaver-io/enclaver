#!/usr/bin/env bash
#
# Generates the throwaway root CA for this example. The SPIRE server signs its
# own CA with it (UpstreamAuthority "disk"), the enclaves pin it to authenticate
# the SPIRE server, and it ends up in every SVID chain in the trust domain.
#
# This is a demo CA: the key is unencrypted and world readable so that the SPIRE
# server container can read it whatever uid you run as. Do not reuse it.

set -euo pipefail

out_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out/ca"

if [ -f "${out_dir}/ca.crt" ]; then
    echo "CA already exists at ${out_dir}/ca.crt; delete it to regenerate" >&2
    exit 0
fi

mkdir -p "${out_dir}"

openssl req -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -days 3650 \
    -nodes \
    -keyout "${out_dir}/ca.key" \
    -out "${out_dir}/ca.crt" \
    -subj "/CN=Enclaver SPIFFE example root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

chmod 0644 "${out_dir}/ca.key"

echo "wrote ${out_dir}/ca.crt and ${out_dir}/ca.key"
