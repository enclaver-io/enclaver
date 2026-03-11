#!/bin/bash

set -euo pipefail

TMP_DIR="$(mktemp -d)"
STATE_DIR="${TMP_DIR}/state"
APP_DIR="${TMP_DIR}/app"
MANIFEST_PATH="${TMP_DIR}/enclaver.yaml"
APP_IMAGE_TAG="hostfs-smoke-app:latest"
RELEASE_IMAGE_TAG="hostfs-smoke-enclave:latest"
ENCLAVER_BIN="${ENCLAVER_BIN:-enclaver}"
RUNNER="${RUNNER:-sudo}"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${STATE_DIR}" "${APP_DIR}"

cat > "${APP_DIR}/Dockerfile" <<'EOF'
FROM alpine:3.21
RUN apk add --no-cache coreutils
CMD ["/bin/sh", "-euc", "\
if [ ! -f /mnt/appdata/probe.txt ]; then \
  echo enclave-persist-ok > /mnt/appdata/probe.txt; \
  sync; \
  echo wrote:/mnt/appdata/probe.txt; \
else \
  value=\"$(cat /mnt/appdata/probe.txt)\"; \
  [ \"$value\" = \"enclave-persist-ok\" ]; \
  echo verified:$value; \
fi"]
EOF

cat > "${MANIFEST_PATH}" <<EOF
version: "v1"
name: "hostfs-smoke"
target: "${RELEASE_IMAGE_TAG}"
sources:
  app: "${APP_IMAGE_TAG}"
api:
  listen_port: 18000
storage:
  mounts:
    - name: "appdata"
      mount_path: "/mnt/appdata"
      required: true
      size_mb: 64
EOF

echo "[1/4] building app image ${APP_IMAGE_TAG}"
docker build -t "${APP_IMAGE_TAG}" "${APP_DIR}"

echo "[2/4] building enclaver release image ${RELEASE_IMAGE_TAG}"
"${ENCLAVER_BIN}" build -f "${MANIFEST_PATH}" >/dev/null

echo "[3/4] first enclave run: expect file creation"
first_output="$(${RUNNER} "${ENCLAVER_BIN}" run -f "${MANIFEST_PATH}" --mount appdata="${STATE_DIR}" 2>&1)"
echo "${first_output}"
grep -q "wrote:/mnt/appdata/probe.txt" <<<"${first_output}"

echo "[4/4] second enclave run: expect persisted file verification"
second_output="$(${RUNNER} "${ENCLAVER_BIN}" run -f "${MANIFEST_PATH}" --mount appdata="${STATE_DIR}" 2>&1)"
echo "${second_output}"
grep -q "verified:enclave-persist-ok" <<<"${second_output}"

echo "host-backed mount smoke test passed"
