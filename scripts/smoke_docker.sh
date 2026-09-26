#!/usr/bin/env bash
# Bash Docker Smoke Test for FortiGate Security Analyzer
# Verifies container build, non-root user, offline capability, CLI commands, and Streamlit UI.

set -euo pipefail

echo "============================================================"
echo "FortiGate Security Analyzer - Docker Smoke Validation Script"
echo "============================================================"

# 1. Check Docker availability
if ! command -v docker &> /dev/null; then
    echo "[SKIPPED] Docker CLI not found in PATH."
    exit 0
fi

if ! docker info &> /dev/null; then
    echo "[SKIPPED] Docker daemon is not running."
    exit 0
fi

IMAGE_TAG="fortigate-analyzer:ci"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 2. Build Docker Image
echo -e "\n[STEP 1/8] Building Docker image (${IMAGE_TAG})..."
docker build -t "${IMAGE_TAG}" "${REPO_DIR}"

# 3. Check CLI Version
echo -e "\n[STEP 2/8] Testing CLI --version..."
VER_OUTPUT=$(docker run --rm "${IMAGE_TAG}" --version)
echo "Output: ${VER_OUTPUT}"
echo "${VER_OUTPUT}" | grep -q "fortigate-analyzer 0.1.0"

# 4. Check CLI Help
echo -e "\n[STEP 3/8] Testing CLI --help (default action)..."
HELP_OUTPUT=$(docker run --rm "${IMAGE_TAG}" --help)
echo "${HELP_OUTPUT}" | grep -q "FortiGate Security Analyzer"

# 5. Non-Root Identity Check via explicit entrypoint override
echo -e "\n[STEP 4/8] Verifying non-root user (UID 10001 / appuser)..."
USER_ID=$(docker run --rm --entrypoint id "${IMAGE_TAG}" -u)
echo "Container user ID: ${USER_ID}"
if [ "${USER_ID}" != "10001" ]; then
    echo "ERROR: Expected UID 10001, got ${USER_ID}" >&2
    exit 1
fi

# 6. Read-Only Mount & Offline Analysis (--network none)
echo -e "\n[STEP 5/8] Testing offline static analysis (--network none, read-only volume)..."
SAMPLE_CONF="${REPO_DIR}/tests/fixtures/golden/combined_realistic.conf"

docker run --rm --network none \
  -v "${SAMPLE_CONF}:/data/config.conf:ro" \
  "${IMAGE_TAG}" analyze /data/config.conf

# 7. JSON & HTML Volume Mount Exports
echo -e "\n[STEP 6/8] Testing report export to host volume..."
TEMP_OUT_DIR=$(mktemp -d)

chmod 755 "${TEMP_OUT_DIR}"
# Set non-root write access on host mount directory for container UID 10001
if command -v sudo &> /dev/null && [ "$(id -u)" -ne 0 ]; then
    sudo chown 10001:10001 "${TEMP_OUT_DIR}"
elif [ "$(id -u)" -eq 0 ]; then
    chown 10001:10001 "${TEMP_OUT_DIR}"
fi

docker run --rm --network none \
  -v "${SAMPLE_CONF}:/data/config.conf:ro" \
  -v "${TEMP_OUT_DIR}:/out" \
  "${IMAGE_TAG}" export /data/config.conf --format json -o /out/report.json

[ -s "${TEMP_OUT_DIR}/report.json" ] || { echo "JSON report export failed" >&2; exit 1; }
echo "JSON export verified"

docker run --rm --network none \
  -v "${SAMPLE_CONF}:/data/config.conf:ro" \
  -v "${TEMP_OUT_DIR}:/out" \
  "${IMAGE_TAG}" export /data/config.conf --format html -o /out/report.html

[ -s "${TEMP_OUT_DIR}/report.html" ] || { echo "HTML report export failed" >&2; exit 1; }
echo "HTML export verified"

rm -rf "${TEMP_OUT_DIR}"

# 8. Streamlit UI Startup Smoke Test & Health Check
echo -e "\n[STEP 7/8] Testing Streamlit UI container startup ('ui' subcommand)..."
CONTAINER_NAME="fgt-ui-smoke-$RANDOM"
docker run -d --name "${CONTAINER_NAME}" -p 8501:8501 "${IMAGE_TAG}" ui

# Ensure cleanup on exit
cleanup() {
    echo -e "\n[STEP 8/8] Cleaning up smoke container..."
    docker stop "${CONTAINER_NAME}" > /dev/null 2>&1 || true
    docker rm "${CONTAINER_NAME}" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Poll health endpoint from host runner
echo "Polling Streamlit health endpoint (http://127.0.0.1:8501/_stcore/health)..."
HEALTHY=0
for i in $(seq 1 30); do
    if curl -s -f "http://127.0.0.1:8501/_stcore/health" > /dev/null 2>&1; then
        echo "Streamlit health check passed (attempt ${i})!"
        HEALTHY=1
        break
    fi
    sleep 1
done

if [ "${HEALTHY}" -ne 1 ]; then
    echo "ERROR: Streamlit UI health check timed out after 30 seconds" >&2
    docker logs "${CONTAINER_NAME}" >&2
    exit 1
fi

echo -e "\n============================================================"
echo "SUCCESS: All 8 Docker smoke tests completed successfully!"
echo "============================================================"
