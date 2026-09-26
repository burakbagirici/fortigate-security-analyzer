# FortiGate Security Analyzer: Docker & Container Deployment Guide

This guide covers building, running, and deploying the FortiGate Security Analyzer in containerized and offline air-gapped environments.

> [!NOTE]
> **Verification Status**: Container configurations (`Dockerfile`, `.dockerignore`, `docker-entrypoint.sh`) are statically audited and structurally validated. In local development environments where a Docker daemon is not active, runtime commands remain **STATICALLY VALIDATED / UNVERIFIED LOCALLY**. When a Docker daemon is available, run `scripts/smoke_docker.ps1` (Windows) or `scripts/smoke_docker.sh` (Linux/macOS) for automated end-to-end validation.

---

## 1. Image Architecture & Security Features

The container image is built with production security best practices:

- **Base Image**: Official `python:3.11-slim` Linux image.
- **Non-Root Execution**: Runs under a dedicated unprivileged user (`appuser`, UID: `10001`, GID: `10001`) with no login shell (`/bin/sh`).
- **Minimal Attack Surface**: Uses a strict `.dockerignore` to prevent accidental inclusion of git history, local test corpora, secrets, development caches, or uncommitted backup files.
- **Offline Assurance**: Core static analysis and reporting require **zero internet connectivity** and zero external API calls. Containers can run with `--network none`.
- **Dual-Mode Entrypoint**: Supports both the command-line interface (`fortigate-analyzer`) and the Streamlit web dashboard via a unified entrypoint script.

---

## 2. Building the Image

Build the container image from the repository root:

```bash
docker build -t fortigate-analyzer:0.1.0 -t fortigate-analyzer:latest .
```

---

## 3. Running Static Analysis (CLI Mode)

### A. Display Version & Help

```bash
# Display help menu
docker run --rm fortigate-analyzer

# Display version
docker run --rm fortigate-analyzer --version
```

### B. Analyze Configuration File (Offline & Read-Only)

Mount your FortiGate backup file into the container as a read-only volume:

```bash
docker run --rm \
  --network none \
  -v /path/to/my_firewall.conf:/data/config.conf:ro \
  fortigate-analyzer analyze /data/config.conf
```

### C. Verbose Analysis

```bash
docker run --rm \
  --network none \
  -v /path/to/my_firewall.conf:/data/config.conf:ro \
  fortigate-analyzer analyze -v /data/config.conf
```

---

## 4. Exporting Reports (JSON & HTML)

### A. Export JSON to Host Directory

```bash
docker run --rm \
  --network none \
  -v /path/to/backup.conf:/data/config.conf:ro \
  -v $(pwd)/output:/output \
  fortigate-analyzer export /data/config.conf --format json -o /output/report.json
```

### B. Export Printable HTML Report

```bash
docker run --rm \
  --network none \
  -v /path/to/backup.conf:/data/config.conf:ro \
  -v $(pwd)/output:/output \
  fortigate-analyzer export /data/config.conf --format html -o /output/report.html
```

### C. Stream JSON to stdout (Pipe to Local Tooling)

```bash
docker run --rm -i \
  --network none \
  -v /path/to/backup.conf:/data/config.conf:ro \
  fortigate-analyzer export /data/config.conf --format json > report.json
```

---

## 5. Running the Streamlit Web UI

To launch the web interface, pass the `ui` subcommand:

```bash
docker run --rm -d \
  -p 8501:8501 \
  --name fortigate-analyzer-ui \
  fortigate-analyzer ui
```

Access the application in your browser at `http://localhost:8501`.

To stop the web UI container:

```bash
docker stop fortigate-analyzer-ui
```

---

## 6. Permissions & File Ownership in Non-Root Containers

Because the container runs as `appuser` (UID: `10001`), mounted write directories for report exports should allow writes from UID 10001 or world-writable permissions if writing output files:

```bash
mkdir -p output
chmod 777 output
docker run --rm -v $(pwd)/output:/output fortigate-analyzer export ... -o /output/report.json
```

Alternatively, stream the output directly to stdout without granting write permissions to the container:

```bash
docker run --rm -v /path/to/backup.conf:/data/config.conf:ro fortigate-analyzer export /data/config.conf --format json > output.json
```
