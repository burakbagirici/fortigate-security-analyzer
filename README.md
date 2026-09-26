# FortiGate Security Analyzer

Offline static configuration security analyzer and health auditing tool for Fortinet FortiGate firewalls.

## Key Capabilities
- **Static Configuration Review**: Offline analysis of firewall policies, rule shadowing/containment, local-in management rules, interface policies, and IPv4/IPv6 rules.
- **Security Baseline Health Checks**: Administrative access controls, system hardening, VPN parameters (IPsec and SSL-VPN), and configuration integrity.
- **Version-Aware Defaults**: Evaluates documented FortiOS defaults where explicit settings are absent.
- **Reporting & Export**:
  - Web UI via Streamlit (`streamlit run app.py`)
  - Standalone, self-contained HTML report export
  - Schema-versioned (v1.0) machine-readable JSON export
  - Command-line interface (`fortigate-analyzer`)
- **Deployment & Distribution**:
  - Zero external dependencies for core CLI & static analysis pipeline (standard library only)
  - Optional `[ui]` extra for Streamlit web interface
  - Container-ready architecture: Docker configuration designed for unprivileged non-root execution (`appuser`, UID 10001) and offline operation (`--network none`)

## Installation & Distribution

### Standard Python Package
```bash
# Core CLI and static analyzer (standard library only, no external dependencies)
pip install .

# Or install pre-built wheel directly
pip install dist/fortigate_analyzer-0.1.0-py3-none-any.whl

# Include optional Streamlit web UI
pip install ".[ui]"
```

### Docker Container

```bash
# Build the container image
docker build -t fortigate-analyzer .

# Run CLI analysis (offline, read-only volume mount)
docker run --rm --network none -v $(pwd)/backup.conf:/data/backup.conf:ro fortigate-analyzer analyze /data/backup.conf

# Export JSON report to host volume
docker run --rm --network none -v $(pwd):/data fortigate-analyzer export /data/backup.conf --format json -o /data/report.json

# Launch Streamlit web UI
docker run --rm -p 8501:8501 fortigate-analyzer ui
```

## CLI Quickstart

```bash
# Analyze a configuration file in terminal
fortigate-analyzer analyze backup.conf

# Verbose terminal analysis with finding details
fortigate-analyzer analyze backup.conf --verbose

# Export to clean JSON (schema 1.0)
fortigate-analyzer export backup.conf --format json --output result.json

# Stream JSON directly to stdout
fortigate-analyzer export backup.conf --format json > result.json

# Export to self-contained printable HTML report
fortigate-analyzer export backup.conf --format html --output report.html
```

## Documentation
- [CLI Reference](docs/CLI.md)
- [Docker & Clean Deployment Guide](docs/DOCKER.md)
- [JSON Schema Specification](docs/JSON_SCHEMA.md)
- [Corpus Testing](docs/CORPUS_TESTING.md)
- [FortiOS Defaults Engine](docs/FORTIOS_DEFAULTS.md)
