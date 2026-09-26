# FortiGate Security Analyzer — Corpus Testing Guide & Policy

## 1. Corpus Testing Philosophy

The FortiGate Security Analyzer is designed to process real-world FortiGate backups and partial configuration snippets safely, deterministically, and without runtime crashes or false assumptions.

To ensure robustness against the immense variety of FortiOS syntax, versions, and deployment topologies encountered in the field, we maintain a developer-facing corpus testing workflow.

### Core Testing Principles
1. **False-Positive Avoidance > Maximum Detection**:
   A warning or finding must only be generated when backed by factual configuration or explicitly verified FortiOS semantics.
2. **Deterministic Processing**:
   Running the analyzer multiple times against the identical configuration must yield bit-for-bit identical results.
3. **No Unhandled Exceptions**:
   Malformed tokens, unclosed blocks, unexpected indentation, or unknown sections must never cause an unhandled exception or crash.
4. **Strict Secret Hygiene**:
   Sensitive operational data (passwords, private keys, PSKs, tokens, hashes) must never be committed to the repository, emitted in test logs, or exposed in public models.

---

## 2. Corpus Acquisition & Handling Policy

### Prohibited Content
- **NEVER** commit private customer, client, or enterprise FortiGate backup files to the repository.
- **NEVER** commit third-party configuration files unless their license explicitly permits redistribution.
- **NEVER** download or ingest leaked, compromised, or questionable credential dumps.

### Permitted Public Sources
- Official Fortinet documentation examples (FortiOS Administration Guide, CLI Reference, Fortinet Cookbooks).
- Cloud vendor architecture templates (AWS CloudFormation / Azure Resource Manager / GCP Deployment Manager FortiGate reference implementations with open-source licenses).
- Vendor lab topology examples with explicit public licensing (e.g., Apache 2.0, MIT, Creative Commons).

### Handling Public & Private Configurations
When testing against public or private configurations:
1. Store source files locally in an ignored developer directory (e.g., `corpus/` which is in `.gitignore`).
2. Record the source URL and license (if public) in local test metadata.
3. If a bug, crash, or unexpected behavior is discovered:
   - **Do NOT** commit the original full configuration.
   - **Minimize** the configuration to the smallest self-contained snippet that triggers the behavior (typically 5–15 lines).
   - **Sanitize** all identifiers, hostnames, IP addresses (use RFC 5737 / RFC 3849 documentation prefixes: `192.0.2.0/24`, `2001:db8::/32`), and redact any sensitive material.
   - Commit the minimal sanitized test case to `tests/fixtures/golden/` or as an inline unit test in `tests/`.

---

## 3. Tooling

### Corpus Runner (`tools/run_config_corpus.py`)
Executes the full static analysis pipeline (`parse_configuration`, `analyze_configuration`, `run_health_check`) across a directory of configuration files.
Outputs sanitized metrics:
- File name / Identifier
- FortiOS version detected
- Input classification (`LIKELY_FULL_BACKUP`, `PARTIAL_CONFIGURATION`, etc.)
- Object and policy counts
- Purpose classification distribution
- Findings and health check results
- Timing and execution performance
- Strict suppression of passwords, secrets, and private keys

### Crash Fuzz Runner (`tools/fuzz_parser.py`)
Applies deterministic, seed-based mutations (syntax truncation, Unicode injection, block omission, extreme nesting, cycle generation) to verify parser and analyzer resilience against malformed inputs.
