# FortiGate Security Analyzer: Command-Line Interface Reference

The `fortigate-analyzer` CLI provides offline static configuration review and health auditing directly from the terminal without launching the Streamlit web application.

---

## Installation

Install the package into your Python environment:

```bash
pip install -e .
```

Verify that the CLI command and module execution are available:

```bash
fortigate-analyzer --version
python -m fortigate_analyzer --version
```

---

## Global Options

- `-h`, `--help`: Display available commands and usage instructions.
- `--version`: Display application release version (`fortigate-analyzer 0.1.0`).

---

## Commands

### 1. `analyze`

Evaluates a configuration file and prints a concise terminal summary.

```bash
fortigate-analyzer analyze <INPUT_FILE> [OPTIONS]
```

#### Arguments & Options:
- `INPUT_FILE`: Path to a FortiGate configuration file (`.conf` or `.txt`).
- `-v`, `--verbose`: Print itemized finding summaries with recommendations.

#### Example:
```bash
fortigate-analyzer analyze backup.conf
```

#### Verbose Output Example:
```bash
fortigate-analyzer analyze backup.conf --verbose
```

---

### 2. `export`

Exports the static analysis to a structured machine-readable JSON document or a self-contained, printable HTML report.

```bash
fortigate-analyzer export <INPUT_FILE> [OPTIONS]
```

#### Arguments & Options:
- `INPUT_FILE`: Path to a FortiGate configuration file (`.conf` or `.txt`).
- `--format {json,html}`: Export format (default: `json`).
- `-o`, `--output <OUTPUT_FILE>`: Destination file path. If omitted, output is printed to `stdout`.
- `--generated-at <TIMESTAMP>`: Explicit timestamp string (e.g. for deterministic regression testing).

#### Examples:

**Export JSON to file:**
```bash
fortigate-analyzer export backup.conf --format json --output result.json
```

**Stream JSON to stdout / pipe to file:**
```bash
fortigate-analyzer export backup.conf --format json > result.json
```

**Export HTML report:**
```bash
fortigate-analyzer export backup.conf --format html --output report.html
```

---

## Exit Codes

The CLI uses predictable, standard exit codes:

| Exit Code | Meaning | Description |
|---|---|---|
| `0` | **Success** | Analysis completed successfully (even if review findings are present). |
| `1` | **Usage Error** | Invalid flags, missing required arguments, or unsupported options. |
| `2` | **File Read Error** | Input file does not exist, permission denied, or target is a directory. |
| `3` | **Processing Error** | Input file is empty or content is not recognized as FortiGate syntax. |

> [!NOTE]
> Findings of severity HIGH, MEDIUM, or LOW do **not** trigger a non-zero exit code. A non-zero exit code indicates an execution failure, not a security observation.

---

## Clean Stdout Guarantee

When exporting without the `--output` parameter:
- `sys.stdout` contains strictly the export payload (clean JSON or clean HTML).
- Informational, diagnostic, and error messages are written exclusively to `sys.stderr`.
- Shell redirection (e.g. `fortigate-analyzer export backup.conf --format json > result.json`) produces clean, parseable documents.

---

## Static & Offline Boundary

The CLI operates purely offline:
- No network connections or FortiGate API calls are initiated.
- Analysis evaluates configured settings and rule ordering.
- Live runtime state (such as routing convergence, session counters, and tunnel UP/DOWN status) is not assessed.
