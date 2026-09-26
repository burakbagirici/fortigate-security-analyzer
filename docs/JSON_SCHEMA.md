# FortiGate Security Analyzer: Public JSON Schema Specification (v1.0)

## Overview
The FortiGate Security Analyzer exports a normalized, machine-readable JSON representation of static configuration reviews and health audits.

- **Schema Version**: `"1.0"`
- **Analyzer Version**: Independent application release version (e.g. `"0.1.0"`).
- **Safety**: Guarantees zero inclusion of credentials (passwords, ENC hashes, PSKs, private keys, API tokens, SNMP communities), raw configuration text, or parser AST blocks.

---

## Top-Level Schema Structure

```json
{
  "schema_version": "1.0",
  "metadata": { ... },
  "input_assessment": { ... },
  "summary": { ... },
  "findings": [ ... ],
  "policies": [ ... ],
  "vpn": { ... },
  "ssl_vpn": { ... },
  "local_in_policies": [ ... ],
  "interface_policies": [ ... ],
  "documented_defaults": [ ... ],
  "inventory": { ... },
  "limitations": [ ... ]
}
```

---

## Field Specifications

### 1. `metadata`
| Field | Type | Description | Nullable / Optional |
|---|---|---|---|
| `filename` | string | Name of the analyzed input configuration file | No |
| `analyzer_version` | string | Software version of the analyzer package (e.g. `"0.1.0"`) | No |
| `file_size` | integer | Size of the input configuration file in bytes | Optional |
| `generated_at` | string | UTC timestamp of report generation (`YYYY-MM-DD HH:MM:SS UTC`) | Optional |

### 2. `input_assessment`
| Field | Type | Description | Nullable / Optional |
|---|---|---|---|
| `classification` | string | Structural classification: `FULL_BACKUP`, `PARTIAL_CONFIGURATION`, `CORRUPTED_OR_TRUNCATED`, `UNRECOGNIZED_INPUT` | No |
| `fortigate_detected` | boolean | True if FortiGate CLI configuration syntax was identified | No |
| `fortios` | object | FortiOS environment metadata (`detected`: bool, `version`: string, `platform`: string/null) | No |
| `recognized_sections` | array[string] | List of recognized FortiOS table identifiers | No |
| `structural_warnings` | array[string] | Structural parsing observations and anomalies | No |
| `analysis_scope` | object | Map of analysis domain names to `{ "status": string, "evidence": string }` | No |
| `explanation` | array[string] | Technical rationale for the assigned input classification | No |

#### Scope Status Values:
- `COVERED`: Source configuration table observed and statically evaluated.
- `UNAVAILABLE_NOT_SUPPLIED`: Configuration table absent in partial input; domain cannot be evaluated.
- `UNOBSERVED_IN_INPUT`: Domain table unobserved in full backup; treated as unconfigured rather than an error.

### 3. `summary`
| Field | Type | Description |
|---|---|---|
| `vdom_count` | integer | Number of distinct VDOMs detected (minimum 1) |
| `vdoms` | array[string] | List of distinct VDOM names (e.g. `["root", "DMZ"]`) |
| `total_policies` | integer | Total count of firewall forwarding policies |
| `enabled_policies` | integer | Count of enabled firewall forwarding policies |
| `disabled_policies` | integer | Count of disabled firewall forwarding policies |
| `findings_by_severity` | object | Breakdown of findings count by severity: `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `total_findings` | integer | Sum of all review findings and health check observations |
| `unresolved_references_count` | integer | Total count of dangling object references across configuration tables |
| `ipsec_tunnels_count` | integer | Number of static IPsec Phase 1 definitions |
| `ssl_vpn_status` | string | Remote access SSL-VPN status: `ENABLED`, `DISABLED`, `NOT_OBSERVED` |

### 4. `findings` (Array of Objects)
| Field | Type | Description | Nullable / Optional |
|---|---|---|---|
| `severity` | string | Severity rating: `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"` | No |
| `category` | string | Domain classification: `"FIREWALL_POLICY"`, `"SYSTEM_HEALTH"`, `"ADMIN_HARDENING"`, etc. | No |
| `title` | string | Concise title of the review finding | No |
| `description` | string | Technical explanation of the identified configuration condition | No |
| `recommendation` | string | Neutral engineering recommendation or remediation guideline | No |
| `vdom` | string | Target VDOM scope (default `"root"`) | No |
| `policy_id` | string / null | Associated policy ID number, if applicable | Yes |
| `object_name` | string / null | Associated object name, if applicable | Yes |
| `evidence` | array[string] | Sanitized reference evidence strings supporting the finding | No |

### 5. `policies` (Array of Objects)
| Field | Type | Description |
|---|---|---|
| `sequence_index` | integer | 1-indexed visual evaluation order in configuration file |
| `policy_id` | string | Configured firewall policy identifier (`edit <id>`) |
| `name` | string | Policy name label, or empty string |
| `vdom` | string | VDOM scope of the policy |
| `address_family` | string | Evaluated IP family: `"IPv4"` or `"IPv6"` |
| `status` | string | Rule status: `"enable"` or `"disable"` |
| `action` | string | Rule action: `"accept"` or `"deny"` |
| `source_interfaces` | array[string] | Source interface names (`srcintf`) |
| `destination_interfaces` | array[string] | Destination interface names (`dstintf`) |
| `source_selectors` | array[string] | Source address object or group names |
| `destination_selectors` | array[string] | Destination address object or group names |
| `services` | array[string] | Service object or service group names |
| `flow_type` | string | Inferred traffic direction classification (e.g. `"INTERNET_OUTBOUND"`) |
| `technical_purpose` | string | Inferred technical purpose (e.g. `"Internet Access"`) |
| `security_profiles` | object | Attached UTM profiles (e.g. `{"ips": "default", "av": "scan"}`) |
| `logging` | string | Configured traffic logging parameter |

### 6. `vpn` & `ssl_vpn`
- **`vpn.ipsec_phase1`**: Static tunnel definition metadata: `name`, `interface`, `remote_gw`, `proposal`, `dhgrp`, `ike_version`, `vdom`.
- **`ssl_vpn`**: Static configuration status: `status`, `listening_ports`, `source_interfaces`, `servercert`, `portals` (`name`, `tunnel_mode`, `web_mode`, `split_tunneling`).

### 7. `local_in_policies` & `interface_policies`
- Normalized ingress filtering rules and interface inspection attachments with selectors, services, and actions.

### 8. `documented_defaults`
- Represents verified version-aware FortiOS defaults evaluated where explicit settings were absent:
  - `section`: Configuration table path
  - `field`: Setting name
  - `effective_value`: Applied default value
  - `source`: `"DOCUMENTED_DEFAULT"`
  - `version_branch`: FortiOS branch (e.g. `"7.2"`)
  - `documentation`: Official FortiOS documentation citation

### 9. `inventory`
- Normalized counts of all parsed configuration objects.

### 10. `limitations`
- List of technical methodology boundaries explaining that static analysis operates offline and does not establish live state.
