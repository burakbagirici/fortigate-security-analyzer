"""FortiGate Security Analyzer - Professional Static Analysis Report Export.

This module is strictly a PRESENTATION layer that consumes existing structured
results from parser.py, analyzer.py, and health_check.py. It produces a
self-contained, printable, professional HTML report.

Design principles:
- Zero security logic reproduction or re-interpretation of raw config.
- Zero AI/LLM generation; 100% deterministic and neutral presentation.
- Zero numeric security scores (no arbitrary risk scores).
- Clear separation between Configuration Facts, Technical Interpretation,
  Review Findings, and Input Scope & Limitations.
- Explicit static vs. runtime analysis boundaries.
- Strict secret suppression (passwords, ENC hashes, PSKs, tokens, communities).
- Standard library only (no external dependencies, CDN, remote fonts, or JS).
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import re
from typing import Any

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")

SEVERITY_COLORS = {
    "HIGH": {"bg": "#fef2f2", "text": "#991b1b", "border": "#f87171"},
    "MEDIUM": {"bg": "#fffbeb", "text": "#b45309", "border": "#fcd34d"},
    "LOW": {"bg": "#eff6ff", "text": "#1d4ed8", "border": "#93c5fd"},
    "INFO": {"bg": "#f8fafc", "text": "#475569", "border": "#cbd5e1"},
}

STATUS_COLORS = {
    "ENABLED": {"bg": "#dcfce7", "text": "#166534", "border": "#86efac"},
    "DISABLED": {"bg": "#f1f5f9", "text": "#64748b", "border": "#cbd5e1"},
    "NOT_OBSERVED": {"bg": "#f3f4f6", "text": "#6b7280", "border": "#d1d5db"},
    "RESOLVED": {"bg": "#dcfce7", "text": "#166534", "border": "#86efac"},
    "UNRESOLVED": {"bg": "#fef3c7", "text": "#b45309", "border": "#fcd34d"},
    "BUILTIN": {"bg": "#f3e8ff", "text": "#6b21a8", "border": "#d8b4fe"},
}

# Regex patterns for defense-in-depth secret suppression (fallback on final rendered HTML only)
FALLBACK_SECRET_PATTERNS = [
    (re.compile(r"\bENC\s+[A-Za-z0-9+/=]{16,}\b", re.IGNORECASE), "ENC [REDACTED]"),
    (re.compile(r"-----BEGIN\s+[A-Z\s]*PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]*PRIVATE\s+KEY-----", re.IGNORECASE), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?:set\s+)?(password|passwd|psksecret|private-key)\s+([\"'][^\"']+[\"']|\S+)", re.IGNORECASE), r"\1 [REDACTED]"),
]


def _escape(value: Any) -> str:
    """Safely convert value to string and HTML-escape it without mutating legitimate names."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _sanitize_final_report(html_text: str) -> str:
    """Fallback defense-in-depth sanitization on final rendered HTML."""
    if not html_text:
        return ""
    sanitized = str(html_text)
    for pattern, replacement in FALLBACK_SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _sanitize_secret(text: str) -> str:
    """Redact any accidental secrets from evidence or text (fallback helper)."""
    return _sanitize_final_report(text)


def _format_list(values: Any, max_items: int = 3) -> str:
    """Format a list of strings with explicit truncation indicator if needed."""
    if not values:
        return "-"
    if isinstance(values, (str, int, float, bool)):
        return _escape(values)
    items = [str(v) for v in values if v is not None and str(v).strip()]
    if not items:
        return "-"
    if len(items) <= max_items:
        return _escape(", ".join(items))
    shown = items[:max_items]
    remainder = len(items) - max_items
    return f"{_escape(', '.join(shown))} <em>(+{remainder} more)</em>"


def _extract_vdoms(config: dict) -> list[str]:
    """Extract distinct VDOM names from config collections."""
    names: dict[str, str] = {}
    for value in config.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("vdom") is not None:
                    name = str(item["vdom"]).strip()
                    if name:
                        names.setdefault(name.casefold(), name)
    return sorted(names.values(), key=str.casefold)


def _collect_findings(analysis_result: dict, health_result: dict) -> list[dict]:
    """Collect and unify findings from analysis_result and health_result without duplicating."""
    unified: list[dict] = []
    seen_keys: set[str] = set()

    # 1. Health checks
    for check in health_result.get("checks", []):
        if not isinstance(check, dict):
            continue
        severity = str(check.get("severity", "INFO")).upper()
        title = check.get("title") or "Untitled Health Finding"
        category = check.get("category") or "Configuration Integrity"
        vdom = check.get("vdom")
        key = f"HEALTH|{category}|{severity}|{title}|{vdom}|{check.get('description', '')[:40]}"
        if key not in seen_keys:
            seen_keys.add(key)
            unified.append({
                "source": "Configuration Health Check",
                "severity": severity if severity in SEVERITY_ORDER else "INFO",
                "category": category,
                "title": title,
                "description": check.get("description") or "No description provided.",
                "recommendation": check.get("recommendation") or "Review configuration against FortiOS hardening guidance.",
                "evidence": [_sanitize_secret(e) for e in check.get("evidence", [])],
                "affected_object": check.get("affected_object") or (f"VDOM: {vdom}" if vdom else "-"),
                "vdom": vdom,
                "analysis_basis": "FortiOS Best Practice & Integrity Rules",
            })

    # 2. Policy analysis findings (including duplicates, shadowing, and overly permissive rules)
    for finding in analysis_result.get("findings", []):
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "INFO")).upper()
        title = finding.get("title") or "Untitled Policy Finding"
        policy_id = finding.get("policy_id")
        policy_name = finding.get("policy_name")
        vdom = finding.get("vdom")

        if title in {"Duplicate Firewall Policy", "Fully Shadowed Firewall Policy", "Conflicting Policy Shadowing"}:
            category = "Policy Relationships"
        else:
            category = "Firewall Policy Security"

        key = f"POLICY|{category}|{severity}|{title}|{policy_id}|{vdom}"
        if key not in seen_keys:
            seen_keys.add(key)
            raw_evidence = finding.get("evidence")
            if isinstance(raw_evidence, list):
                ev_list = [_sanitize_secret(e) for e in raw_evidence]
            elif raw_evidence:
                ev_list = [_sanitize_secret(raw_evidence)]
            else:
                ev_list = []

            affected = f"Policy #{policy_id}"
            if policy_name:
                affected += f" ({policy_name})"
            if vdom:
                affected += f" [VDOM: {vdom}]"

            unified.append({
                "source": "Policy Analysis Engine",
                "severity": severity if severity in SEVERITY_ORDER else "INFO",
                "category": category,
                "title": title,
                "description": finding.get("description") or "No description provided.",
                "recommendation": finding.get("recommendation") or "Review policy order, selectors, and profile attachments.",
                "evidence": ev_list,
                "affected_object": affected,
                "vdom": vdom,
                "analysis_basis": finding.get("technical_context") or "Static Policy Flow & Shadowing Analysis",
            })

    # Sort deterministically: SEVERITY_ORDER, Category, Title
    def _sort_key(item: dict) -> tuple:
        sev = item["severity"]
        sev_rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99
        return (sev_rank, item["category"], item["title"])

    unified.sort(key=_sort_key)
    return unified


def _build_metrics(config: dict, analysis_result: dict, health_result: dict, findings: list[dict]) -> dict:
    """Compute deterministic metrics for executive summary and overview."""
    input_assessment = config.get("input_assessment") or {}
    fortios_ver_info = input_assessment.get("fortios") or input_assessment.get("fortios_version")
    if isinstance(fortios_ver_info, dict):
        version_str = fortios_ver_info.get("version", "unknown")
        platform = fortios_ver_info.get("platform") or input_assessment.get("platform")
    elif fortios_ver_info:
        version_str = str(fortios_ver_info)
        platform = input_assessment.get("platform")
    else:
        version_str = "unknown"
        platform = input_assessment.get("platform")

    classification = input_assessment.get("classification", "FORTIGATE_CONFIGURATION")

    policies = config.get("policies", [])
    if not isinstance(policies, list):
        policies = []
    total_policies = len(policies)
    disabled_policies = sum(
        1 for p in policies
        if isinstance(p, dict) and str(p.get("status", "")).casefold() in {"disable", "disabled"}
    )
    enabled_policies = total_policies - disabled_policies

    vdoms = _extract_vdoms(config)
    vdom_count = max(len(vdoms), 1)

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    ipsec_p1 = config.get("ipsec_phase1", [])
    ipsec_count = len(ipsec_p1) if isinstance(ipsec_p1, list) else 0

    ssl_vpn_settings = config.get("ssl_vpn_settings", [])
    if isinstance(ssl_vpn_settings, list) and ssl_vpn_settings:
        first_ssl = ssl_vpn_settings[0]
        status_val = str(first_ssl.get("status", "")).casefold()
        if status_val in {"enable", "enabled"}:
            ssl_vpn_status = "ENABLED"
        elif status_val in {"disable", "disabled"}:
            ssl_vpn_status = "DISABLED"
        else:
            ssl_vpn_status = "NOT_OBSERVED"
    elif isinstance(ssl_vpn_settings, dict) and ssl_vpn_settings:
        status_val = str(ssl_vpn_settings.get("status", "")).casefold()
        if status_val in {"enable", "enabled"}:
            ssl_vpn_status = "ENABLED"
        elif status_val in {"disable", "disabled"}:
            ssl_vpn_status = "DISABLED"
        else:
            ssl_vpn_status = "NOT_OBSERVED"
    else:
        ssl_vpn_status = "NOT_OBSERVED"

    # Count IPv6 items
    ipv6_policies = sum(
        1 for p in policies
        if isinstance(p, dict) and (p.get("srcaddr6") or p.get("dstaddr6"))
    )
    addr6 = len(config.get("addresses6", [])) if isinstance(config.get("addresses6"), list) else 0
    grp6 = len(config.get("address_groups6", [])) if isinstance(config.get("address_groups6"), list) else 0
    vip6 = len(config.get("vips6", [])) if isinstance(config.get("vips6"), list) else 0
    local_in6 = len(config.get("local_in_policies6", [])) if isinstance(config.get("local_in_policies6"), list) else 0
    intf_pol6 = len(config.get("interface_policies6", [])) if isinstance(config.get("interface_policies6"), list) else 0
    ipv6_objects_total = addr6 + grp6 + vip6 + local_in6 + intf_pol6

    # Unresolved references count from health checks
    unresolved_count = 0
    for check in health_result.get("checks", []):
        if check.get("title") in {
            "Unresolved Object References in Policy",
            "Referenced Security Profile Could Not Be Resolved",
            "Configuration Integrity Review Required",
        }:
            ev = check.get("evidence", [])
            unresolved_count += len(ev)

    return {
        "fortios_version": version_str,
        "platform": platform,
        "classification": classification,
        "vdom_count": vdom_count,
        "vdoms": vdoms,
        "total_policies": total_policies,
        "enabled_policies": enabled_policies,
        "disabled_policies": disabled_policies,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "ipsec_count": ipsec_count,
        "ssl_vpn_status": ssl_vpn_status,
        "ipv6_policies": ipv6_policies,
        "ipv6_objects_total": ipv6_objects_total,
        "unresolved_count": unresolved_count,
    }


def _render_executive_summary_text(metrics: dict) -> str:
    """Create a concise, deterministic, neutral executive summary statement."""
    high = metrics["severity_counts"]["HIGH"]
    med = metrics["severity_counts"]["MEDIUM"]
    low = metrics["severity_counts"]["LOW"]
    info = metrics["severity_counts"]["INFO"]
    total = metrics["total_findings"]
    classification = metrics["classification"].replace("_", " ").title()

    if total == 0:
        return (
            f"Static analysis of the supplied FortiGate configuration ({classification}) "
            f"identified 0 review findings across {metrics['total_policies']} firewall "
            f"policies and {metrics['vdom_count']} VDOM(s). No static configuration discrepancies "
            f"or best-practice review items were flagged by the supported analyzer rules."
        )

    parts = []
    if high > 0:
        parts.append(f"{high} HIGH")
    if med > 0:
        parts.append(f"{med} MEDIUM")
    if low > 0:
        parts.append(f"{low} LOW")
    if info > 0:
        parts.append(f"{info} INFO")

    counts_str = ", ".join(parts) if len(parts) <= 2 else f"{', '.join(parts[:-1])}, and {parts[-1]}"

    return (
        f"Static analysis of the supplied FortiGate configuration ({classification}) "
        f"identified {counts_str} review findings in the supplied configuration "
        f"across {metrics['total_policies']} firewall policies ({metrics['enabled_policies']} enabled, "
        f"{metrics['disabled_policies']} disabled) and {metrics['vdom_count']} VDOM(s). "
        f"Findings represent potential security posture, operational, or hygiene considerations "
        f"requiring technical review against organizational policy and live operational context."
    )


def generate_static_report(
    config: dict,
    analysis_result: dict,
    health_result: dict,
    metadata: dict | None = None,
) -> str:
    """Generate a self-contained, printable HTML static analysis report."""
    config = config or {}
    analysis_result = analysis_result or {}
    health_result = health_result or {}
    metadata = metadata or {}

    findings = _collect_findings(analysis_result, health_result)
    metrics = _build_metrics(config, analysis_result, health_result, findings)

    filename = metadata.get("filename") or "Uploaded configuration"
    generated_at = metadata.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Render HTML sections
    html_parts: list[str] = []

    html_parts.append(_render_html_header(filename, generated_at))
    html_parts.append(_render_banner(filename, generated_at, metrics))
    html_parts.append(_render_boundary_disclaimer())
    html_parts.append(_render_executive_summary_section(metrics))
    html_parts.append(_render_input_assessment_section(config.get("input_assessment", {})))
    html_parts.append(_render_findings_section(findings))
    html_parts.append(_render_policy_table_section(config, analysis_result))
    html_parts.append(_render_relationships_section(analysis_result))
    html_parts.append(_render_security_profiles_section(config, analysis_result))
    html_parts.append(_render_admin_hardening_section(config, health_result))
    html_parts.append(_render_ipsec_vpn_section(config, analysis_result))
    html_parts.append(_render_ssl_vpn_section(config, analysis_result))
    html_parts.append(_render_local_in_section(config, analysis_result))
    html_parts.append(_render_interface_policies_section(config, analysis_result))
    html_parts.append(_render_ipv6_section(config, analysis_result))
    html_parts.append(_render_integrity_section(health_result))
    html_parts.append(_render_documented_defaults_section(analysis_result, health_result))
    html_parts.append(_render_inventory_summary_section(config))
    html_parts.append(_render_limitations_section())
    html_parts.append(_render_html_footer())

    full_html = "\n".join(html_parts)
    return _sanitize_final_report(full_html)


# ==============================================================================
# SECTION RENDERERS
# ==============================================================================

def _render_html_header(filename: str, generated_at: str) -> str:
    escaped_title = _escape(f"FortiGate Security Analysis Report - {filename}")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escaped_title}</title>
<style>
/* Embedded Professional Stylesheet - Self-Contained & Print-Optimized */
:root {{
  --bg-page: #f8fafc;
  --bg-card: #ffffff;
  --text-main: #1e293b;
  --text-muted: #64748b;
  --border: #e2e8f0;
  --primary: #0f172a;
  --primary-accent: #2563eb;
  --table-stripe: #f8fafc;
}}

* {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background-color: var(--bg-page);
  color: var(--text-main);
  line-height: 1.5;
  font-size: 13.5px;
  padding: 24px;
}}

.container {{
  max-width: 1200px;
  margin: 0 auto;
}}

/* Typography */
h1, h2, h3, h4 {{
  color: var(--primary);
  font-weight: 600;
  line-height: 1.3;
}}

h1 {{ font-size: 24px; margin-bottom: 6px; }}
h2 {{ font-size: 18px; margin-bottom: 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }}
h3 {{ font-size: 15px; margin-bottom: 8px; }}

p {{ margin-bottom: 10px; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; }}

/* Card Containers */
.card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}}

/* Metrics Grid */
.metrics-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin: 16px 0;
}}

.metric-box {{
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  text-align: center;
}}

.metric-label {{
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  font-weight: 600;
  margin-bottom: 4px;
}}

.metric-value {{
  font-size: 20px;
  font-weight: 700;
  color: var(--primary);
}}

/* Badges */
.badge {{
  display: inline-block;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  border: 1px solid transparent;
  white-space: nowrap;
}}

.badge-HIGH {{ background: #fef2f2; color: #991b1b; border-color: #f87171; }}
.badge-MEDIUM {{ background: #fffbeb; color: #b45309; border-color: #fcd34d; }}
.badge-LOW {{ background: #eff6ff; color: #1d4ed8; border-color: #93c5fd; }}
.badge-INFO {{ background: #f8fafc; color: #475569; border-color: #cbd5e1; }}

.badge-ENABLED {{ background: #dcfce7; color: #166534; border-color: #86efac; }}
.badge-DISABLED {{ background: #f1f5f9; color: #64748b; border-color: #cbd5e1; }}
.badge-NOT_OBSERVED {{ background: #f3f4f6; color: #6b7280; border-color: #d1d5db; }}
.badge-RESOLVED {{ background: #dcfce7; color: #166534; border-color: #86efac; }}
.badge-UNRESOLVED {{ background: #fef3c7; color: #b45309; border-color: #fcd34d; }}
.badge-BUILTIN {{ background: #f3e8ff; color: #6b21a8; border-color: #d8b4fe; }}

/* Tables */
.table-wrapper {{
  overflow-x: auto;
  margin-top: 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
}}

table {{
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 12.5px;
}}

th, td {{
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}}

th {{
  background: #f1f5f9;
  color: var(--primary);
  font-weight: 600;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}

tr:nth-child(even) td {{
  background-color: var(--table-stripe);
}}

tr:last-child td {{
  border-bottom: none;
}}

/* Callouts */
.callout {{
  padding: 12px 16px;
  border-radius: 6px;
  margin: 12px 0;
  font-size: 13px;
}}

.callout-info {{
  background: #f0f9ff;
  border-left: 4px solid #0284c7;
  color: #0c4a6e;
}}

.callout-warning {{
  background: #fffbeb;
  border-left: 4px solid #f59e0b;
  color: #78350f;
}}

/* Finding Card */
.finding-item {{
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  margin-bottom: 12px;
  background: #ffffff;
}}

.finding-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}}

.finding-title {{
  font-size: 14px;
  font-weight: 600;
  color: var(--primary);
}}

.finding-meta {{
  font-size: 11.5px;
  color: var(--text-muted);
  margin-bottom: 8px;
}}

.finding-evidence {{
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 8px 12px;
  margin-top: 8px;
  font-size: 12px;
}}

.finding-evidence ul {{
  margin-left: 18px;
}}

/* Print Media Query */
@media print {{
  body {{
    background: #ffffff;
    color: #000000;
    font-size: 10.5pt;
    padding: 0;
  }}
  .container {{
    max-width: 100%;
  }}
  .card, .finding-item, tr {{
    page-break-inside: avoid;
  }}
  .card {{
    box-shadow: none;
    border: 1px solid #cbd5e1;
    margin-bottom: 16px;
    padding: 14px;
  }}
  h1 {{ font-size: 18pt; }}
  h2 {{ font-size: 13pt; margin-top: 8pt; }}
  .no-print {{ display: none !important; }}
}}
</style>
</head>
<body>
<div class="container">
"""


def _render_html_footer() -> str:
    return """
  <div class="card" style="text-align: center; color: var(--text-muted); font-size: 11.5px;">
    FortiGate Security Analyzer &mdash; Static Configuration Assessment Report &mdash; Generated Locally
  </div>
</div>
</body>
</html>
"""


def _render_banner(filename: str, generated_at: str, metrics: dict) -> str:
    platform_label = f"{_escape(metrics['platform'])} · " if metrics.get("platform") else ""
    version_label = f"{platform_label}FortiOS {_escape(metrics['fortios_version'])}" if metrics['fortios_version'] != "unknown" else "FortiOS Version Unknown / Header Absent"
    classification_label = _escape(metrics["classification"].replace("_", " "))

    return f"""
<div class="card" style="border-top: 4px solid var(--primary-accent);">
  <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
    <div>
      <h1>FortiGate Static Configuration Analysis Report</h1>
      <p style="color: var(--text-muted); margin-bottom: 4px;">
        Source: <strong>{_escape(filename)}</strong> &nbsp;|&nbsp; Generated: <strong>{_escape(generated_at)}</strong>
      </p>
      <p style="color: var(--text-muted); font-size: 12px;">
        Environment: <strong>{version_label}</strong> &nbsp;|&nbsp; Scope: <strong>{classification_label}</strong>
      </p>
    </div>
  </div>
</div>
"""


def _render_boundary_disclaimer() -> str:
    return """
<div class="callout callout-info">
  <strong>Static vs. Runtime Analysis Boundary:</strong>
  This report is generated exclusively through static analysis of the supplied FortiGate configuration file.
  Static analysis evaluates configured policies, object relationships, configured security profiles, VPN definitions, and internal configuration consistency.
  It <strong>cannot</strong> establish live operational state, including tunnel UP/DOWN status, live network reachability, effective runtime routing, active sessions, CPU/RAM utilization, live FortiGuard connectivity, or user authentication success.
  Diagnostic evaluation of live operational health is performed via the separate Runtime Health Analysis workflow.
</div>
"""


def _render_executive_summary_section(metrics: dict) -> str:
    summary_text = _render_executive_summary_text(metrics)
    high = metrics["severity_counts"]["HIGH"]
    med = metrics["severity_counts"]["MEDIUM"]
    low = metrics["severity_counts"]["LOW"]
    info = metrics["severity_counts"]["INFO"]

    vdom_subtext = ""
    if metrics.get("vdoms"):
        vdom_subtext = f'<div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">{_escape(", ".join(metrics["vdoms"]))}</div>'

    return f"""
<div class="card">
  <h2>1. Executive Summary</h2>
  <p>{_escape(summary_text)}</p>

  <div class="metrics-grid">
    <div class="metric-box">
      <div class="metric-label">High Findings</div>
      <div class="metric-value" style="color: #991b1b;">{high}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Medium Findings</div>
      <div class="metric-value" style="color: #b45309;">{med}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Low Findings</div>
      <div class="metric-value" style="color: #1d4ed8;">{low}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Informational</div>
      <div class="metric-value" style="color: #475569;">{info}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Total Policies</div>
      <div class="metric-value">{metrics['total_policies']}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">VDOMs Detected</div>
      <div class="metric-value">{metrics['vdom_count']}</div>
      {vdom_subtext}
    </div>
    <div class="metric-box">
      <div class="metric-label">IPsec Tunnels</div>
      <div class="metric-value">{metrics['ipsec_count']}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">SSL-VPN Status</div>
      <div class="metric-value" style="font-size: 15px; margin-top: 4px;">
        <span class="badge badge-{_escape(metrics['ssl_vpn_status'])}">{_escape(metrics['ssl_vpn_status'])}</span>
      </div>
    </div>
  </div>
</div>
"""


def _render_input_assessment_section(input_assessment: dict) -> str:
    if not input_assessment:
        return ""

    classification = _escape(input_assessment.get("classification", "UNKNOWN").replace("_", " "))
    recognized = input_assessment.get("recognized_sections", [])
    warnings = input_assessment.get("structural_warnings", [])
    scope = input_assessment.get("analysis_scope", {})
    explanations = input_assessment.get("explanation", [])

    scope_rows: list[str] = []
    if isinstance(scope, dict):
        for domain, info in sorted(scope.items()):
            status = info.get("status", "UNKNOWN")
            evidence = info.get("evidence", "-")
            badge_class = "badge-ENABLED" if status == "COVERED" else ("badge-DISABLED" if status == "UNOBSERVED_IN_INPUT" else "badge-MEDIUM")
            domain_label = domain.replace("_", " ").title()
            scope_rows.append(f"""
            <tr>
              <td><strong>{_escape(domain_label)}</strong></td>
              <td><span class="badge {badge_class}">{_escape(status)}</span></td>
              <td>{_escape(evidence)}</td>
            </tr>
            """)

    warning_block = ""
    if warnings:
        warn_items = "".join(f"<li>{_escape(w)}</li>" for w in warnings)
        warning_block = f"""
        <div class="callout callout-warning" style="margin-top: 12px;">
          <strong>Structural Observations:</strong>
          <ul style="margin-left: 18px; margin-top: 4px;">{warn_items}</ul>
        </div>
        """

    explanation_block = ""
    if explanations and isinstance(explanations, list):
        expl_items = "".join(f"<li>{_escape(e)}</li>" for e in explanations)
        explanation_block = f"""
        <div style="margin-top: 8px; margin-bottom: 12px; font-size: 12.5px; color: var(--text-muted);">
          <strong>Scope Observations:</strong>
          <ul style="margin-left: 18px; margin-top: 4px;">{expl_items}</ul>
        </div>
        """

    return f"""
<div class="card">
  <h2>2. Input Quality &amp; Analysis Scope Assessment</h2>
  <p>
    Input Classification: <strong>{classification}</strong> &nbsp;|&nbsp;
    Recognized Config Tables: <strong>{len(recognized)}</strong>
  </p>
  {explanation_block}
  {warning_block}

  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th style="width: 25%;">Analysis Domain</th>
          <th style="width: 25%;">Input Status</th>
          <th style="width: 50%;">Evidence & Observations</th>
        </tr>
      </thead>
      <tbody>
        {''.join(scope_rows) if scope_rows else '<tr><td colspan="3">No domain scope data recorded.</td></tr>'}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_findings_section(findings: list[dict]) -> str:
    if not findings:
        return """
<div class="card">
  <h2>3. Review Findings by Category</h2>
  <div class="callout callout-info">
    No security or configuration review findings were identified by the supported static analysis rules.
  </div>
</div>
"""

    categories: dict[str, list[dict]] = {}
    for f in findings:
        cat = f["category"]
        categories.setdefault(cat, []).append(f)

    rendered_categories: list[str] = []
    for cat_name, cat_findings in categories.items():
        items_html: list[str] = []
        for item in cat_findings:
            sev = item["severity"]
            badge = f'<span class="badge badge-{_escape(sev)}">{_escape(sev)}</span>'
            ev_html = ""
            if item.get("evidence"):
                ev_lines = "".join(f"<li><code>{_escape(e)}</code></li>" for e in item["evidence"])
                ev_html = f"""
                <div class="finding-evidence">
                  <strong>Supporting Configuration Evidence:</strong>
                  <ul>{ev_lines}</ul>
                </div>
                """

            affected_str = _escape(item.get("affected_object") or "-")
            basis_str = _escape(item.get("analysis_basis") or "Static Configuration Check")

            items_html.append(f"""
            <div class="finding-item">
              <div class="finding-header">
                <span class="finding-title">{_escape(item['title'])}</span>
                {badge}
              </div>
              <div class="finding-meta">
                Affected: <strong>{affected_str}</strong> &nbsp;|&nbsp;
                Source: <strong>{_escape(item['source'])}</strong> &nbsp;|&nbsp;
                Basis: <strong>{basis_str}</strong>
              </div>
              <p><strong>Description:</strong> {_escape(item['description'])}</p>
              <p><strong>Recommendation:</strong> {_escape(item['recommendation'])}</p>
              {ev_html}
            </div>
            """)

        rendered_categories.append(f"""
        <div style="margin-top: 16px;">
          <h3>{_escape(cat_name)} ({len(cat_findings)})</h3>
          {''.join(items_html)}
        </div>
        """)

    return f"""
<div class="card">
  <h2>3. Review Findings by Category ({len(findings)})</h2>
  {''.join(rendered_categories)}
</div>
"""


def _render_policy_table_section(config: dict, analysis_result: dict) -> str:
    policies = config.get("policies", [])
    if not isinstance(policies, list) or not policies:
        return """
<div class="card">
  <h2>4. Firewall Policy Inventory &amp; Analysis</h2>
  <p style="color: var(--text-muted);">No firewall policies were found in the uploaded configuration.</p>
</div>
"""

    assessments_by_id: dict[str, dict] = {}
    for a in analysis_result.get("policy_assessments", []):
        pid = str(a.get("policy_id"))
        vdom = str(a.get("vdom") or "")
        assessments_by_id[f"{vdom}|{pid}"] = a

    rows_html: list[str] = []
    # If policy count is very large (>500), cap table rendering with notice
    limit = 500
    shown_policies = policies[:limit]

    for p in shown_policies:
        pid = str(p.get("id") or "-")
        name = str(p.get("name") or "-")
        vdom = str(p.get("vdom") or "root")
        status_raw = str(p.get("status") or "enable").upper()
        status_badge = "badge-ENABLED" if status_raw in {"ENABLE", "ENABLED"} else "badge-DISABLED"

        # Check address family
        is_v6 = bool(p.get("srcaddr6") or p.get("dstaddr6"))
        family_badge = '<span class="badge" style="background:#e0e7ff; color:#3730a3;">IPv6</span>' if is_v6 else '<span class="badge" style="background:#f1f5f9; color:#475569;">IPv4</span>'

        srcintf = _format_list(p.get("srcintf"))
        dstintf = _format_list(p.get("dstintf"))
        srcaddr = _format_list(p.get("srcaddr6") if is_v6 else p.get("srcaddr"))
        dstaddr = _format_list(p.get("dstaddr6") if is_v6 else p.get("dstaddr"))
        service = _format_list(p.get("service"))
        action = str(p.get("action") or "deny").upper()
        action_color = "#166534" if action == "ACCEPT" else "#991b1b"

        # Lookup technical purpose from assessment
        assessment = assessments_by_id.get(f"{vdom}|{pid}") or {}
        flow_type = assessment.get("flow_type") or "-"
        purpose = assessment.get("technical_purpose") or "-"

        # Profile summary
        profiles = []
        if p.get("ips-sensor"):
            profiles.append(f"IPS:{p.get('ips-sensor')}")
        if p.get("av-profile"):
            profiles.append(f"AV:{p.get('av-profile')}")
        if p.get("webfilter-profile"):
            profiles.append(f"Web:{p.get('webfilter-profile')}")
        if p.get("application-list"):
            profiles.append(f"App:{p.get('application-list')}")
        if p.get("ssl-ssh-profile"):
            profiles.append(f"SSL:{p.get('ssl-ssh-profile')}")
        profile_str = _format_list(profiles, max_items=2)

        rows_html.append(f"""
        <tr>
          <td><strong>#{_escape(pid)}</strong></td>
          <td>{_escape(name)}</td>
          <td>{family_badge}</td>
          <td><span class="badge {status_badge}">{_escape(status_raw)}</span></td>
          <td>{_escape(srcintf)} &rarr; {_escape(dstintf)}</td>
          <td>{srcaddr} &rarr; {dstaddr}</td>
          <td>{service}</td>
          <td><strong style="color: {action_color};">{_escape(action)}</strong></td>
          <td>{_escape(flow_type)}</td>
          <td>{profile_str}</td>
        </tr>
        """)

    truncation_notice = ""
    if len(policies) > limit:
        truncation_notice = f"""
        <div class="callout callout-info">
          Displaying first {limit} of {len(policies)} policies in the inventory table. All {len(policies)} policies were fully evaluated for findings.
        </div>
        """

    return f"""
<div class="card">
  <h2>4. Firewall Policy Inventory ({len(policies)})</h2>
  {truncation_notice}
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Family</th>
          <th>Status</th>
          <th>Interfaces</th>
          <th>Source &rarr; Destination</th>
          <th>Service</th>
          <th>Action</th>
          <th>Inferred Flow</th>
          <th>Profiles</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_relationships_section(analysis_result: dict) -> str:
    findings = analysis_result.get("findings", [])
    relationships = [
        f for f in findings
        if f.get("title") in {"Duplicate Firewall Policy", "Fully Shadowed Firewall Policy", "Conflicting Policy Shadowing"}
    ]

    if not relationships:
        return """
<div class="card">
  <h2>5. Policy Duplicate &amp; Shadowing Analysis</h2>
  <div class="callout callout-info">
    No duplicate or fully shadowed firewall policies were detected in the supplied configuration.
  </div>
</div>
"""

    rows_html: list[str] = []
    for f in relationships:
        sev = f.get("severity", "INFO")
        title = f.get("title", "Relationship")
        pid = f.get("policy_id")
        pname = f.get("policy_name")
        shadow_id = f.get("shadowed_by_policy_id")
        shadow_name = f.get("shadowed_by_policy_name")
        vdom = f.get("vdom") or "root"
        reasons = _format_list(f.get("reasons", []), max_items=2)

        rows_html.append(f"""
        <tr>
          <td><span class="badge badge-{_escape(sev)}">{_escape(sev)}</span></td>
          <td><strong>{_escape(title)}</strong></td>
          <td>Policy #{_escape(pid)} ({_escape(pname)})</td>
          <td>Policy #{_escape(shadow_id)} ({_escape(shadow_name)})</td>
          <td>{_escape(vdom)}</td>
          <td>{reasons}</td>
        </tr>
        """)

    return f"""
<div class="card">
  <h2>5. Policy Duplicate &amp; Shadowing Analysis ({len(relationships)})</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Rule ordering and containment analysis evaluates whether later policies are identical to, shadowed by, or conflict with earlier policies.
  </p>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Relationship Type</th>
          <th>Later Policy</th>
          <th>Earlier (Shadowing) Policy</th>
          <th>VDOM</th>
          <th>Containment Basis</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_security_profiles_section(config: dict, analysis_result: dict) -> str:
    # Summarize profile tables
    profile_counts = {
        "IPS Sensors": len(config.get("ips_sensors", [])) if isinstance(config.get("ips_sensors"), list) else 0,
        "Antivirus Profiles": len(config.get("antivirus_profiles", [])) if isinstance(config.get("antivirus_profiles"), list) else 0,
        "Web Filter Profiles": len(config.get("webfilter_profiles", [])) if isinstance(config.get("webfilter_profiles"), list) else 0,
        "Application Lists": len(config.get("application_lists", [])) if isinstance(config.get("application_lists"), list) else 0,
        "SSL/SSH Profiles": len(config.get("ssl_ssh_profiles", [])) if isinstance(config.get("ssl_ssh_profiles"), list) else 0,
        "DNS Filter Profiles": len(config.get("dnsfilter_profiles", [])) if isinstance(config.get("dnsfilter_profiles"), list) else 0,
    }

    boxes_html = "".join(
        f"""
        <div class="metric-box">
          <div class="metric-label">{_escape(k)}</div>
          <div class="metric-value">{v}</div>
        </div>
        """
        for k, v in profile_counts.items()
    )

    return f"""
<div class="card">
  <h2>6. Security Profiles Inventory &amp; Inspection Overview</h2>
  <div class="metrics-grid">
    {boxes_html}
  </div>
  <p style="color: var(--text-muted); font-size: 12px; margin-top: 8px;">
    FortiOS inspection profiles enforce threat prevention (IPS, AV, Web Filtering, Application Control) when attached to policies with UTM enabled.
  </p>
</div>
"""


def _render_admin_hardening_section(config: dict, health_result: dict) -> str:
    admins = config.get("admins", [])
    dns = config.get("dns") or {}
    ntp = config.get("ntp") or {}

    has_data = bool(admins or dns or ntp)
    if not has_data:
        return ""

    admin_rows: list[str] = []
    if isinstance(admins, list):
        for adm in admins:
            if not isinstance(adm, dict):
                continue
            name = adm.get("name") or "-"
            accprofile = adm.get("accprofile") or "-"
            vdom = adm.get("vdom") or "root"
            trusthosts = []
            for i in range(1, 11):
                th = adm.get(f"trusthost{i}")
                if th:
                    trusthosts.append(str(th))
            th_str = _format_list(trusthosts, max_items=2)

            admin_rows.append(f"""
            <tr>
              <td><strong>{_escape(name)}</strong></td>
              <td>{_escape(accprofile)}</td>
              <td>{_escape(vdom)}</td>
              <td>{th_str}</td>
            </tr>
            """)

    dns_primary = dns.get("primary") or "-" if isinstance(dns, dict) else "-"
    dns_secondary = dns.get("secondary") or "-" if isinstance(dns, dict) else "-"
    ntp_server = "-"
    if isinstance(ntp, dict):
        servers = ntp.get("ntpserver", [])
        if isinstance(servers, list) and servers:
            ntp_server = ", ".join(str(s.get("server", s)) if isinstance(s, dict) else str(s) for s in servers)
        elif ntp.get("ntpserver"):
            ntp_server = str(ntp.get("ntpserver"))

    return f"""
<div class="card">
  <h2>7. Administrative Access &amp; System Hardening</h2>
  <div style="display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 12px;">
    <div><strong>DNS Primary:</strong> <code>{_escape(dns_primary)}</code> &nbsp;|&nbsp; <strong>Secondary:</strong> <code>{_escape(dns_secondary)}</code></div>
    <div><strong>NTP Servers:</strong> <code>{_escape(ntp_server)}</code></div>
  </div>

  {'<div style="margin-top: 12px;"><h3>Administrator Accounts (' + str(len(admin_rows)) + ')</h3><div class="table-wrapper"><table><thead><tr><th>Admin Name</th><th>Profile</th><th>VDOM</th><th>Trusted Hosts</th></tr></thead><tbody>' + ''.join(admin_rows) + '</tbody></table></div></div>' if admin_rows else '<p style="color: var(--text-muted); font-size: 12px;">No custom administrator accounts found in backup.</p>'}
</div>
"""


def _render_ipsec_vpn_section(config: dict, analysis_result: dict) -> str:
    p1 = config.get("ipsec_phase1", [])
    if not isinstance(p1, list):
        p1 = []

    p2 = config.get("ipsec_phase2", [])
    if not isinstance(p2, list):
        p2 = []

    if not p1 and not p2:
        return ""

    p1_rows: list[str] = []
    for phase1 in p1:
        name = phase1.get("name") or "-"
        intf = phase1.get("interface") or "-"
        vdom = phase1.get("vdom") or "root"
        def_type = phase1.get("definition_type") or "phase1-interface"
        remote_gw = phase1.get("remote-gw") or "Dynamic / Dial-up"
        proposal = phase1.get("proposal") or "-"
        dhgrp = phase1.get("dhgrp") or "-"

        p1_rows.append(f"""
        <tr>
          <td><strong>{_escape(name)}</strong></td>
          <td>{_escape(intf)}</td>
          <td>{_escape(vdom)}</td>
          <td>{_escape(def_type)}</td>
          <td>{_escape(remote_gw)}</td>
          <td>{_escape(proposal)} (DH: {_escape(dhgrp)})</td>
        </tr>
        """)

    return f"""
<div class="card">
  <h2>7. IPsec VPN Static Configuration ({len(p1)} Tunnels)</h2>
  <div class="callout callout-info">
    Static configuration confirms configured IPsec Phase 1/Phase 2 parameters and interface bindings. It does not establish live tunnel UP/DOWN state or passing traffic.
  </div>

  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Interface</th>
          <th>VDOM</th>
          <th>Type</th>
          <th>Remote Gateway</th>
          <th>Proposal & DH Group</th>
        </tr>
      </thead>
      <tbody>
        {''.join(p1_rows) if p1_rows else '<tr><td colspan="6">No Phase 1 definitions found.</td></tr>'}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_ssl_vpn_section(config: dict, analysis_result: dict) -> str:
    ssl_settings = config.get("ssl_vpn_settings", [])
    if isinstance(ssl_settings, list) and ssl_settings:
        ssl_obj = ssl_settings[0]
    elif isinstance(ssl_settings, dict):
        ssl_obj = ssl_settings
    else:
        ssl_obj = {}

    portals = config.get("ssl_vpn_portals", [])
    if not isinstance(portals, list):
        portals = []

    if not ssl_obj and not portals:
        return ""

    status = str(ssl_obj.get("status", "NOT_OBSERVED")).upper()
    port = str(ssl_obj.get("port") or "443")
    cert = str(ssl_obj.get("servercert") or "-")
    min_tls = str(ssl_obj.get("ssl-min-proto-ver") or "-")
    interfaces = _format_list(ssl_obj.get("source-interface"))
    src_addrs = _format_list(ssl_obj.get("source-address"))
    src_addrs6 = _format_list(ssl_obj.get("source-address6"))

    portal_rows: list[str] = []
    for p in portals:
        pname = p.get("name") or "-"
        tunnel = str(p.get("tunnel-mode") or "disable").upper()
        web = str(p.get("web-mode") or "enable").upper()
        split = str(p.get("split-tunneling") or "disable").upper()
        pools = _format_list(p.get("ip-pools"))
        portal_rows.append(f"""
        <tr>
          <td><strong>{_escape(pname)}</strong></td>
          <td><span class="badge badge-{_escape(tunnel)}">{_escape(tunnel)}</span></td>
          <td><span class="badge badge-{_escape(web)}">{_escape(web)}</span></td>
          <td>{_escape(split)}</td>
          <td>{pools}</td>
        </tr>
        """)

    # Auth rules
    raw_rules = ssl_obj.get("authentication_rules", []) if isinstance(ssl_obj, dict) else []
    rule_rows: list[str] = []
    for r in raw_rules:
        rid = str(r.get("id") or "-")
        portal_ref = str(r.get("portal") or "-")
        groups = _format_list(r.get("groups"))
        users = _format_list(r.get("users"))
        src_intfs = _format_list(r.get("source-interface"))
        rule_rows.append(f"""
        <tr>
          <td><strong>#{_escape(rid)}</strong></td>
          <td>{_escape(portal_ref)}</td>
          <td>{groups}</td>
          <td>{users}</td>
          <td>{src_intfs}</td>
        </tr>
        """)

    return f"""
<div class="card">
  <h2>8. SSL-VPN Remote Access Configuration</h2>
  <div class="callout callout-info">
    Static analysis assesses SSL-VPN service status, portal mode, listening interfaces, and authentication mappings. It does not establish Internet reachability or authentication runtime state.
  </div>

  <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 12px;">
    <div>Service Status: <span class="badge badge-{_escape(status)}">{_escape(status)}</span></div>
    <div>Port: <strong>{_escape(port)}</strong></div>
    <div>Server Certificate: <strong>{_escape(cert)}</strong></div>
    <div>Minimum TLS: <strong>{_escape(min_tls)}</strong></div>
  </div>
  <p style="color: var(--text-muted); font-size: 12.5px; margin-bottom: 12px;">
    Listening Interfaces: <strong>{interfaces}</strong> &nbsp;|&nbsp;
    Source Restrictions (IPv4): <strong>{src_addrs}</strong> &nbsp;|&nbsp;
    Source Restrictions (IPv6): <strong>{src_addrs6}</strong>
  </p>

  {'<div style="margin-top: 12px;"><h3>Web Portals (' + str(len(portals)) + ')</h3><div class="table-wrapper"><table><thead><tr><th>Portal Name</th><th>Tunnel Mode</th><th>Web Mode</th><th>Split Tunneling</th><th>IP Pools</th></tr></thead><tbody>' + ''.join(portal_rows) + '</tbody></table></div></div>' if portal_rows else ''}

  {'<div style="margin-top: 12px;"><h3>Authentication Rules (' + str(len(raw_rules)) + ')</h3><div class="table-wrapper"><table><thead><tr><th>Rule ID</th><th>Portal</th><th>User Groups</th><th>Users</th><th>Source Interfaces</th></tr></thead><tbody>' + ''.join(rule_rows) + '</tbody></table></div></div>' if rule_rows else ''}
</div>
"""


def _render_local_in_section(config: dict, analysis_result: dict) -> str:
    local_in = config.get("local_in_policies", [])
    local_in6 = config.get("local_in_policies6", [])
    total_local = (len(local_in) if isinstance(local_in, list) else 0) + (len(local_in6) if isinstance(local_in6, list) else 0)

    if total_local == 0:
        return ""

    local_rows: list[str] = []
    if isinstance(local_in, list):
        for p in local_in:
            local_rows.append(f"""
            <tr>
              <td><strong>#{_escape(p.get('id', '-'))}</strong></td>
              <td><span class="badge" style="background:#f1f5f9; color:#475569;">IPv4</span></td>
              <td>{_escape(p.get('intf', '-'))}</td>
              <td>{_format_list(p.get('srcaddr'))} &rarr; {_format_list(p.get('dstaddr'))}</td>
              <td>{_format_list(p.get('service'))}</td>
              <td><strong>{_escape(str(p.get('action', 'deny')).upper())}</strong></td>
            </tr>
            """)
    if isinstance(local_in6, list):
        for p in local_in6:
            local_rows.append(f"""
            <tr>
              <td><strong>#{_escape(p.get('id', '-'))}</strong></td>
              <td><span class="badge" style="background:#e0e7ff; color:#3730a3;">IPv6</span></td>
              <td>{_escape(p.get('intf', '-'))}</td>
              <td>{_format_list(p.get('srcaddr6') or p.get('srcaddr'))} &rarr; {_format_list(p.get('dstaddr6') or p.get('dstaddr'))}</td>
              <td>{_format_list(p.get('service6') or p.get('service'))}</td>
              <td><strong>{_escape(str(p.get('action', 'deny')).upper())}</strong></td>
            </tr>
            """)

    return f"""
<div class="card">
  <h2>9. Local-In Policies ({total_local})</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Local-in policies filter traffic addressed directly to the FortiGate management and control plane before reaching local daemons.
  </p>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Family</th>
          <th>Interface</th>
          <th>Source &rarr; Destination</th>
          <th>Service</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {''.join(local_rows)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_interface_policies_section(config: dict, analysis_result: dict) -> str:
    intf_pol = config.get("interface_policies", [])
    intf_pol6 = config.get("interface_policies6", [])
    total_intf = (len(intf_pol) if isinstance(intf_pol, list) else 0) + (len(intf_pol6) if isinstance(intf_pol6, list) else 0)

    if total_intf == 0:
        return ""

    rows: list[str] = []
    if isinstance(intf_pol, list):
        for p in intf_pol:
            rows.append(f"""
            <tr>
              <td><strong>#{_escape(p.get('id', '-'))}</strong></td>
              <td><span class="badge" style="background:#f1f5f9; color:#475569;">IPv4</span></td>
              <td>{_escape(p.get('srcintf', '-'))}</td>
              <td>{_format_list(p.get('srcaddr'))} &rarr; {_format_list(p.get('dstaddr'))}</td>
              <td>{_format_list(p.get('service'))}</td>
              <td>IPS: <code>{_escape(p.get('ips-sensor', '-'))}</code></td>
            </tr>
            """)
    if isinstance(intf_pol6, list):
        for p in intf_pol6:
            rows.append(f"""
            <tr>
              <td><strong>#{_escape(p.get('id', '-'))}</strong></td>
              <td><span class="badge" style="background:#e0e7ff; color:#3730a3;">IPv6</span></td>
              <td>{_escape(p.get('srcintf', '-'))}</td>
              <td>{_format_list(p.get('srcaddr6') or p.get('srcaddr'))} &rarr; {_format_list(p.get('dstaddr6') or p.get('dstaddr'))}</td>
              <td>{_format_list(p.get('service6') or p.get('service'))}</td>
              <td>IPS: <code>{_escape(p.get('ips-sensor', '-'))}</code></td>
            </tr>
            """)

    return f"""
<div class="card">
  <h2>10. Interface Policies ({total_intf})</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Interface policies apply stateless inspection profiles (e.g. IPS sensor, application list) directly to ingress interfaces before forwarding firewall policy evaluation.
  </p>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Family</th>
          <th>Interface</th>
          <th>Source &rarr; Destination</th>
          <th>Service</th>
          <th>Attached Inspection</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_integrity_section(health_result: dict) -> str:
    checks = health_result.get("checks", [])
    integrity_checks = [
        c for c in checks
        if c.get("category") == "Configuration Integrity" or "Unresolved" in (c.get("title") or "")
    ]

    if not integrity_checks:
        return """
<div class="card">
  <h2>11. Configuration Integrity &amp; Reference Resolution</h2>
  <div class="callout callout-info">
    All referenced objects, interfaces, address objects, and security profiles evaluated during analysis were successfully resolved within the configuration context.
  </div>
</div>
"""

    rows: list[str] = []
    for c in integrity_checks:
        sev = c.get("severity", "MEDIUM")
        title = c.get("title", "Integrity Issue")
        for ev in c.get("evidence", []):
            rows.append(f"""
            <tr>
              <td><span class="badge badge-{_escape(sev)}">{_escape(sev)}</span></td>
              <td><strong>{_escape(title)}</strong></td>
              <td><code>{_escape(ev)}</code></td>
            </tr>
            """)

    return f"""
<div class="card">
  <h2>11. Configuration Integrity &amp; Reference Resolution ({len(rows)} Observations)</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Unresolved references occur when a policy or setting points to an object (address, interface, service, or profile) that is missing from the configuration file.
  </p>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Integrity Review Item</th>
          <th>Reference Evidence</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_ipv6_section(config: dict, analysis_result: dict) -> str:
    addr6 = len(config.get("addresses6", [])) if isinstance(config.get("addresses6"), list) else 0
    grp6 = len(config.get("address_groups6", [])) if isinstance(config.get("address_groups6"), list) else 0
    vip6 = len(config.get("vips6", [])) if isinstance(config.get("vips6"), list) else 0
    local_in6 = len(config.get("local_in_policies6", [])) if isinstance(config.get("local_in_policies6"), list) else 0
    intf_pol6 = len(config.get("interface_policies6", [])) if isinstance(config.get("interface_policies6"), list) else 0

    policies = config.get("policies", [])
    pol6 = sum(1 for p in policies if isinstance(p, dict) and (p.get("srcaddr6") or p.get("dstaddr6"))) if isinstance(policies, list) else 0

    total_v6 = addr6 + grp6 + vip6 + local_in6 + intf_pol6 + pol6
    if total_v6 == 0:
        return ""

    return f"""
<div class="card">
  <h2>12. IPv6 Static Analysis Coverage</h2>
  <div class="metrics-grid">
    <div class="metric-box">
      <div class="metric-label">IPv6 Policies</div>
      <div class="metric-value">{pol6}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Addresses (IPv6)</div>
      <div class="metric-value">{addr6}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Address Groups (IPv6)</div>
      <div class="metric-value">{grp6}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">VIPs (IPv6)</div>
      <div class="metric-value">{vip6}</div>
    </div>
    <div class="metric-box">
      <div class="metric-label">Local-In (IPv6)</div>
      <div class="metric-value">{local_in6}</div>
    </div>
  </div>
  <p style="color: var(--text-muted); font-size: 12px; margin-top: 8px;">
    IPv4 and IPv6 rules and objects are strictly isolated; IPv4 rules cannot resolve IPv6 address objects and vice versa.
  </p>
</div>
"""


def _render_documented_defaults_section(analysis_result: dict, health_result: dict | None = None) -> str:
    defaults = analysis_result.get("documented_defaults")
    if defaults is None and isinstance(health_result, dict):
        defaults = health_result.get("documented_defaults")
    if not isinstance(defaults, list):
        defaults = []

    if not defaults:
        return """
<div class="card">
  <h2>13. Documented FortiOS Defaults Applied (0)</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Where explicit configuration was absent, verified FortiOS documented defaults were evaluated. No documented defaults were applied to this configuration.
  </p>
</div>
"""

    rows_html: list[str] = []
    for d in defaults:
        sec = d.get("section") or "-"
        field = d.get("field") or "-"
        val = d.get("effective_value") or "-"
        ver = d.get("fortios_version") or "-"
        doc = d.get("documentation") or "-"

        rows_html.append(f"""
        <tr>
          <td><code>{_escape(sec)}.{_escape(field)}</code></td>
          <td><code>{_escape(val)}</code></td>
          <td><span class="badge badge-INFO">DOCUMENTED_DEFAULT</span></td>
          <td>FortiOS {_escape(ver)}</td>
          <td>{_escape(doc)}</td>
        </tr>
        """)

    return f"""
<div class="card">
  <h2>13. Documented FortiOS Defaults Applied ({len(defaults)})</h2>
  <p style="color: var(--text-muted); font-size: 12.5px;">
    Where explicit configuration settings were absent, verified FortiOS version-aware default rules were applied to represent configuration facts neutrally. These are baseline facts, not review findings.
  </p>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Configuration Path</th>
          <th>Effective Default Value</th>
          <th>Source</th>
          <th>Version Branch</th>
          <th>Documentation Basis</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_inventory_summary_section(config: dict) -> str:
    inventory_items = [
        ("Firewall Policies", len(config.get("policies", [])) if isinstance(config.get("policies"), list) else 0),
        ("Local-In Policies", len(config.get("local_in_policies", [])) if isinstance(config.get("local_in_policies"), list) else 0),
        ("Interface Policies", len(config.get("interface_policies", [])) if isinstance(config.get("interface_policies"), list) else 0),
        ("System Interfaces", len(config.get("interfaces", [])) if isinstance(config.get("interfaces"), list) else 0),
        ("Firewall Addresses", len(config.get("addresses", [])) if isinstance(config.get("addresses"), list) else 0),
        ("Address Groups", len(config.get("address_groups", [])) if isinstance(config.get("address_groups"), list) else 0),
        ("Firewall Services", len(config.get("services", [])) if isinstance(config.get("services"), list) else 0),
        ("Service Groups", len(config.get("service_groups", [])) if isinstance(config.get("service_groups"), list) else 0),
        ("Virtual IPs (VIPs)", len(config.get("vips", [])) if isinstance(config.get("vips"), list) else 0),
        ("IPsec Phase 1", len(config.get("ipsec_phase1", [])) if isinstance(config.get("ipsec_phase1"), list) else 0),
        ("IPsec Phase 2", len(config.get("ipsec_phase2", [])) if isinstance(config.get("ipsec_phase2"), list) else 0),
        ("Administrators", len(config.get("admins", [])) if isinstance(config.get("admins"), list) else 0),
        ("Local Users", len(config.get("user_locals", [])) if isinstance(config.get("user_locals"), list) else 0),
        ("User Groups", len(config.get("user_groups", [])) if isinstance(config.get("user_groups"), list) else 0),
    ]

    boxes_html = "".join(
        f"""
        <div class="metric-box">
          <div class="metric-label">{_escape(k)}</div>
          <div class="metric-value">{v}</div>
        </div>
        """
        for k, v in inventory_items
    )

    return f"""
<div class="card">
  <h2>14. Configuration Inventory Summary</h2>
  <div class="metrics-grid">
    {boxes_html}
  </div>
</div>
"""


def _render_limitations_section() -> str:
    return """
<div class="card">
  <h2>15. Analysis Methodology &amp; Limitations</h2>
  <p>
    The FortiGate Security Analyzer performs automated, explainable static inspection of exported configuration text files.
    The methodology is subject to the following technical boundaries:
  </p>
  <ul style="margin-left: 20px; line-height: 1.8; color: var(--text-muted); font-size: 13px;">
    <li><strong>Static Configuration Scope:</strong> Findings evaluate static settings. Unused or dormant policies cannot be distinguished from active rules without live hit counts.</li>
    <li><strong>Partial Backups:</strong> Omission of configuration sections (e.g. system interfaces, users, or routing) is reported as scope limitations rather than false vulnerabilities.</li>
    <li><strong>No Runtime Verification:</strong> Static analysis does not verify live routing convergence, interface link state, license validity, or FortiGuard update reachability.</li>
    <li><strong>No Vulnerability Database / CVE Lookup:</strong> Findings reflect static configuration hardening and consistency; they do not report firmware CVEs or hardware lifecycle dates.</li>
    <li><strong>Secret Suppression:</strong> Passwords, pre-shared keys, private keys, and encryption hashes are strictly omitted from analysis outputs to ensure safe distribution.</li>
  </ul>
</div>
"""
