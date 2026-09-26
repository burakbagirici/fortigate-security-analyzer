"""Public machine-readable JSON projection engine for FortiGate Static Analysis.

Conforms to schema_version 1.0.
Provides an explicit, safe, normalized public projection with strict secret exclusion.
"""

from __future__ import annotations

import re
from typing import Any

from . import __version__

SCHEMA_VERSION = "1.0"
SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")

FALLBACK_SECRET_PATTERNS = [
    re.compile(r"\bENC\s+[A-Za-z0-9+/=]{16,}\b", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+[A-Z\s]*PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]*PRIVATE\s+KEY-----", re.IGNORECASE),
    re.compile(r"(?:set\s+)?(password|passwd|psksecret|private-key)\s+([\"'][^\"']+[\"']|\S+)", re.IGNORECASE),
]

FORBIDDEN_SECRET_KEYS = {
    "password",
    "passwd",
    "old-password",
    "psksecret",
    "private-key",
    "private_key",
    "token",
    "otp",
    "community",
    "secret",
}

METHODOLOGY_LIMITATIONS = [
    "Static Configuration Scope: Findings evaluate static configuration settings offline. Unused or dormant policies cannot be distinguished from active rules without live hit counters.",
    "Partial Backups: Omission of configuration sections (e.g. system interfaces, users, or routing) is reported as scope limitations rather than false vulnerabilities.",
    "No Runtime Verification: Static analysis does not verify live routing convergence, interface link state, license validity, or FortiGuard update reachability.",
    "No Vulnerability Database / CVE Lookup: Findings reflect static configuration hardening and consistency; they do not report firmware CVEs or hardware lifecycle dates.",
    "Secret Suppression: Passwords, pre-shared keys, private keys, and encryption hashes are strictly omitted from analysis outputs to ensure safe distribution.",
]


def _list_strings(value: Any) -> list[str]:
    """Convert scalar or list value into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    val_str = str(value).strip()
    return [val_str] if val_str else []


def _collect_unified_findings(analysis_result: dict[str, Any], health_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect and normalize findings from analyzer and health checks."""
    unified: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. Health check findings
    for check in health_result.get("checks", []):
        if not isinstance(check, dict):
            continue
        category = str(check.get("category", "SYSTEM_HEALTH")).upper()
        severity = str(check.get("severity", "INFO")).upper()
        if severity not in SEVERITY_ORDER:
            severity = "INFO"
        title = str(check.get("title", "Health Observation"))
        vdom = str(check.get("vdom") or "root")
        policy_id = str(check.get("policy_id")) if check.get("policy_id") is not None else None
        object_name = str(check.get("affected_object") or check.get("object_name") or "-")

        dedup_key = f"HEALTH|{category}|{severity}|{title}|{vdom}|{policy_id}|{object_name}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        evidence = [_clean_string(str(e)) for e in check.get("evidence", []) if str(e).strip()]

        unified.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": str(check.get("description", "")),
            "recommendation": str(check.get("recommendation", "")),
            "vdom": vdom,
            "policy_id": policy_id,
            "object_name": object_name if object_name != "-" else None,
            "evidence": evidence,
        })

    # 2. Forwarding policy findings
    for finding in analysis_result.get("findings", []):
        if not isinstance(finding, dict):
            continue
        category = str(finding.get("category", "FIREWALL_POLICY")).upper()
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in SEVERITY_ORDER:
            severity = "INFO"
        title = str(finding.get("title", "Policy Finding"))
        vdom = str(finding.get("vdom") or "root")
        policy_id = str(finding.get("policy_id")) if finding.get("policy_id") is not None else None
        object_name = str(finding.get("policy_name") or finding.get("object_name") or "-")

        dedup_key = f"POLICY|{category}|{severity}|{title}|{vdom}|{policy_id}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        evidence: list[str] = []
        if finding.get("reasons"):
            evidence.extend(str(r) for r in finding["reasons"])
        if finding.get("evidence"):
            evidence.extend(str(e) for e in finding["evidence"])
        cleaned_evidence = [_clean_string(e) for e in evidence if e.strip()]

        unified.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": str(finding.get("description", "")),
            "recommendation": str(finding.get("recommendation", "")),
            "vdom": vdom,
            "policy_id": policy_id,
            "object_name": object_name if object_name != "-" else None,
            "evidence": cleaned_evidence,
        })

    def _sort_key(item: dict[str, Any]) -> tuple[int, str, str, str]:
        sev_rank = SEVERITY_ORDER.index(item["severity"]) if item["severity"] in SEVERITY_ORDER else 99
        return (sev_rank, item["title"], item["vdom"], str(item.get("policy_id") or ""))

    unified.sort(key=_sort_key)
    return unified


def _clean_string(text: str) -> str:
    """Sanitize string values using fallback secret patterns."""
    res = text
    for pat in FALLBACK_SECRET_PATTERNS:
        res = pat.sub("[REDACTED]", res)
    return res.strip()


def _sanitize_data_tree(data: Any, path: str = "") -> Any:
    """Recursively enforce that no raw secrets or forbidden keys enter the JSON tree."""
    if isinstance(data, dict):
        cleaned_dict: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).casefold()
            if key_lower in FORBIDDEN_SECRET_KEYS:
                continue
            if key.startswith("_") and key not in {"_configured"}:
                continue
            cleaned_dict[key] = _sanitize_data_tree(value, f"{path}.{key}")
        return cleaned_dict
    elif isinstance(data, list):
        return [_sanitize_data_tree(item, f"{path}[]") for item in data]
    elif isinstance(data, str):
        return _clean_string(data)
    else:
        return data


def project_json_report(
    static_result: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project a static analysis pipeline result into a normalized, public JSON report conforming to Schema 1.0."""
    config = static_result.get("config") or {}
    analysis = static_result.get("analysis") or {}
    health = static_result.get("health") or {}
    meta = dict(static_result.get("metadata") or {})
    if metadata:
        meta.update(metadata)

    # 1. Metadata
    report_metadata: dict[str, Any] = {
        "filename": meta.get("filename") or "Uploaded configuration",
        "analyzer_version": __version__,
    }
    if meta.get("file_size") is not None:
        report_metadata["file_size"] = meta["file_size"]
    if meta.get("generated_at"):
        report_metadata["generated_at"] = meta["generated_at"]

    # 2. Input Assessment
    input_assessment_raw = config.get("input_assessment") or {}
    fortios_raw = input_assessment_raw.get("fortios") or {}
    fortios_version = fortios_raw.get("version", "unknown") if isinstance(fortios_raw, dict) else str(fortios_raw or "unknown")
    platform = fortios_raw.get("platform") if isinstance(fortios_raw, dict) else input_assessment_raw.get("platform")

    input_assessment_projected = {
        "classification": input_assessment_raw.get("classification", "UNKNOWN"),
        "fortigate_detected": bool(input_assessment_raw.get("fortigate_detected", False)),
        "fortios": {
            "detected": bool(fortios_raw.get("detected", False) if isinstance(fortios_raw, dict) else False),
            "version": fortios_version,
            "platform": platform,
        },
        "recognized_sections": list(input_assessment_raw.get("recognized_sections", [])),
        "structural_warnings": list(input_assessment_raw.get("structural_warnings", [])),
        "analysis_scope": input_assessment_raw.get("analysis_scope", {}),
        "explanation": list(input_assessment_raw.get("explanation", [])),
    }

    # 3. Policies Projection
    raw_policies = config.get("policies", [])
    if not isinstance(raw_policies, list):
        raw_policies = []

    assessments_by_id: dict[str, dict[str, Any]] = {}
    for a in analysis.get("policy_assessments", []):
        if isinstance(a, dict):
            pid = str(a.get("policy_id"))
            vdom = str(a.get("vdom") or "root")
            assessments_by_id[f"{vdom}|{pid}"] = a

    projected_policies: list[dict[str, Any]] = []
    vdoms_set: set[str] = set()

    for idx, p in enumerate(raw_policies, start=1):
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or idx)
        vdom = str(p.get("vdom") or "root")
        vdoms_set.add(vdom)
        family = str(p.get("address_family", "IPv4"))
        status = str(p.get("status", "enable")).casefold()
        action = str(p.get("action", "deny")).casefold()

        src_key = "srcaddr6" if family == "IPv6" else "srcaddr"
        dst_key = "dstaddr6" if family == "IPv6" else "dstaddr"

        assessment = assessments_by_id.get(f"{vdom}|{pid}", {})
        flow_type = assessment.get("flow_type") or "-"
        technical_purpose = assessment.get("purpose") or "-"

        # Security profiles
        profiles: dict[str, str] = {}
        for prof_key in ("ips-sensor", "av-profile", "webfilter-profile", "application-list", "ssl-ssh-profile", "dnsfilter-profile"):
            if p.get(prof_key):
                norm_key = prof_key.replace("-profile", "").replace("-sensor", "").replace("-list", "").replace("-", "_")
                profiles[norm_key] = str(p[prof_key])

        projected_policies.append({
            "sequence_index": idx,
            "policy_id": pid,
            "name": str(p.get("name") or ""),
            "vdom": vdom,
            "address_family": family,
            "status": status,
            "action": action,
            "source_interfaces": _list_strings(p.get("srcintf")),
            "destination_interfaces": _list_strings(p.get("dstintf")),
            "source_selectors": _list_strings(p.get(src_key, p.get("srcaddr"))),
            "destination_selectors": _list_strings(p.get(dst_key, p.get("dstaddr"))),
            "services": _list_strings(p.get("service")),
            "flow_type": flow_type,
            "technical_purpose": technical_purpose,
            "security_profiles": profiles,
            "logging": str(p.get("logtraffic", "-")),
        })

    # 4. Findings
    findings = _collect_unified_findings(analysis, health)

    # 5. Summary metrics
    total_policies = len(projected_policies)
    disabled_policies = sum(1 for p in projected_policies if p["status"] in {"disable", "disabled"})
    enabled_policies = total_policies - disabled_policies

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    unresolved_count = 0
    for check in health.get("checks", []):
        if check.get("title") in {
            "Unresolved Object References in Policy",
            "Referenced Security Profile Could Not Be Resolved",
            "Configuration Integrity Review Required",
        }:
            unresolved_count += len(check.get("evidence", []))

    # IPsec & SSL-VPN summaries
    ipsec_raw = config.get("ipsec_phase1", [])
    ipsec_count = len(ipsec_raw) if isinstance(ipsec_raw, list) else 0

    ssl_vpn_settings = config.get("ssl_vpn_settings", [])
    if isinstance(ssl_vpn_settings, list) and ssl_vpn_settings:
        st_val = str(ssl_vpn_settings[0].get("status", "")).casefold()
        ssl_vpn_status = "ENABLED" if st_val in {"enable", "enabled"} else ("DISABLED" if st_val in {"disable", "disabled"} else "NOT_OBSERVED")
    elif isinstance(ssl_vpn_settings, dict) and ssl_vpn_settings:
        st_val = str(ssl_vpn_settings.get("status", "")).casefold()
        ssl_vpn_status = "ENABLED" if st_val in {"enable", "enabled"} else ("DISABLED" if st_val in {"disable", "disabled"} else "NOT_OBSERVED")
    else:
        ssl_vpn_status = "NOT_OBSERVED"

    summary = {
        "vdom_count": max(len(vdoms_set), 1),
        "vdoms": sorted(list(vdoms_set)) if vdoms_set else ["root"],
        "total_policies": total_policies,
        "enabled_policies": enabled_policies,
        "disabled_policies": disabled_policies,
        "findings_by_severity": severity_counts,
        "total_findings": len(findings),
        "unresolved_references_count": unresolved_count,
        "ipsec_tunnels_count": ipsec_count,
        "ssl_vpn_status": ssl_vpn_status,
    }

    # 6. VPN (IPsec)
    projected_ipsec: list[dict[str, Any]] = []
    if isinstance(ipsec_raw, list):
        for item in ipsec_raw:
            if not isinstance(item, dict):
                continue
            projected_ipsec.append({
                "name": str(item.get("name") or ""),
                "interface": str(item.get("interface") or "-"),
                "remote_gw": str(item.get("remote-gw") or "-"),
                "proposal": str(item.get("proposal") or "-"),
                "dhgrp": str(item.get("dhgrp") or "-"),
                "ike_version": str(item.get("ike-version") or "1"),
                "vdom": str(item.get("vdom") or "root"),
            })

    # 7. SSL-VPN
    ssl_settings_first = ssl_vpn_settings[0] if isinstance(ssl_vpn_settings, list) and ssl_vpn_settings else (ssl_vpn_settings if isinstance(ssl_vpn_settings, dict) else {})
    ssl_portals_raw = config.get("ssl_vpn_portals", [])
    projected_portals: list[dict[str, Any]] = []
    if isinstance(ssl_portals_raw, list):
        for portal in ssl_portals_raw:
            if not isinstance(portal, dict):
                continue
            projected_portals.append({
                "name": str(portal.get("name") or ""),
                "tunnel_mode": str(portal.get("tunnel-mode", "")).casefold() == "enable",
                "web_mode": str(portal.get("web-mode", "")).casefold() == "enable",
                "split_tunneling": str(portal.get("split-tunneling") or "-"),
            })

    ports_val: list[int] = []
    if ssl_settings_first.get("port"):
        try:
            ports_val.append(int(ssl_settings_first["port"]))
        except (ValueError, TypeError):
            pass

    projected_ssl = {
        "status": ssl_vpn_status,
        "listening_ports": ports_val,
        "source_interfaces": _list_strings(ssl_settings_first.get("source-interface")),
        "servercert": str(ssl_settings_first.get("servercert") or "-"),
        "portals": projected_portals,
    }

    # 8. Local-In Policies
    projected_local_in: list[dict[str, Any]] = []
    for pol in config.get("local_in_policies", []):
        if not isinstance(pol, dict):
            continue
        intf_vals = _list_strings(pol.get("intf"))
        projected_local_in.append({
            "id": str(pol.get("id") or "-"),
            "interface": ", ".join(intf_vals) if intf_vals else "-",
            "source_selectors": _list_strings(pol.get("srcaddr")),
            "destination_selectors": _list_strings(pol.get("dstaddr")),
            "services": _list_strings(pol.get("service")),
            "action": str(pol.get("action", "deny")).casefold(),
            "vdom": str(pol.get("vdom") or "root"),
        })

    # 9. Interface Policies
    projected_interface_policies: list[dict[str, Any]] = []
    for pol in config.get("interface_policies", []):
        if not isinstance(pol, dict):
            continue
        intf_vals = _list_strings(pol.get("srcintf"))
        projected_interface_policies.append({
            "id": str(pol.get("id") or "-"),
            "interface": ", ".join(intf_vals) if intf_vals else "-",
            "source_selectors": _list_strings(pol.get("srcaddr")),
            "destination_selectors": _list_strings(pol.get("dstaddr")),
            "services": _list_strings(pol.get("service")),
            "action": str(pol.get("action", "accept")).casefold(),
            "vdom": str(pol.get("vdom") or "root"),
        })

    # 10. Documented Defaults
    doc_defaults_raw = (
        analysis.get("documented_defaults")
        or health.get("documented_defaults")
        or []
    )
    projected_defaults: list[dict[str, Any]] = []
    if isinstance(doc_defaults_raw, list):
        for d in doc_defaults_raw:
            if not isinstance(d, dict):
                continue
            projected_defaults.append({
                "section": str(d.get("section") or "-"),
                "field": str(d.get("field") or "-"),
                "effective_value": str(d.get("effective_value") or "-"),
                "source": "DOCUMENTED_DEFAULT",
                "version_branch": str(d.get("fortios_version") or "-"),
                "documentation": str(d.get("documentation") or "-"),
            })

    # 11. Inventory
    inventory = {
        "firewall_policies": len(raw_policies),
        "local_in_policies": len(config.get("local_in_policies", [])) if isinstance(config.get("local_in_policies"), list) else 0,
        "interface_policies": len(config.get("interface_policies", [])) if isinstance(config.get("interface_policies"), list) else 0,
        "interfaces": len(config.get("interfaces", [])) if isinstance(config.get("interfaces"), list) else 0,
        "addresses": len(config.get("addresses", [])) if isinstance(config.get("addresses"), list) else 0,
        "address_groups": len(config.get("address_groups", [])) if isinstance(config.get("address_groups"), list) else 0,
        "services": len(config.get("services", [])) if isinstance(config.get("services"), list) else 0,
        "service_groups": len(config.get("service_groups", [])) if isinstance(config.get("service_groups"), list) else 0,
        "vips": len(config.get("vips", [])) if isinstance(config.get("vips"), list) else 0,
        "ipsec_phase1": ipsec_count,
        "ipsec_phase2": len(config.get("ipsec_phase2", [])) if isinstance(config.get("ipsec_phase2"), list) else 0,
        "administrators": len(config.get("admins", [])) if isinstance(config.get("admins"), list) else 0,
        "user_locals": len(config.get("user_locals", [])) if isinstance(config.get("user_locals"), list) else 0,
        "user_groups": len(config.get("user_groups", [])) if isinstance(config.get("user_groups"), list) else 0,
    }

    # Top-level assembly
    report_data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "metadata": report_metadata,
        "input_assessment": input_assessment_projected,
        "summary": summary,
        "findings": findings,
        "policies": projected_policies,
        "vpn": {
            "ipsec_phase1": projected_ipsec,
        },
        "ssl_vpn": projected_ssl,
        "local_in_policies": projected_local_in,
        "interface_policies": projected_interface_policies,
        "documented_defaults": projected_defaults,
        "inventory": inventory,
        "limitations": METHODOLOGY_LIMITATIONS,
    }

    # Apply recursive sanitization check
    return _sanitize_data_tree(report_data)
