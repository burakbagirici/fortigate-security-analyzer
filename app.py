"""Streamlit interface for the FortiGate Security Analyzer."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re

import streamlit as st

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import parse_configuration
from reporting import generate_static_report
from runtime_health import (
    SUPPORTED_COMMANDS,
    analyze_runtime_health,
    parse_runtime_output,
)


SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")
RELATIONSHIP_TITLES = {
    "Duplicate Firewall Policy",
    "Fully Shadowed Firewall Policy",
    "Conflicting Policy Shadowing",
}
RELATIONSHIP_GROUPS = (
    ("Conflicting Shadowing", "Conflicting Policy Shadowing"),
    ("Full Shadowing", "Fully Shadowed Firewall Policy"),
    ("Duplicates", "Duplicate Firewall Policy"),
)
PROFILE_LABELS = {
    "ips": "IPS",
    "antivirus": "Antivirus",
    "web_filter": "Web Filter",
    "application_control": "Application Control",
    "ssl_inspection": "SSL Inspection",
    "dns_filter": "DNS Filter",
}
INVENTORY_FIELDS = (
    ("Policies", "policies"),
    ("Local-In Policies", "local_in_policies"),
    ("Local-In Policies (IPv6)", "local_in_policies6"),
    ("Interface Policies", "interface_policies"),
    ("Interface Policies (IPv6)", "interface_policies6"),
    ("Interfaces", "interfaces"),
    ("Addresses", "addresses"),
    ("Addresses (IPv6)", "addresses6"),
    ("Address Groups", "address_groups"),
    ("Address Groups (IPv6)", "address_groups6"),
    ("Services", "services"),
    ("Service Groups", "service_groups"),
    ("VIPs", "vips"),
    ("VIPs (IPv6)", "vips6"),
    ("IPsec Phase 1", "ipsec_phase1"),
    ("IPsec Phase 2", "ipsec_phase2"),
    ("DoS Policies", "dos_policies"),
    ("SSL-VPN Settings", "ssl_vpn_settings"),
    ("SSL-VPN Portals", "ssl_vpn_portals"),
    ("User Groups", "user_groups"),
    ("Local Users", "user_locals"),
)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    """Count supported severities without inventing a score."""
    return {
        severity: sum(
            1
            for finding in findings
            if str(finding.get("severity", "")).upper() == severity
        )
        for severity in SEVERITY_ORDER
    }


def _display_value(value: object) -> str:
    """Format scalar and list configuration values for display."""
    if value is None or value == "":
        return "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "-"
    if isinstance(value, set):
        return ", ".join(sorted(str(item) for item in value)) or "-"
    return str(value)


def _format_file_size(size_bytes: int) -> str:
    """Format uploaded byte size for display."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _vdom_key(value: object) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    return str(value).casefold()


def _detected_vdoms(config: dict) -> list[str]:
    """Return distinct named VDOMs found in parsed object collections."""
    names: dict[str, str] = {}
    for value in config.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict) or item.get("vdom") is None:
                continue
            name = str(item["vdom"])
            names.setdefault(name.casefold(), name)
    return sorted(names.values(), key=str.casefold)


def _filter_vdom_items(items: object, selected_vdom: str) -> list[dict]:
    """Filter VDOM-scoped objects; ``All`` retains every scope."""
    if not isinstance(items, list):
        return []
    dictionaries = [item for item in items if isinstance(item, dict)]
    if selected_vdom == "All":
        return dictionaries
    selected_key = _vdom_key(selected_vdom)
    return [
        item
        for item in dictionaries
        if _vdom_key(item.get("vdom")) == selected_key
    ]


def _health_check_vdoms(check: dict) -> set[str]:
    """Extract explicit VDOM context from structured fields or evidence."""
    vdoms: set[str] = set()
    if check.get("vdom") is not None:
        vdoms.add(str(check["vdom"]))
    for evidence in check.get("evidence", []):
        vdoms.update(_evidence_vdoms(evidence))
    return vdoms


def _evidence_vdoms(evidence: object) -> set[str]:
    """Extract named VDOMs from one health-check evidence item."""
    vdoms: set[str] = set()
    for match in re.findall(
        r"VDOM:\s*([^;,)]+)", str(evidence), flags=re.IGNORECASE
    ):
        name = match.strip()
        if name and name.casefold() != "global":
            vdoms.add(name)
    return vdoms


def _filter_health_checks(checks: object, selected_vdom: str) -> list[dict]:
    """Keep global checks plus checks associated with the selected VDOM."""
    if not isinstance(checks, list):
        return []
    valid_checks = [check for check in checks if isinstance(check, dict)]
    if selected_vdom == "All":
        return valid_checks
    selected_key = _vdom_key(selected_vdom)
    filtered: list[dict] = []
    for check in valid_checks:
        check_vdoms = _health_check_vdoms(check)
        if check_vdoms and selected_key not in {
            _vdom_key(vdom) for vdom in check_vdoms
        }:
            continue
        scoped_check = dict(check)
        scoped_check["evidence"] = [
            evidence
            for evidence in check.get("evidence", [])
            if not _evidence_vdoms(evidence)
            or selected_key
            in {_vdom_key(vdom) for vdom in _evidence_vdoms(evidence)}
        ]
        filtered.append(scoped_check)
    return filtered


def _policy_key(item: dict) -> tuple[str | None, object]:
    return _vdom_key(item.get("vdom")), item.get("policy_id", item.get("id"))


def _policy_inventory_rows(policies: list[dict]) -> list[dict]:
    """Build the factual policy inventory displayed by Streamlit."""
    rows = []
    for policy in policies:
        family = policy.get("address_family", "IPv4")
        if family == "IPv6":
            src = policy.get("srcaddr6") or policy.get("srcaddr")
            dst = policy.get("dstaddr6") or policy.get("dstaddr")
        else:
            src = policy.get("srcaddr")
            dst = policy.get("dstaddr")
        rows.append(
            {
                "VDOM": _display_value(policy.get("vdom")),
                "Sequence": _display_value(policy.get("sequence_index")),
                "ID": _display_value(policy.get("id")),
                "Name": _display_value(policy.get("name")),
                "Address Family": family,
                "Source Interface": _display_value(policy.get("srcintf")),
                "Destination Interface": _display_value(policy.get("dstintf")),
                "Source Address": _display_value(src),
                "Destination Address": _display_value(dst),
                "Service": _display_value(policy.get("service")),
                "Action": _display_value(policy.get("action")),
                "Status": _display_value(policy.get("status")),
                "Schedule": _display_value(policy.get("schedule")),
                "Logging": _display_value(policy.get("logtraffic")),
                "UTM Status": _display_value(policy.get("utm-status")),
                "IPS Sensor": _display_value(policy.get("ips-sensor")),
                "Antivirus Profile": _display_value(policy.get("av-profile")),
                "Web Filter": _display_value(policy.get("webfilter-profile")),
                "Application Control": _display_value(policy.get("application-list")),
                "SSL/SSH Profile": _display_value(policy.get("ssl-ssh-profile")),
                "Inspection Mode": _display_value(policy.get("inspection-mode")),
                "Log Traffic Start": _display_value(policy.get("logtraffic-start")),
                "Packet Capture": _display_value(policy.get("capture-packet")),
                "ASIC Offload": _display_value(policy.get("auto-asic-offload")),
            }
        )
    return rows


def _run_analysis_pipeline(config_text: str) -> dict:
    """Parse once, analyze once, and reuse that analysis for health checks."""
    config = parse_configuration(config_text)
    analysis_result = analyze_configuration(config)
    health_result = run_health_check(config, analysis_result=analysis_result)
    documented_defaults = analysis_result.get("documented_defaults", [])
    if "input_assessment" in config and isinstance(config["input_assessment"], dict):
        config["input_assessment"]["documented_defaults"] = documented_defaults
    return {
        "config": config,
        "analysis_result": analysis_result,
        "health_result": health_result,
        "documented_defaults": documented_defaults,
    }


def _run_runtime_pipeline(runtime_text: str) -> dict:
    """Parse runtime CLI output text and run runtime health checks."""
    runtime_data = parse_runtime_output(runtime_text)
    runtime_result = analyze_runtime_health(runtime_data)
    return {
        "runtime_data": runtime_data,
        "runtime_result": runtime_result,
    }


def _render_severity_metrics(findings: list[dict], include_info: bool) -> None:
    counts = _severity_counts(findings)
    severities = SEVERITY_ORDER if include_info else SEVERITY_ORDER[:3]
    columns = st.columns(len(severities) + 1)
    columns[0].metric("Total", len(findings))
    for column, severity in zip(columns[1:], severities):
        column.metric(severity, counts[severity])


def _render_inventory_metrics(config: dict, selected_vdom: str) -> None:
    st.subheader("Configuration Inventory")
    chunk_size = 5
    for i in range(0, len(INVENTORY_FIELDS), chunk_size):
        chunk = INVENTORY_FIELDS[i : i + chunk_size]
        cols = st.columns(len(chunk))
        for col, (label, config_key) in zip(cols, chunk):
            objects = _filter_vdom_items(config.get(config_key, []), selected_vdom)
            col.metric(label, len(objects))


def _render_important_item(source: str, item: dict) -> None:
    severity = str(item.get("severity", "INFO")).upper()
    title = item.get("title") or "Untitled finding"
    vdom = item.get("vdom")
    context = f" · VDOM {vdom}" if vdom is not None else ""
    text = f"{source} · {severity} · {title}{context}"
    if severity == "HIGH":
        st.error(text)
    else:
        st.warning(text)


def _render_input_quality_summary(input_assessment: dict) -> None:
    """Render structured FortiGate input classification and metadata summary."""
    if not isinstance(input_assessment, dict) or not input_assessment:
        return

    st.subheader("Input Quality & Configuration Scope")

    classification = input_assessment.get("classification", "UNKNOWN")
    fortios = input_assessment.get("fortios", {})
    version_str = fortios.get("version", "unknown")
    build = fortios.get("build")
    platform = fortios.get("platform")

    version_label = version_str
    if build:
        version_label += f" (Build {build})"
    if platform:
        version_label = f"{platform} · FortiOS {version_label}"
    elif version_str != "unknown":
        version_label = f"FortiOS {version_label}"

    col1, col2, col3 = st.columns(3)
    col1.metric("Input Classification", classification.replace("_", " "))
    col2.metric(
        "FortiOS Version",
        version_label if version_str != "unknown" else "Unknown / Header Absent",
    )
    col3.metric(
        "Recognized Sections",
        len(input_assessment.get("recognized_sections", [])),
    )

    explanations = input_assessment.get("explanation", [])
    if explanations:
        st.info(" · ".join(explanations))

    warnings = input_assessment.get("structural_warnings", [])
    if warnings:
        with st.expander("Structural Warnings", expanded=False):
            for warning in warnings:
                st.caption(f"⚠️ {warning}")

    scope = input_assessment.get("analysis_scope", {})
    unsupplied = [
        domain
        for domain, info in scope.items()
        if info.get("status") == "UNAVAILABLE_NOT_SUPPLIED"
    ]
    if unsupplied:
        with st.expander("Analysis Scope Limitations", expanded=False):
            for domain in unsupplied:
                evidence = scope[domain].get("evidence", "")
                st.caption(f"ℹ️ **{domain.replace('_', ' ').title()}**: {evidence}")

    documented_defaults = input_assessment.get("documented_defaults") or []
    if documented_defaults:
        with st.expander(f"Documented FortiOS Defaults ({len(documented_defaults)})", expanded=False):
            for default in documented_defaults:
                st.caption(
                    f"ℹ️ **{default.get('section', '')}.{default.get('field', '')}**: `{default.get('effective_value', '')}` "
                    f"(FortiOS {default.get('fortios_version', '')} default) — {default.get('documentation', '')}"
                )


def display_overview(
    config: dict,
    policy_findings: list[dict],
    health_checks: list[dict],
    filename: str,
    file_size: int,
    vdoms: list[str],
    selected_vdom: str,
) -> None:
    """Render inventory and factual finding summaries."""
    input_assessment = config.get("input_assessment", {})
    _render_input_quality_summary(input_assessment)
    _render_inventory_metrics(config, selected_vdom)

    st.subheader("Findings Summary")
    policy_column, health_column = st.columns(2)
    with policy_column:
        st.markdown("**Policy Findings**")
        _render_severity_metrics(policy_findings, include_info=False)
    with health_column:
        st.markdown("**Health Check Results**")
        _render_severity_metrics(health_checks, include_info=True)

    st.subheader("Important Findings")
    important = [
        ("Policy Analysis", finding)
        for finding in policy_findings
        if str(finding.get("severity", "")).upper() in {"HIGH", "MEDIUM"}
    ] + [
        ("Health Check", check)
        for check in health_checks
        if str(check.get("severity", "")).upper() in {"HIGH", "MEDIUM"}
    ]
    important.sort(
        key=lambda item: (
            SEVERITY_ORDER.index(str(item[1].get("severity", "INFO")).upper())
            if str(item[1].get("severity", "INFO")).upper() in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            str(item[1].get("title", "")),
        )
    )
    if important:
        for source, item in important[:8]:
            _render_important_item(source, item)
        if len(important) > 8:
            st.caption(
                f"{len(important) - 8} additional HIGH/MEDIUM item(s) are "
                "shown in the detailed tabs."
            )
    else:
        st.success(
            "No HIGH or MEDIUM items were produced by the supported analysis model."
        )

    st.subheader("Configuration Summary")
    summary_columns = st.columns(5)
    summary_columns[0].caption("Uploaded filename")
    summary_columns[0].write(filename)
    summary_columns[1].caption("File size")
    summary_columns[1].write(_format_file_size(file_size))
    summary_columns[2].caption("VDOMs detected")
    summary_columns[2].write(", ".join(vdoms) if vdoms else "None")
    summary_columns[3].caption("Policies parsed")
    summary_columns[3].write(str(len(config.get("policies", []))))
    categories = sorted(
        {str(check.get("category")) for check in health_checks if check.get("category")}
    )
    summary_columns[4].caption("Health categories")
    summary_columns[4].write(", ".join(categories) if categories else "None")


def _resolved_object_lines(items: object, depth: int = 0) -> list[str]:
    """Create readable lines from analyzer-resolved objects."""
    if not isinstance(items, list):
        return []
    lines: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "Unnamed")
        object_type = str(item.get("type") or "object").replace("_", " ")
        details: list[str] = []
        for key, label in (
            ("subnet", "subnet"),
            ("start_ip", "start IP"),
            ("end_ip", "end IP"),
            ("fqdn", "FQDN"),
            ("value", "value"),
            ("definition", "definition"),
            ("protocol", "protocol"),
            ("tcp_ports", "TCP ports"),
            ("udp_ports", "UDP ports"),
            ("external_ip", "external IP"),
            ("mapped_ip", "mapped IP"),
            ("external_port", "external port"),
            ("mapped_port", "mapped port"),
        ):
            if item.get(key) not in (None, "", []):
                details.append(f"{label}: {_display_value(item.get(key))}")
        suffix = f" — {'; '.join(details)}" if details else ""
        lines.append(f"{'  ' * depth}{name} ({object_type}){suffix}")
        lines.extend(_resolved_object_lines(item.get("members"), depth + 1))
    return lines


def _render_resolved_objects(title: str, items: object) -> None:
    st.markdown(f"**{title}**")
    lines = _resolved_object_lines(items)
    if not lines:
        st.caption("No objects were available for this field.")
        return
    for line in lines:
        st.markdown(f"- {line}")


def _render_security_profiles(profiles: object) -> None:
    st.markdown("**Security Profiles**")
    if not isinstance(profiles, dict):
        st.caption("No structured security-profile inventory is available.")
        return
    for profile_type, label in PROFILE_LABELS.items():
        profile = profiles.get(profile_type, {})
        if not profile.get("attached"):
            st.write(f"- {label}: Not attached")
            continue
        resolution = "Resolved" if profile.get("resolved") else "Unresolved"
        source = profile.get("source")
        source_label = str(source).title() if source else "Unknown source"
        st.write(
            f"- {label}: {profile.get('name') or '-'} — "
            f"{resolution} — {source_label}"
        )


def _render_policy_finding(finding: dict) -> None:
    severity = str(finding.get("severity", "INFO")).upper()
    st.markdown(f"**{severity} — {finding.get('title') or 'Untitled finding'}**")
    st.write(finding.get("description") or "No description provided.")
    st.caption(
        "Recommendation: "
        + str(finding.get("recommendation") or "Review with the policy owner.")
    )


def display_policy_analysis(
    policies: list[dict], assessments: list[dict], findings: list[dict]
) -> None:
    """Render analyzer assessments without adding UI conclusions."""
    st.subheader("Policy Analysis")
    if not policies:
        st.info("No firewall policies are available for the selected scope.")
        return

    policy_by_key = {_policy_key(policy): policy for policy in policies}
    assessment_by_key = {_policy_key(item): item for item in assessments}
    for key, policy in policy_by_key.items():
        assessment = assessment_by_key.get(key, {})
        policy_id = _display_value(policy.get("id"))
        policy_name = _display_value(policy.get("name"))
        vdom = policy.get("vdom")
        header = f"Policy #{policy_id} — {policy_name}"
        if vdom is not None:
            header += f" · VDOM {vdom}"

        with st.expander(header):
            columns = st.columns(4)
            details = (
                ("Policy ID", policy.get("id")),
                ("Policy Name", policy.get("name")),
                ("VDOM", vdom),
                ("Sequence", policy.get("sequence_index")),
                ("Inferred Purpose", assessment.get("purpose")),
                ("Purpose Confidence", assessment.get("purpose_confidence")),
                ("Traffic Direction", assessment.get("traffic_direction")),
                ("Flow Type", assessment.get("flow_type")),
                ("Action", policy.get("action")),
                ("Status", policy.get("status") or "enable"),
            )
            for index, (label, value) in enumerate(details):
                columns[index % 4].caption(label)
                columns[index % 4].write(_display_value(value))

            st.markdown("**Assessment**")
            st.write(
                assessment.get("assessment")
                or "No human-readable assessment is available."
            )
            _render_resolved_objects(
                "Resolved Sources", assessment.get("resolved_sources")
            )
            _render_resolved_objects(
                "Resolved Destinations", assessment.get("resolved_destinations")
            )
            _render_resolved_objects(
                "Resolved Services", assessment.get("resolved_services")
            )
            _render_security_profiles(assessment.get("security_profiles"))

            st.markdown("**Operational Settings**")
            operational_settings = assessment.get("operational_settings", {})
            if isinstance(operational_settings, dict) and any(
                value is not None for value in operational_settings.values()
            ):
                for setting, value in operational_settings.items():
                    st.write(f"- {setting}: {_display_value(value)}")
            else:
                st.caption("No supported operational fields were configured.")

            st.markdown("**Security Observations**")
            observations = assessment.get("security_observations", [])
            if observations:
                for observation in observations:
                    st.write(f"- {observation}")
            else:
                st.caption("No neutral security observations were generated.")

            st.markdown("**Findings for This Policy**")
            policy_findings = [
                finding for finding in findings if _policy_key(finding) == key
            ]
            if policy_findings:
                for finding in policy_findings:
                    _render_policy_finding(finding)
            else:
                st.caption("No analyzer findings are associated with this policy.")


def _interface_policy_key(item: dict) -> tuple[str | None, object, str | None]:
    return (
        _vdom_key(item.get("vdom")),
        item.get("policy_id", item.get("id")),
        item.get("address_family", "IPv4"),
    )


def display_interface_policies(
    interface_policies: list[dict], assessments: list[dict]
) -> None:
    """Render interface policy inspection assessments without adding UI conclusions."""
    st.subheader("Interface Policies")
    if not interface_policies:
        st.info("No interface policies are available for the selected scope.")
        return

    policy_by_key = {_interface_policy_key(policy): policy for policy in interface_policies}
    assessment_by_key = {_interface_policy_key(item): item for item in assessments}
    for key, policy in policy_by_key.items():
        assessment = assessment_by_key.get(key, {})
        policy_id = _display_value(policy.get("id"))
        interface_name = _display_value(policy.get("interface"))
        vdom = policy.get("vdom")
        family = policy.get("address_family", "IPv4")
        family_tag = f" [{family}]" if family == "IPv6" else ""
        header = f"Interface Policy #{policy_id}{family_tag} — {interface_name}"
        if vdom is not None:
            header += f" · VDOM {vdom}"

        with st.expander(header):
            columns = st.columns(4)
            intf_ctx = assessment.get("interface_context", {})
            effective_context = (
                intf_ctx.get("role", "UNKNOWN")
                if isinstance(intf_ctx, dict)
                else "UNKNOWN"
            )
            details = (
                ("Policy ID", policy.get("id")),
                ("Address Family", family),
                ("Interface", policy.get("interface")),
                ("Interface Context", effective_context),
                ("VDOM", vdom),
                ("Sequence", policy.get("sequence_index")),
                ("Purpose", assessment.get("purpose")),
                ("Status", policy.get("status") or "enable"),
                ("Log Traffic", _display_value(policy.get("logtraffic"))),
                ("DSRI", _display_value(policy.get("dsri"))),
                ("Comments", _display_value(policy.get("comments"))),
            )
            for index, (label, value) in enumerate(details):
                columns[index % 4].caption(label)
                columns[index % 4].write(_display_value(value))

            _render_resolved_objects(
                "Resolved Sources", assessment.get("resolved_sources")
            )
            _render_resolved_objects(
                "Resolved Destinations", assessment.get("resolved_destinations")
            )
            _render_resolved_objects(
                "Resolved Services", assessment.get("resolved_services")
            )

            st.markdown("**Inspection Profiles**")
            inspection_profiles = assessment.get("inspection_profiles", {})
            if isinstance(inspection_profiles, dict) and inspection_profiles:
                for profile_type, pinfo in inspection_profiles.items():
                    label = pinfo.get("label", profile_type)
                    ref = pinfo.get("configured_reference")
                    if not ref:
                        st.write(f"- {label}: Not configured")
                        continue
                    activation = pinfo.get("activation_status", "UNKNOWN")
                    active_label = (
                        "Active"
                        if pinfo.get("active") is True
                        else (
                            "Inactive"
                            if pinfo.get("active") is False
                            else "Unknown"
                        )
                    )
                    res = "Resolved" if pinfo.get("resolved") else "Unresolved"
                    source = pinfo.get("source")
                    source_label = f" ({source})" if source else ""
                    st.write(
                        f"- {label}: `{ref}` — {activation} [{active_label}] — {res}{source_label}"
                    )
            else:
                st.caption("No inspection profile details available.")

            st.markdown("**Security Observations**")
            observations = assessment.get("security_observations", [])
            if observations:
                for obs in observations:
                    st.write(f"- {obs}")
            else:
                st.caption("No neutral security observations were generated.")


def display_ssl_vpn(ssl_vpn_assessments: list[dict]) -> None:
    """Render SSL-VPN static configuration assessments neutrally."""
    st.subheader("SSL-VPN Configuration")
    if not ssl_vpn_assessments:
        st.info("No SSL-VPN configuration was observed for the selected scope.")
        return

    for assessment in ssl_vpn_assessments:
        vdom = assessment.get("vdom")
        header = f"SSL-VPN Configuration · VDOM {vdom}" if vdom is not None else "SSL-VPN Configuration"
        with st.expander(header, expanded=True):
            cols = st.columns(4)
            details = (
                ("Status", assessment.get("status")),
                ("Listening Port", _display_value(assessment.get("port") or "443 (default)")),
                ("Server Certificate", _display_value(assessment.get("servercert"))),
                ("Minimum TLS", _display_value(assessment.get("ssl_min_proto_ver"))),
                ("DTLS Tunnel", _display_value(assessment.get("dtls_tunnel"))),
                ("Default Portal", _display_value(assessment.get("default_portal"))),
                ("Banned Cipher", _display_value(assessment.get("banned_cipher"))),
                ("Ciphersuite / Algorithm", _display_value(assessment.get("ciphersuite"))),
            )
            for index, (label, val) in enumerate(details):
                cols[index % 4].caption(label)
                cols[index % 4].write(_display_value(val))

            # Listening interfaces
            st.markdown("**Listening Interfaces & Contexts**")
            intf_contexts = assessment.get("interface_contexts", [])
            if intf_contexts:
                for intf in intf_contexts:
                    iname = intf.get("name", "Unknown")
                    role = intf.get("role", "UNKNOWN")
                    res = "Resolved" if intf.get("resolved") else "Unresolved"
                    st.write(f"- `{iname}` — Role: **{role}** ({res})")
            else:
                st.caption("No listening interfaces configured.")

            # Source addresses
            _render_resolved_objects("Restricted Source Addresses", assessment.get("resolved_sources"))

            # Portals
            st.markdown("**SSL-VPN Portals**")
            portals = assessment.get("portals", [])
            if portals:
                for p in portals:
                    pname = p.get("name", "Unnamed")
                    mode = p.get("mode_summary", "UNKNOWN")
                    split = p.get("split_tunneling", "NOT_OBSERVED")
                    st.write(f"- Portal **{pname}** — Mode: `{mode}`, Split-Tunneling: `{split}`")
                    if p.get("split_routing_addresses"):
                        st.caption(f"  Split-routing routes: {', '.join(p.get('split_routing_addresses'))}")
                    if p.get("ip_pools"):
                        st.caption(f"  IP pools: {', '.join(p.get('ip_pools'))}")
            else:
                st.caption("No portals configured in this scope.")

            # Authentication rules
            st.markdown("**Authentication Rules**")
            rules = assessment.get("authentication_rules", [])
            if rules:
                for r in rules:
                    rid = r.get("rule_id", "Unknown")
                    p_res = r.get("portal_resolution", {})
                    p_target = p_res.get("name") or "None"
                    p_src = f" ({p_res.get('source')})" if p_res.get("source") else (" [Unresolved]" if not p_res.get("resolved") else "")
                    groups_str = ", ".join(r.get("groups", [])) or "None"
                    users_str = ", ".join(r.get("users", [])) or "None"
                    st.write(f"- Rule #{rid}: Portal -> `{p_target}`{p_src}, Groups: `{groups_str}`, Users: `{users_str}`")
                    if r.get("interfaces"):
                        st.caption(f"  Interfaces: {', '.join(i.get('name', '') for i in r.get('interfaces'))}")
                    if r.get("resolved_addresses"):
                        st.caption(f"  Source addresses: {', '.join(a.get('name', '') for a in r.get('resolved_addresses'))}")
            else:
                st.caption("No authentication rules configured.")

            # Observations
            st.markdown("**Security Observations**")
            observations = assessment.get("security_observations", [])
            if observations:
                for obs in observations:
                    st.write(f"- {obs}")
            else:
                st.caption("No neutral security observations were generated.")


def display_health_check(checks: list[dict]) -> None:
    """Render existing health-check results by category and severity."""
    st.subheader("Configuration Health Check")
    if not checks:
        st.success("No health-check results were produced for the selected scope.")
        return

    categories: dict[str, list[dict]] = {}
    for check in checks:
        categories.setdefault(str(check.get("category") or "Other"), []).append(check)

    for category, category_checks in categories.items():
        with st.expander(f"{category} ({len(category_checks)})", expanded=True):
            category_checks.sort(
                key=lambda item: (
                    SEVERITY_ORDER.index(str(item.get("severity", "INFO")).upper())
                    if str(item.get("severity", "INFO")).upper() in SEVERITY_ORDER
                    else len(SEVERITY_ORDER),
                    str(item.get("title", "")),
                )
            )
            for index, check in enumerate(category_checks):
                if index:
                    st.divider()
                severity = str(check.get("severity", "INFO")).upper()
                st.markdown(
                    f"**{severity} — {check.get('title') or 'Untitled result'}**"
                )
                check_vdoms = sorted(_health_check_vdoms(check), key=str.casefold)
                if check_vdoms:
                    st.caption("VDOM: " + ", ".join(check_vdoms))
                st.markdown("**Description**")
                st.write(check.get("description") or "No description provided.")
                st.markdown("**Recommendation**")
                st.write(check.get("recommendation") or "Review this result.")
                st.markdown("**Evidence**")
                evidence = check.get("evidence", [])
                if evidence:
                    for item in evidence:
                        st.write(f"- {item}")
                else:
                    st.caption("No evidence details were supplied.")


def display_policy_relationships(findings: list[dict]) -> None:
    """Render duplicate and shadowing findings already produced by analyzer."""
    st.subheader("Policy Relationships")
    relationships = [
        finding
        for finding in findings
        if finding.get("title") in RELATIONSHIP_TITLES
    ]
    if not relationships:
        st.success(
            "No duplicate or fully-shadowed policy relationships were detected "
            "by the supported analysis model."
        )
        return

    for heading, relationship_title in RELATIONSHIP_GROUPS:
        group = [
            finding
            for finding in relationships
            if finding.get("title") == relationship_title
        ]
        if not group:
            continue
        st.markdown(f"### {heading}")
        for finding in group:
            severity = str(finding.get("severity", "INFO")).upper()
            later_id = _display_value(finding.get("policy_id"))
            later_name = _display_value(finding.get("policy_name"))
            with st.expander(f"{severity} — Policy #{later_id} — {later_name}"):
                columns = st.columns(3)
                relationship_details = (
                    ("Severity", severity),
                    ("VDOM", finding.get("vdom")),
                    ("Later Policy", f"#{later_id} — {later_name}"),
                    (
                        "Earlier Policy",
                        f"#{_display_value(finding.get('shadowed_by_policy_id'))} — "
                        f"{_display_value(finding.get('shadowed_by_policy_name'))}",
                    ),
                    ("Earlier Sequence", finding.get("earlier_sequence")),
                    ("Later Sequence", finding.get("later_sequence")),
                )
                for index, (label, value) in enumerate(relationship_details):
                    columns[index % 3].caption(label)
                    columns[index % 3].write(_display_value(value))
                st.markdown("**Description**")
                st.write(finding.get("description") or "No description provided.")
                st.markdown("**Recommendation**")
                st.write(finding.get("recommendation") or "Review policy order.")


def display_policy_inventory(policies: list[dict]) -> None:
    """Display parsed policy fields without assigning additional risk."""
    st.subheader("Policy Inventory")
    rows = _policy_inventory_rows(policies)
    if not rows:
        st.info("No firewall policies are available for the selected scope.")
        return
    st.dataframe(rows, width="stretch", hide_index=True)


def display_about_analysis() -> None:
    """Explain current static-analysis capabilities and boundaries."""
    supported, unsupported = st.columns(2)
    with supported:
        st.subheader("Supported static analysis")
        st.markdown(
            "- Firewall policy analysis\n"
            "- Policy purpose inference\n"
            "- Object resolution\n"
            "- Duplicate policy detection\n"
            "- Policy shadowing\n"
            "- Security profile resolution\n"
            "- Configuration health checks\n"
            "- Static IPsec VPN configuration analysis\n"
            "- System hardening review\n"
            "- DNS/NTP configuration review\n"
            "- Multi-VDOM parsing"
        )
    with unsupported:
        st.subheader("Not analyzed")
        st.markdown(
            "- Live FortiGate state\n"
            "- Tunnel UP/DOWN status\n"
            "- CPU, RAM, or disk runtime state\n"
            "- FortiGuard live connectivity\n"
            "- Traffic history and policy hit counts\n"
            "- Live routing table or HA state\n"
            "- CVE or firmware vulnerability lookup\n"
            "- FortiAnalyzer runtime data"
        )
    st.info(
        "This tool performs static configuration analysis. A finding does not "
        "automatically mean that a configuration is incorrect. Business "
        "requirements and live device context should also be considered."
    )


def display_results(payload: dict, filename: str, file_size: int) -> None:
    """Render all tabs from one cached backend pipeline result."""
    config = payload["config"]
    analysis_result = payload["analysis_result"]
    health_result = payload["health_result"]
    vdoms = _detected_vdoms(config)

    col_vdom, col_report = st.columns([3, 1])
    selected_vdom = "All"
    with col_vdom:
        if len(vdoms) > 1:
            selected_vdom = st.selectbox("VDOM", ["All", *vdoms])
        elif len(vdoms) == 1:
            st.caption(f"VDOM detected: {vdoms[0]}")
    with col_report:
        if "html_report" not in payload:
            payload["html_report"] = generate_static_report(
                config=config,
                analysis_result=analysis_result,
                health_result=health_result,
                metadata={
                    "filename": filename,
                    "file_size": file_size,
                    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                },
            )
        clean_stem = re.sub(r"[^\w\-.]", "_", filename).rsplit(".", 1)[0]
        st.download_button(
            label="Download HTML Report",
            data=payload["html_report"],
            file_name=f"{clean_stem}_analysis_report.html",
            mime="text/html",
            key="btn_download_html_report",
            help="Download self-contained static analysis HTML report suitable for printing or archiving.",
        )

    policies = _filter_vdom_items(config.get("policies", []), selected_vdom)
    assessments = _filter_vdom_items(
        analysis_result.get("policy_assessments", []), selected_vdom
    )
    interface_policies = _filter_vdom_items(
        config.get("interface_policies", []) + config.get("interface_policies6", []),
        selected_vdom,
    )
    interface_assessments = _filter_vdom_items(
        analysis_result.get("interface_policy_assessments", [])
        + analysis_result.get("interface_policy6_assessments", []),
        selected_vdom,
    )
    ssl_vpn_assessments = _filter_vdom_items(
        analysis_result.get("ssl_vpn_assessments", []), selected_vdom
    )
    policy_findings = _filter_vdom_items(
        analysis_result.get("findings", []), selected_vdom
    )
    health_checks = _filter_health_checks(
        health_result.get("checks", []), selected_vdom
    )

    tabs = st.tabs(
        [
            "Overview",
            "Policy Analysis",
            "Interface Policies",
            "SSL-VPN",
            "Health Check",
            "Policy Relationships",
            "Policy Inventory",
            "About",
        ]
    )
    with tabs[0]:
        display_overview(
            config,
            policy_findings,
            health_checks,
            filename,
            file_size,
            vdoms,
            selected_vdom,
        )
    with tabs[1]:
        display_policy_analysis(policies, assessments, policy_findings)
    with tabs[2]:
        display_interface_policies(interface_policies, interface_assessments)
    with tabs[3]:
        display_ssl_vpn(ssl_vpn_assessments)
    with tabs[4]:
        display_health_check(health_checks)
    with tabs[5]:
        display_policy_relationships(policy_findings)
    with tabs[6]:
        display_policy_inventory(policies)
    with tabs[7]:
        display_about_analysis()


RUNTIME_COMMAND_BUNDLE_TEMPLATE = """=== COMMAND: get system status ===
PASTE OUTPUT HERE

=== COMMAND: get sys fortiguard-service status ===
PASTE OUTPUT HERE

=== COMMAND: diagnose autoupdate status ===
PASTE OUTPUT HERE

=== COMMAND: diagnose autoupdate versions ===
PASTE OUTPUT HERE

=== COMMAND: get sys ha status ===
PASTE OUTPUT HERE

=== COMMAND: diagnose sys ntp status ===
PASTE OUTPUT HERE

=== COMMAND: exec sensor list ===
PASTE OUTPUT HERE

=== COMMAND: exec sensor detail ===
PASTE OUTPUT HERE

=== COMMAND: diag hardware deviceinfo psu ===
PASTE OUTPUT HERE

=== COMMAND: diag hardware deviceinfo rps ===
PASTE OUTPUT HERE

=== COMMAND: diag debug crashlog read ===
PASTE OUTPUT HERE

=== COMMAND: diag debug config-error-log read ===
PASTE OUTPUT HERE

=== COMMAND: get router info routing-table all ===
PASTE OUTPUT HERE"""

RUNTIME_RAW_COMMANDS = """get system status
get sys fortiguard-service status
diagnose autoupdate status
diagnose autoupdate versions
get sys ha status
diagnose sys ntp status
exec sensor list
exec sensor detail
diag hardware deviceinfo psu
diag hardware deviceinfo rps
diag debug crashlog read
diag debug config-error-log read
get router info routing-table all"""


def display_runtime_empty_state() -> None:
    """Explain the workflow and show the diagnostic command bundle before analysis begins."""
    st.info("Start with FortiGate CLI diagnostic command outputs.")
    st.markdown(
        "1. Copy the diagnostic command bundle below.\n"
        "2. Run the commands on the FortiGate CLI.\n"
        "3. Put each command output under its corresponding `=== COMMAND: ... ===` marker.\n"
        "4. Upload the resulting `.txt` file.\n"
        "5. Click **Analyze Runtime Health** to run the checks."
    )

    with st.expander("Diagnostic Command Bundle (Template & Command List)", expanded=True):
        st.markdown("**Organized Template** (paste your FortiGate CLI outputs under each marker):")
        st.code(RUNTIME_COMMAND_BUNDLE_TEMPLATE, language="text")

        st.markdown("**Raw FortiGate CLI Commands** (to execute on the FortiGate):")
        st.code(RUNTIME_RAW_COMMANDS, language="text")

        st.caption(
            "Note: The commands themselves are executed on the FortiGate CLI. "
            "The `=== COMMAND: ... ===` marker lines are only used to organize "
            "the sections in your uploaded text file."
        )


def display_runtime_overview(
    runtime_data: dict,
    runtime_result: dict,
    filename: str,
    file_size: int,
) -> None:
    """Render runtime severity summary counts and session metadata."""
    st.subheader("Runtime Health Overview")
    checks = runtime_result.get("checks", [])
    summary = runtime_result.get("summary", {})
    commands_received = runtime_result.get("commands_received", [])
    unsupported_commands = runtime_result.get("unsupported_commands", [])

    columns = st.columns(5)
    columns[0].metric("Total Findings", summary.get("total", len(checks)))
    columns[1].metric("HIGH", summary.get("high", 0))
    columns[2].metric("MEDIUM", summary.get("medium", 0))
    columns[3].metric("LOW", summary.get("low", 0))
    columns[4].metric("INFO", summary.get("info", 0))

    if not checks:
        st.success(
            "No problems were detected in the supplied output for the supported runtime checks."
        )
    else:
        st.warning("Runtime observations were detected in the supplied CLI output.")

    st.subheader("Session Information")
    info_cols = st.columns(4)
    info_cols[0].caption("Uploaded filename")
    info_cols[0].write(filename)
    info_cols[1].caption("File size")
    info_cols[1].write(_format_file_size(file_size))
    info_cols[2].caption("Commands received")
    info_cols[2].write(str(len(commands_received)))
    info_cols[3].caption("Unsupported commands")
    info_cols[3].write(str(len(unsupported_commands)))


def display_runtime_findings(checks: list[dict]) -> None:
    """Render runtime health checks grouped by category and ordered by severity."""
    st.subheader("Runtime Findings")
    if not checks:
        st.success("No runtime findings were identified by the supported checks.")
        return

    def _sev_key(c: dict) -> int:
        sev = str(c.get("severity", "INFO")).upper()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)

    sorted_checks = sorted(checks, key=_sev_key)

    categories: dict[str, list[dict]] = {}
    for c in sorted_checks:
        cat = c.get("category", "General")
        categories.setdefault(cat, []).append(c)

    for cat_name, cat_checks in categories.items():
        st.markdown(f"### {cat_name}")
        for item in cat_checks:
            severity = str(item.get("severity", "INFO")).upper()
            title = item.get("title") or "Untitled finding"
            source_cmd = item.get("source_command") or "Unknown"

            with st.expander(f"{severity} — {title}"):
                cols = st.columns(3)
                cols[0].markdown(f"**Severity**: {severity}")
                cols[1].markdown(f"**Category**: {cat_name}")
                cols[2].markdown(f"**Source Command**: `{source_cmd}`")

                st.markdown("**Description**")
                st.write(item.get("description") or "No description provided.")

                st.markdown("**Recommendation**")
                st.write(item.get("recommendation") or "No recommendation provided.")

                evidence = item.get("evidence", [])
                if evidence:
                    st.markdown("**Evidence**")
                    for ev_line in evidence:
                        st.markdown(f"- `{ev_line}`")


def display_runtime_inventory(inventory: dict) -> None:
    """Render structured runtime inventory."""
    st.subheader("Runtime Inventory")
    if not inventory:
        st.info("No runtime inventory data was extracted from the supplied output.")
        return

    # 1. System Status
    st.markdown("### System Status")
    sys_status = inventory.get("system_status")
    if sys_status:
        cols = st.columns(5)
        cols[0].caption("Hostname")
        cols[0].write(sys_status.get("hostname") or "-")
        cols[1].caption("FortiOS Version")
        cols[1].write(sys_status.get("version") or "-")
        cols[2].caption("Model / Platform")
        cols[2].write(sys_status.get("model") or "-")
        cols[3].caption("Serial Number")
        cols[3].write(sys_status.get("serial_number") or "-")
        cols[4].caption("System Time")
        cols[4].write(sys_status.get("system_time") or "-")
    else:
        st.caption("System status information was not supplied or could not be parsed.")

    st.divider()

    # 2. High Availability & NTP in columns
    col_ha, col_ntp = st.columns(2)
    with col_ha:
        st.markdown("### High Availability")
        ha = inventory.get("ha")
        if ha:
            st.markdown(f"**HA Mode**: {ha.get('ha_mode', 'unknown')}")
            st.markdown(f"**Synchronization**: {ha.get('sync_status', 'unknown')}")
        else:
            st.caption("HA status was not supplied or not configured.")

    with col_ntp:
        st.markdown("### Time Synchronization (NTP)")
        ntp = inventory.get("ntp")
        if ntp:
            st.markdown(f"**State**: {ntp.get('synchronization_state', 'unknown')}")
            st.markdown(f"**Server**: {ntp.get('server') or '-'}")
            st.markdown(f"**Stratum**: {ntp.get('stratum') or '-'}")
            st.markdown(f"**Offset**: {ntp.get('offset') or '-'}")
        else:
            st.caption("NTP status was not supplied or not parsed.")

    st.divider()

    # 3. FortiGuard & Hardware in columns
    col_fg, col_hw = st.columns(2)
    with col_fg:
        st.markdown("### FortiGuard / Updates")
        fg = inventory.get("fortiguard")
        if fg:
            st.markdown(f"**Status**: {fg.get('status', 'unknown')}")
        else:
            st.caption("FortiGuard status was not supplied.")

    with col_hw:
        st.markdown("### Hardware Health")
        hw = inventory.get("hardware")
        if hw:
            st.markdown(f"**PSU Status**: {hw.get('psu_status', 'unknown')}")
        else:
            st.caption("Hardware status was not supplied.")

    st.divider()

    # 4. Routing
    st.markdown("### Routing Table")
    routing = inventory.get("routing")
    if routing:
        r_cols = st.columns(4)
        r_cols[0].caption("Active Routes")
        r_cols[0].write(str(routing.get("route_count", 0)))
        r_cols[1].caption("Default Route Detected")
        r_cols[1].write("Yes" if routing.get("has_default_route") else "No")
        r_cols[2].caption("Default Gateway")
        r_cols[2].write(routing.get("default_gateway") or "-")
        r_cols[3].caption("Outgoing Interface")
        r_cols[3].write(routing.get("default_route_interface") or "-")
    else:
        st.caption("Routing table was not supplied.")

    st.divider()

    # 5. Stability & Config Errors
    col_crash, col_cfg = st.columns(2)
    with col_crash:
        st.markdown("### Crash Log")
        crashlog = inventory.get("crashlog")
        if crashlog:
            st.markdown(f"**Recorded Crashes**: {crashlog.get('crash_count', 0)}")
            for item in crashlog.get("crashes", []):
                st.caption(f"• `{item}`")
        else:
            st.caption("Crash log was not supplied or was empty.")

    with col_cfg:
        st.markdown("### Configuration Error Log")
        cfg_err = inventory.get("config_error_log")
        if cfg_err:
            st.markdown(f"**Recorded Errors**: {cfg_err.get('error_count', 0)}")
            for item in cfg_err.get("errors", []):
                st.caption(f"• `{item}`")
        else:
            st.caption("Configuration error log was not supplied or was empty.")


def display_runtime_commands(runtime_data: dict, runtime_result: dict) -> None:
    """Render list of commands analyzed and reference list."""
    st.subheader("Commands Analyzed")
    st.info("Only supplied commands are analyzed. Missing commands are not treated as warnings.")

    received = runtime_result.get("commands_received", [])
    unsupported = runtime_result.get("unsupported_commands", [])

    st.markdown("### Commands Received in Upload")
    if received:
        for cmd in received:
            status_badge = " [Unsupported / Skipped]" if cmd in unsupported else " [Supported]"
            st.markdown(f"- `{cmd}`{status_badge}")
    else:
        st.caption("No commands were recognized in the uploaded file.")

    st.markdown("### Supported Command Reference")
    for cmd in sorted(SUPPORTED_COMMANDS):
        st.markdown(f"- `{cmd}`")


def display_about_runtime_analysis() -> None:
    """Explain scope and limitations of runtime health analysis."""
    st.subheader("About Runtime Health Analysis")
    st.markdown(
        "Runtime Health Analysis evaluates CLI diagnostic output supplied by the user.\n\n"
        "It does **NOT**:\n"
        "- Connect to the FortiGate device\n"
        "- Execute commands\n"
        "- Use SSH or API connections\n"
        "- Continuously monitor the firewall\n"
        "- Prove end-to-end connectivity\n"
        "- Perform CVE lookups\n"
        "- Determine firmware support lifecycle\n"
        "- Replace FortiAnalyzer or FortiManager monitoring"
    )
    st.info(
        "Runtime results describe only the state reported in the supplied command "
        "output at the time it was collected."
    )
    st.markdown("### Comparison")
    st.markdown(
        "- **Configuration Analysis**: *What is configured?* (Evaluates policy logic, object containment, and static hardening settings in backups).\n"
        "- **Runtime Health Analysis**: *What state did the device report?* (Evaluates live operational state like HA synchronization, NTP lock, hardware sensors, and crash logs)."
    )


def display_runtime_results(payload: dict, filename: str, file_size: int) -> None:
    """Render all tabs for runtime analysis results."""
    runtime_data = payload["runtime_data"]
    runtime_result = payload["runtime_result"]

    tabs = st.tabs(
        [
            "Overview",
            "Runtime Findings",
            "Runtime Inventory",
            "Commands",
            "About Runtime Analysis",
        ]
    )
    with tabs[0]:
        display_runtime_overview(runtime_data, runtime_result, filename, file_size)
    with tabs[1]:
        display_runtime_findings(runtime_result.get("checks", []))
    with tabs[2]:
        display_runtime_inventory(runtime_result.get("inventory", {}))
    with tabs[3]:
        display_runtime_commands(runtime_data, runtime_result)
    with tabs[4]:
        display_about_runtime_analysis()


def display_sidebar(analysis_mode: str = "Configuration Analysis") -> None:
    """Render sidebar context depending on the selected analysis mode."""
    with st.sidebar:
        st.header("FortiGate Security Analyzer")
        if analysis_mode == "Runtime Health Analysis":
            st.subheader("Runtime Modules")
            st.markdown(
                "- FortiGuard / Updates\n"
                "- High Availability\n"
                "- Time Synchronization (NTP)\n"
                "- Hardware Health\n"
                "- System Stability\n"
                "- Configuration Integrity\n"
                "- Routing"
            )
            st.subheader("Analysis Type")
            st.write("Uploaded CLI Runtime Output")
            st.subheader("Privacy")
            st.caption(
                "Uploaded diagnostic output is processed locally in memory by "
                "the Streamlit application. Raw sensitive data is not displayed."
            )
        else:
            st.subheader("Analysis Modules")
            st.markdown(
                "- Policy Analysis\n"
                "- Policy Relationships\n"
                "- Health Check\n"
                "- IPsec Review\n"
                "- Security Profiles\n"
                "- System Hardening"
            )
            st.subheader("Analysis Type")
            st.write("Static Configuration Analysis")
            st.subheader("Privacy")
            st.caption(
                "Uploaded configuration is processed in memory by the local "
                "Streamlit application. Raw configuration text is not displayed."
            )


def display_empty_state() -> None:
    """Explain the workflow before analysis begins."""
    st.info("Start with a FortiGate configuration backup.")
    st.markdown(
        "1. Upload a FortiGate configuration backup.\n"
        "2. Run static analysis.\n"
        "3. Review policy behavior, health checks, and relationships."
    )
    st.caption("Supported files: .conf and .txt")


def main() -> None:
    """Render the upload, cached analysis, filtering, and result workflow."""
    st.set_page_config(page_title="FortiGate Security Analyzer", layout="wide")

    analysis_mode = st.radio(
        "Analysis Mode",
        options=["Configuration Analysis", "Runtime Health Analysis"],
        horizontal=True,
    )

    display_sidebar(analysis_mode)
    st.title("FortiGate Security Analyzer")

    if analysis_mode == "Configuration Analysis":
        st.write(
            "Static analysis of FortiGate firewall policies and configuration health."
        )
        st.caption(
            "This tool identifies configurations that may require security review. "
            "Findings are not necessarily configuration errors."
        )

        uploaded_file = st.file_uploader(
            "Upload a FortiGate configuration",
            type=["conf", "txt"],
            help="The file is processed in memory and is not saved by this app.",
            key="config_uploader",
        )
        file_bytes = uploaded_file.getvalue() if uploaded_file is not None else b""
        fingerprint = (
            hashlib.sha256(file_bytes).hexdigest() if uploaded_file is not None else None
        )
        if st.session_state.get("uploaded_fingerprint") != fingerprint:
            st.session_state["uploaded_fingerprint"] = fingerprint
            st.session_state.pop("analysis_payload", None)
            st.session_state.pop("analysis_filename", None)
            st.session_state.pop("analysis_file_size", None)

        if uploaded_file is not None:
            st.caption(
                f"Selected file: {uploaded_file.name} "
                f"({_format_file_size(len(file_bytes))})"
            )

        analyze_clicked = st.button("Analyze Configuration", type="primary", key="btn_analyze_config")
        if analyze_clicked:
            if uploaded_file is None:
                st.warning("Upload a FortiGate .conf or .txt file before analyzing.")
            elif not file_bytes or not file_bytes.strip():
                st.warning("The uploaded file is empty.")
            else:
                try:
                    config_text = file_bytes.decode("utf-8", errors="replace")
                    st.session_state["analysis_payload"] = _run_analysis_pipeline(
                        config_text
                    )
                    st.session_state["analysis_filename"] = uploaded_file.name
                    st.session_state["analysis_file_size"] = len(file_bytes)
                except Exception as error:  # Streamlit boundary for malformed uploads.
                    st.error(f"The configuration could not be analyzed: {error}")
                    return

        payload = st.session_state.get("analysis_payload")
        if payload is None:
            display_empty_state()
            return

        st.divider()
        display_results(
            payload,
            str(st.session_state.get("analysis_filename") or "Uploaded configuration"),
            int(st.session_state.get("analysis_file_size") or 0),
        )

    else:
        st.write(
            "Runtime health analysis of live FortiGate diagnostic command outputs."
        )
        st.caption(
            "Evaluate operational status, HA synchronization, NTP state, hardware health, "
            "and crash logs from supplied CLI text."
        )

        runtime_file = st.file_uploader(
            "Upload FortiGate CLI Runtime Output",
            type=["txt"],
            help="Upload a text file containing FortiGate CLI outputs with === COMMAND: <name> === markers.",
            key="runtime_uploader",
        )
        r_file_bytes = runtime_file.getvalue() if runtime_file is not None else b""
        r_fingerprint = (
            hashlib.sha256(r_file_bytes).hexdigest() if runtime_file is not None else None
        )
        if st.session_state.get("runtime_fingerprint") != r_fingerprint:
            st.session_state["runtime_fingerprint"] = r_fingerprint
            st.session_state.pop("runtime_payload", None)
            st.session_state.pop("runtime_filename", None)
            st.session_state.pop("runtime_file_size", None)

        if runtime_file is not None:
            st.caption(
                f"Selected file: {runtime_file.name} "
                f"({_format_file_size(len(r_file_bytes))})"
            )

        analyze_runtime_clicked = st.button("Analyze Runtime Health", type="primary", key="btn_analyze_runtime")
        if analyze_runtime_clicked:
            if runtime_file is None:
                st.warning("Upload a FortiGate runtime .txt file before analyzing.")
            elif not r_file_bytes or not r_file_bytes.strip():
                st.warning("The uploaded file is empty.")
            else:
                try:
                    runtime_text = r_file_bytes.decode("utf-8", errors="replace")
                    st.session_state["runtime_payload"] = _run_runtime_pipeline(
                        runtime_text
                    )
                    st.session_state["runtime_filename"] = runtime_file.name
                    st.session_state["runtime_file_size"] = len(r_file_bytes)
                except Exception as error:  # Streamlit boundary for malformed runtime uploads.
                    st.error(f"The runtime output could not be analyzed: {error}")
                    return

        runtime_payload = st.session_state.get("runtime_payload")
        if runtime_payload is None:
            display_runtime_empty_state()
            return

        st.divider()
        display_runtime_results(
            runtime_payload,
            str(st.session_state.get("runtime_filename") or "Uploaded runtime output"),
            int(st.session_state.get("runtime_file_size") or 0),
        )


if __name__ == "__main__":
    main()
