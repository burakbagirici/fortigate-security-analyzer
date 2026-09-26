"""FortiGate Configuration Health Check v4 backend."""

from __future__ import annotations

import re

from .analyzer import (
    analyze_configuration,
    classify_interface,
)
from .fortios_defaults import collect_applied_defaults, infer_field_default


MANAGEMENT_PROTOCOLS = {"http", "https", "ssh", "telnet"}
DISABLED_VALUES = {"disable", "disabled", "no"}
KNOWN_INTERFACE_BUILTINS = {"any"}
MAX_INTEGRITY_EVIDENCE = 10
LEGACY_DH_GROUPS = {1, 2, 5}
PROFILE_TYPE_LABELS = {
    "ips": "IPS",
    "antivirus": "Antivirus",
    "web_filter": "Web Filter",
    "application_control": "Application Control",
    "ssl_inspection": "SSL Inspection",
    "dns_filter": "DNS Filter",
    "email_filter": "Email Filter",
    "dlp": "DLP",
    "casb": "CASB",
}
SUPPORTED_UTM_PROFILE_TYPES = {
    "ips",
    "antivirus",
    "web_filter",
    "application_control",
    "dns_filter",
}
MAX_PROFILE_EVIDENCE = 20


def _values(value: object) -> list[str]:
    """Return a configuration value as a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _normalized(value: object) -> set[str]:
    """Return case-insensitive configuration values."""
    return {item.casefold() for item in _values(value)}


def _first(value: object, default: str = "-") -> str:
    """Return the first scalar representation of a setting."""
    values = _values(value)
    return values[0] if values else default


def _result(
    category: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: list[str],
) -> dict:
    """Build one structured health-check result."""
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence,
        "review_required": True,
    }


def _scoped_result(result: dict, source: dict) -> dict:
    """Attach VDOM context to a result when its source is VDOM-scoped."""
    if source.get("vdom") is not None:
        result["vdom"] = source.get("vdom")
    return result


def _settings_blocks(config: dict, plural_key: str, singular_key: str) -> list[dict]:
    """Read repeated settings while accepting the single-block compatibility key."""
    blocks = config.get(plural_key, [])
    if isinstance(blocks, list):
        return [block for block in blocks if isinstance(block, dict)]
    block = config.get(singular_key, {})
    return [block] if isinstance(block, dict) and block else []


def _numeric_value(value: object) -> float | None:
    """Parse an explicitly configured numeric value without inferring defaults."""
    raw_value = _first(value, "")
    if not raw_value:
        return None
    try:
        return float(raw_value)
    except (TypeError, ValueError):
        return None


def _is_disabled(policy: dict) -> bool:
    return bool(_normalized(policy.get("status")) & {"disable", "disabled"})


def _is_accept(policy: dict) -> bool:
    return "accept" in _normalized(policy.get("action"))


def _profile_detected(policy: dict, field: str) -> bool:
    """Return whether a named profile appears active on the policy."""
    if _normalized(policy.get("utm-status")) & DISABLED_VALUES:
        return False
    values = _normalized(policy.get(field))
    return bool(values - {"", "none", "disable", "disabled"})


def _wan_management_checks(
    interfaces: object,
    ipsec_phase1: object = None,
) -> tuple[list[dict], list[dict]]:
    """Check management protocols and return WAN management context."""
    checks: list[dict] = []
    wan_management: list[dict] = []
    if not isinstance(interfaces, list):
        return checks, wan_management

    vpn_interfaces = {
        (
            str(item.get("vdom")).casefold()
            if item.get("vdom") is not None
            else None,
            str(item.get("name", "")).casefold(),
        )
        for item in (ipsec_phase1 if isinstance(ipsec_phase1, list) else [])
        if isinstance(item, dict)
        and item.get("definition_type") == "phase1-interface"
        and item.get("name") is not None
    }

    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        interface_scope = (
            str(interface.get("vdom")).casefold()
            if interface.get("vdom") is not None
            else None
        )
        if (
            interface_scope,
            str(interface.get("name", "")).casefold(),
        ) in vpn_interfaces:
            continue
        context = classify_interface(interface)
        if context["role"] != "WAN":
            continue

        interface_name = context["name"] or "Unnamed interface"
        allowed = _normalized(interface.get("allowaccess"))
        enabled_management = sorted(allowed & MANAGEMENT_PROTOCOLS)
        role_evidence = (
            "WAN (inferred from interface name or alias)"
            if context["role_inferred"]
            else "WAN"
        )
        base_evidence = [
            f"Interface: {interface_name}",
            f"Role: {role_evidence}",
        ]

        if enabled_management:
            wan_management.append(
                {
                    "interface": interface_name,
                    "protocols": enabled_management,
                    "role": role_evidence,
                }
            )

        if "http" in allowed:
            checks.append(
                _result(
                    "Administrative Security",
                    "HIGH",
                    "Insecure HTTP Management Exposed on WAN",
                    "HTTP management is enabled on a WAN interface. HTTP does "
                    "not encrypt administrative traffic and should be reviewed.",
                    "Disable HTTP management on the WAN interface and use an "
                    "encrypted, intentionally restricted management path.",
                    base_evidence + ["Allowed management protocol: http"],
                )
            )

        if "telnet" in allowed:
            checks.append(
                _result(
                    "Administrative Security",
                    "HIGH",
                    "Telnet Management Exposed on WAN",
                    "Telnet management is enabled on a WAN interface. Telnet "
                    "does not provide encrypted administrative access.",
                    "Disable Telnet management and use an encrypted, "
                    "intentionally restricted management method.",
                    base_evidence + ["Allowed management protocol: telnet"],
                )
            )

        remote_protocols = sorted(allowed & {"https", "ssh"})
        if remote_protocols:
            checks.append(
                _result(
                    "Administrative Security",
                    "MEDIUM",
                    "Remote Management Accessible from WAN",
                    "Encrypted remote management is enabled on a WAN interface. "
                    "This may be intentional, but external firewall "
                    "administration should be restricted and reviewed.",
                    "Verify the operational requirement and restrict remote "
                    "management to approved sources and management paths.",
                    base_evidence
                    + [
                        "Allowed management protocols: "
                        + ", ".join(remote_protocols)
                    ],
                )
            )

    return checks, wan_management


def _has_meaningful_trusted_host(admin: dict) -> bool:
    """Recognize a non-default trusted-host restriction defensively."""
    unrestricted_tokens = {"0.0.0.0", "::", "0", "0:0:0:0:0:0:0:0"}
    for number in range(1, 11):
        values = [
            value.strip().casefold()
            for value in _values(admin.get(f"trusthost{number}"))
            if value.strip()
        ]
        if not values:
            continue
        joined = " ".join(values)
        if joined in {"0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0"}:
            continue
        if all(value in unrestricted_tokens for value in values):
            continue
        return True
    return False


def _administrator_trust_check(
    admins: object,
    wan_management: list[dict],
) -> list[dict]:
    """Report unrestricted administrators only when WAN management exists."""
    if not wan_management or not isinstance(admins, list):
        return []

    unrestricted_admins = [
        admin
        for admin in admins
        if isinstance(admin, dict) and not _has_meaningful_trusted_host(admin)
    ]
    if not unrestricted_admins:
        return []

    evidence = [
        "WAN management interface: " + item["interface"]
        for item in wan_management[:3]
    ]
    for admin in unrestricted_admins[:5]:
        evidence.extend(
            [
                f"Administrator: {_first(admin.get('name'), 'Unnamed')}",
                f"Access profile: {_first(admin.get('accprofile'))}",
                "Meaningful trusted host restriction: not detected",
            ]
        )
    if len(unrestricted_admins) > 5:
        evidence.append(
            f"Additional administrators not shown: {len(unrestricted_admins) - 5}"
        )

    return [
        _result(
            "Administrative Security",
            "MEDIUM",
            "Administrative Access Lacks Trusted Host Restrictions",
            "WAN management access is enabled and one or more administrator "
            "accounts do not have a meaningful trusted-host restriction in "
            "the parsed configuration.",
            "Review administrator trusted-host settings and restrict external "
            "administrative access to approved source networks where practical.",
            evidence,
        )
    ]


def _policy_label(policy: dict) -> str:
    label = f"Policy #{_first(policy.get('id'), 'Unknown')}"
    if policy.get("vdom") is not None:
        return f"{label} (VDOM: {policy.get('vdom')})"
    return label


def _policy_scope_key(policy: dict) -> tuple[str | None, object]:
    vdom = policy.get("vdom")
    normalized_vdom = str(vdom).casefold() if vdom is not None else None
    return normalized_vdom, policy.get("id")


def _policy_evidence(policy: dict, assessment: dict) -> list[str]:
    """Build safe, reusable policy evidence."""
    destinations = ", ".join(_values(policy.get("dstaddr"))) or "-"
    services = ", ".join(_values(policy.get("service"))) or "-"
    evidence = [
        f"Policy ID: {_first(policy.get('id'), 'Unknown')}",
        f"Policy name: {_first(policy.get('name'), 'Unnamed Policy')}",
        f"Traffic direction: {assessment.get('traffic_direction', 'UNKNOWN')}",
        f"Destination/VIP: {destinations}",
        f"Services: {services}",
    ]
    if policy.get("vdom") is not None:
        evidence.insert(0, f"VDOM: {policy.get('vdom')}")
    return evidence


def _policy_health_checks(config: dict, analysis_result: dict) -> list[dict]:
    """Check profile and logging coverage using analyzer traffic context."""
    checks: list[dict] = []
    policies = [
        policy
        for policy in config.get("policies", [])
        if isinstance(policy, dict)
    ]
    assessments = analysis_result.get("policy_assessments", [])
    analyzer_findings = analysis_result.get("findings", [])

    already_reported_logging_policies = {
        (
            str(f.get("vdom")).casefold() if f.get("vdom") is not None else None,
            f.get("policy_id"),
        )
        for f in analyzer_findings
        if isinstance(f, dict)
        and f.get("title") == "Logging Disabled on Security-Relevant Policy"
    }

    for policy, assessment in zip(policies, assessments):
        if _is_disabled(policy) or not _is_accept(policy):
            continue

        flow_type = assessment.get("flow_type", "UNKNOWN")
        purpose = assessment.get("purpose", "Custom / Unknown Access")
        evidence = _policy_evidence(policy, assessment)
        security_profiles = assessment.get("security_profiles", {})
        ips_profile = security_profiles.get("ips", {})

        if flow_type == "INBOUND_PUBLIC" and not ips_profile.get("attached"):
            checks.append(
                _result(
                    "Security Profiles",
                    "MEDIUM",
                    "IPS Not Detected on Internet-Facing Policy",
                    "No IPS profile was detected on this Internet-facing "
                    "policy in the parsed configuration.",
                    "Review whether IPS inspection is appropriate for this "
                    "policy based on its purpose and organizational requirements.",
                    evidence + ["IPS profile status: not detected"],
                )
            )

        if flow_type == "OUTBOUND_INTERNET":
            relevant_types = {
                "antivirus",
                "web_filter",
                "application_control",
                "ips",
            }
            if not any(
                security_profiles.get(profile_type, {}).get("attached")
                for profile_type in relevant_types
            ):
                checks.append(
                    _result(
                        "Security Profiles",
                        "LOW",
                        "No Security Profiles Detected on Outbound Internet Policy",
                        "No antivirus, web-filtering, application-control, or "
                        "IPS profile was detected on this outbound Internet "
                        "policy in the parsed configuration.",
                        "Review whether security profiles are appropriate for "
                        "this policy based on organizational requirements and "
                        "the policy's purpose.",
                        evidence + ["Relevant security profiles: not detected"],
                    )
                )

        logging_disabled = bool(
            _normalized(policy.get("logtraffic")) & DISABLED_VALUES
        )
        security_relevant = (
            flow_type == "INBOUND_PUBLIC"
            or purpose == "Remote Administrative Access"
        )
        if (
            logging_disabled
            and security_relevant
            and _policy_scope_key(policy)
            not in already_reported_logging_policies
        ):
            checks.append(
                _result(
                    "Logging",
                    "MEDIUM",
                    "Traffic Logging Disabled on Security-Relevant Policy",
                    "Traffic logging is explicitly disabled on a policy that "
                    "appears to provide inbound public or administrative access.",
                    "Review whether traffic logging should be enabled based on "
                    "operational and security requirements.",
                    evidence
                    + [
                        f"Traffic purpose: {purpose}",
                        f"Explicit logtraffic value: {_first(policy.get('logtraffic'))}",
                    ],
                )
            )

    return checks


def _security_profile_consistency_checks(
    config: dict, analysis_result: dict
) -> list[dict]:
    """Report resolvability and explicit UTM/profile inconsistencies."""
    checks: list[dict] = []
    unresolved_evidence: list[str] = []
    unresolved_count = 0
    policies = config.get("policies", [])
    if not isinstance(policies, list):
        return checks
    assessments = analysis_result.get("policy_assessments", [])

    for policy, assessment in zip(policies, assessments):
        if not isinstance(policy, dict) or _is_disabled(policy):
            continue

        profiles = assessment.get("security_profiles", {})
        for profile_type, profile in profiles.items():
            if profile.get("attached") and profile.get("resolved") is False:
                unresolved_count += 1
                if len(unresolved_evidence) < MAX_PROFILE_EVIDENCE:
                    unresolved_evidence.append(
                        f"VDOM: {_first(policy.get('vdom'), 'global')}; "
                        f"Policy ID: {_first(policy.get('id'), 'Unknown')}; "
                        f"Policy name: {_first(policy.get('name'), 'Unnamed Policy')}; "
                        f"Profile type: {PROFILE_TYPE_LABELS.get(profile_type, profile_type)}; "
                        f"Referenced profile: {profile.get('name')}"
                    )

        utm_status = _normalized(policy.get("utm-status"))
        attached_utm_profiles = [
            (profile_type, profiles[profile_type])
            for profile_type in SUPPORTED_UTM_PROFILE_TYPES
            if profiles.get(profile_type, {}).get("attached")
        ]
        base_evidence = [
            f"VDOM: {_first(policy.get('vdom'), 'global')}",
            f"Policy ID: {_first(policy.get('id'), 'Unknown')}",
            f"Policy name: {_first(policy.get('name'), 'Unnamed Policy')}",
        ]

        if (
            _is_accept(policy)
            and "enable" in utm_status
            and not attached_utm_profiles
        ):
            checks.append(
                _result(
                    "Security Profiles",
                    "LOW",
                    "UTM Enabled Without Detected Security Profiles",
                    "UTM is explicitly enabled, but none of the security-profile "
                    "types currently understood by this MVP were detected on "
                    "the policy. Other version-specific profile types may exist.",
                    "Review the policy and confirm that the intended inspection "
                    "profiles are attached.",
                    base_evidence + ["utm-status: enable"],
                )
            )

        if utm_status & DISABLED_VALUES and attached_utm_profiles:
            profile_summary = ", ".join(
                f"{PROFILE_TYPE_LABELS.get(profile_type, profile_type)}: "
                f"{profile.get('name')}"
                for profile_type, profile in attached_utm_profiles
            )
            checks.append(
                _result(
                    "Security Profiles",
                    "MEDIUM",
                    "Security Profile Referenced While UTM Is Disabled",
                    "Security profile references are present while UTM is "
                    "explicitly disabled. Review is required to confirm whether "
                    "inspection is applied as intended.",
                    "Confirm the intended UTM state and remove stale references "
                    "or enable the required inspection configuration as appropriate.",
                    base_evidence
                    + [
                        f"utm-status: {_first(policy.get('utm-status'))}",
                        f"Referenced profiles: {profile_summary}",
                    ],
                )
            )

    interface_policies = config.get("interface_policies", [])
    if isinstance(interface_policies, list):
        interface_assessments = analysis_result.get(
            "interface_policy_assessments", []
        )
        for policy, assessment in zip(interface_policies, interface_assessments):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            profiles = assessment.get("inspection_profiles", {})
            for profile_type, profile in profiles.items():
                if profile.get("active") is True and profile.get("resolved") is False:
                    unresolved_count += 1
                    if len(unresolved_evidence) < MAX_PROFILE_EVIDENCE:
                        unresolved_evidence.append(
                            f"VDOM: {_first(policy.get('vdom'), 'global')}; "
                            f"Interface Policy ID: {_first(policy.get('id'), 'Unknown')}; "
                            f"Profile type: {PROFILE_TYPE_LABELS.get(profile_type, profile_type)}; "
                            f"Referenced profile: {profile.get('configured_reference') or profile.get('name')}"
                        )

    interface_policies6 = config.get("interface_policies6", [])
    if isinstance(interface_policies6, list):
        interface_assessments6 = analysis_result.get(
            "interface_policy6_assessments", []
        )
        for policy, assessment in zip(interface_policies6, interface_assessments6):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            profiles = assessment.get("inspection_profiles", {})
            for profile_type, profile in profiles.items():
                if profile.get("active") is True and profile.get("resolved") is False:
                    unresolved_count += 1
                    if len(unresolved_evidence) < MAX_PROFILE_EVIDENCE:
                        unresolved_evidence.append(
                            f"VDOM: {_first(policy.get('vdom'), 'global')}; "
                            f"Interface Policy (IPv6) ID: {_first(policy.get('id'), 'Unknown')}; "
                            f"Profile type: {PROFILE_TYPE_LABELS.get(profile_type, profile_type)}; "
                            f"Referenced profile: {profile.get('configured_reference') or profile.get('name')}"
                        )

    if unresolved_count:
        if unresolved_count > len(unresolved_evidence):
            unresolved_evidence.append(
                f"Additional unresolved references omitted: "
                f"{unresolved_count - len(unresolved_evidence)}"
            )
        checks.append(
            _result(
                "Security Profiles",
                "MEDIUM",
                "Referenced Security Profile Could Not Be Resolved",
                "The backup references one or more security profiles that the "
                "current parser could not resolve. This may reflect an incomplete "
                "backup, version-specific structure, an unsupported built-in "
                "profile, or a stale reference.",
                "Review the referenced names against the source FortiGate and "
                "confirm that the backup contains the expected profile definitions.",
                unresolved_evidence,
            )
        )

    return checks


def _disabled_policy_check(policies: object) -> list[dict]:
    """Aggregate disabled policy cleanup evidence into one result."""
    if not isinstance(policies, list):
        return []
    disabled = [
        policy
        for policy in policies
        if isinstance(policy, dict) and _is_disabled(policy)
    ]
    if not disabled:
        return []

    policy_ids = ", ".join(_first(policy.get("id"), "Unknown") for policy in disabled)
    return [
        _result(
            "Configuration Hygiene",
            "LOW",
            "Disabled Firewall Policies Present",
            "Disabled firewall policies remain in the configuration. They may "
            "be intentionally retained, but obsolete rules should be reviewed "
            "periodically.",
            "Verify whether the disabled policies are still required and "
            "remove obsolete rules after appropriate review.",
            [
                f"Disabled policies detected: {len(disabled)}",
                f"Policy IDs: {policy_ids}",
            ],
        )
    ]


def _unknown_names(resolved: object) -> list[str]:
    """Collect unresolved leaves from analyzer resolution output."""
    if not isinstance(resolved, list):
        return []
    unknown: list[str] = []
    for item in resolved:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "unknown":
            unknown.append(str(item.get("name", "Unknown")))
        unknown.extend(_unknown_names(item.get("members")))
    return unknown


def _configuration_integrity_check(config: dict, analysis_result: dict) -> list[dict]:
    """Aggregate references the current parser cannot resolve."""
    assessments = analysis_result.get("policy_assessments", [])
    policies = [
        policy
        for policy in config.get("policies", [])
        if isinstance(policy, dict)
    ]
    evidence: list[str] = []

    for policy, assessment in zip(policies, assessments):
        label = _policy_label(policy)
        interface_contexts = assessment.get("source_interfaces", []) + (
            assessment.get("destination_interfaces", [])
        )
        for interface in interface_contexts:
            if not isinstance(interface, dict):
                continue
            name = str(interface.get("name", "Unknown"))
            if (
                interface.get("resolved") is False
                and name.casefold() not in KNOWN_INTERFACE_BUILTINS
            ):
                evidence.append(f"{label}: unresolved interface {name}")

        for name in _unknown_names(assessment.get("resolved_sources")):
            evidence.append(f"{label}: unresolved address {name}")
        for name in _unknown_names(assessment.get("resolved_destinations")):
            evidence.append(f"{label}: unresolved address {name}")
        for name in _unknown_names(assessment.get("resolved_services")):
            evidence.append(f"{label}: unresolved service {name}")

        matching = assessment.get("internet_service_matching", {})
        if isinstance(matching, dict):
            for side in ("source", "destination"):
                side_context = matching.get(side, {})
                if not isinstance(side_context, dict):
                    continue
                for selector in side_context.get("selectors", []):
                    if (
                        isinstance(selector, dict)
                        and selector.get("resolution") == "unresolved"
                    ):
                        evidence.append(
                            f"{label}: unresolved {side} ISDB "
                            f"{selector.get('type')} {selector.get('value')}"
                        )

    interface_policies = config.get("interface_policies", [])
    if isinstance(interface_policies, list):
        interface_assessments = analysis_result.get(
            "interface_policy_assessments", []
        )
        for policy, assessment in zip(interface_policies, interface_assessments):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            vdom_suffix = (
                f" (VDOM: {policy.get('vdom')})"
                if policy.get("vdom") is not None
                else ""
            )
            label = f"Interface Policy #{_first(policy.get('id'), 'Unknown')}{vdom_suffix}"
            for interface in assessment.get("interfaces", []):
                if not isinstance(interface, dict):
                    continue
                name = str(interface.get("name", "Unknown"))
                if (
                    interface.get("resolved") is False
                    and name.casefold() not in KNOWN_INTERFACE_BUILTINS
                ):
                    evidence.append(f"{label}: unresolved interface {name}")

            for name in _unknown_names(assessment.get("resolved_sources")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_destinations")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_services")):
                evidence.append(f"{label}: unresolved service {name}")

    interface_policies6 = config.get("interface_policies6", [])
    if isinstance(interface_policies6, list):
        interface_assessments6 = analysis_result.get(
            "interface_policy6_assessments", []
        )
        for policy, assessment in zip(interface_policies6, interface_assessments6):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            vdom_suffix = (
                f" (VDOM: {policy.get('vdom')})"
                if policy.get("vdom") is not None
                else ""
            )
            label = f"Interface Policy (IPv6) #{_first(policy.get('id'), 'Unknown')}{vdom_suffix}"
            for interface in assessment.get("interfaces", []):
                if not isinstance(interface, dict):
                    continue
                name = str(interface.get("name", "Unknown"))
                if (
                    interface.get("resolved") is False
                    and name.casefold() not in KNOWN_INTERFACE_BUILTINS
                ):
                    evidence.append(f"{label}: unresolved interface {name}")

            for name in _unknown_names(assessment.get("resolved_sources")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_destinations")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_services")):
                evidence.append(f"{label}: unresolved service {name}")

    local_in_policies = config.get("local_in_policies", [])
    if isinstance(local_in_policies, list):
        local_in_assessments = analysis_result.get("local_in_assessments", [])
        for policy, assessment in zip(local_in_policies, local_in_assessments):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            vdom_suffix = (
                f" (VDOM: {policy.get('vdom')})"
                if policy.get("vdom") is not None
                else ""
            )
            label = f"Local-In Policy #{_first(policy.get('id'), 'Unknown')}{vdom_suffix}"
            for interface in assessment.get("interfaces", []):
                if not isinstance(interface, dict):
                    continue
                name = str(interface.get("name", "Unknown"))
                if (
                    interface.get("resolved") is False
                    and name.casefold() not in KNOWN_INTERFACE_BUILTINS
                ):
                    evidence.append(f"{label}: unresolved interface {name}")

            for name in _unknown_names(assessment.get("resolved_sources")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_destinations")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_services")):
                evidence.append(f"{label}: unresolved service {name}")

    local_in_policies6 = config.get("local_in_policies6", [])
    if isinstance(local_in_policies6, list):
        local_in_assessments6 = analysis_result.get(
            "local_in_policy6_assessments", []
        )
        for policy, assessment in zip(local_in_policies6, local_in_assessments6):
            if not isinstance(policy, dict) or _is_disabled(policy):
                continue
            vdom_suffix = (
                f" (VDOM: {policy.get('vdom')})"
                if policy.get("vdom") is not None
                else ""
            )
            label = f"Local-In Policy (IPv6) #{_first(policy.get('id'), 'Unknown')}{vdom_suffix}"
            for interface in assessment.get("interfaces", []):
                if not isinstance(interface, dict):
                    continue
                name = str(interface.get("name", "Unknown"))
                if (
                    interface.get("resolved") is False
                    and name.casefold() not in KNOWN_INTERFACE_BUILTINS
                ):
                    evidence.append(f"{label}: unresolved interface {name}")

            for name in _unknown_names(assessment.get("resolved_sources")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_destinations")):
                evidence.append(f"{label}: unresolved address {name}")
            for name in _unknown_names(assessment.get("resolved_services")):
                evidence.append(f"{label}: unresolved service {name}")

    for ssl_assessment in analysis_result.get("ssl_vpn_assessments", []):
        if not isinstance(ssl_assessment, dict):
            continue
        if ssl_assessment.get("status") == "DISABLED":
            continue
        vdom = ssl_assessment.get("vdom")
        vdom_suffix = f" (VDOM: {vdom})" if vdom is not None else ""
        label = f"SSL-VPN Configuration{vdom_suffix}"

        for interface in ssl_assessment.get("interface_contexts", []):
            if not isinstance(interface, dict):
                continue
            name = str(interface.get("name", "Unknown"))
            if (
                interface.get("resolved") is False
                and name.casefold() not in KNOWN_INTERFACE_BUILTINS
            ):
                evidence.append(f"{label}: unresolved source interface {name}")

        for name in _unknown_names(ssl_assessment.get("resolved_sources")):
            evidence.append(f"{label}: unresolved source address {name}")
        for name in _unknown_names(ssl_assessment.get("resolved_sources6")):
            evidence.append(f"{label}: unresolved source address (IPv6) {name}")

        dp_res = ssl_assessment.get("default_portal_resolution", {})
        if (
            isinstance(dp_res, dict)
            and dp_res.get("name")
            and not dp_res.get("resolved")
        ):
            evidence.append(f"{label}: unresolved default portal {dp_res.get('name')}")

        for rule in ssl_assessment.get("authentication_rules", []):
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("rule_id", "Unknown")
            rule_label = f"{label} Auth Rule #{rule_id}"

            p_res = rule.get("portal_resolution", {})
            if (
                isinstance(p_res, dict)
                and p_res.get("name")
                and not p_res.get("resolved")
            ):
                evidence.append(f"{rule_label}: unresolved portal {p_res.get('name')}")

            for g in rule.get("resolved_groups", []):
                if isinstance(g, dict) and not g.get("resolved"):
                    evidence.append(f"{rule_label}: unresolved group {g.get('name')}")

            for u in rule.get("resolved_users", []):
                if isinstance(u, dict) and not u.get("resolved"):
                    evidence.append(f"{rule_label}: unresolved user {u.get('name')}")

            for intf in rule.get("interfaces", []):
                if not isinstance(intf, dict):
                    continue
                iname = str(intf.get("name", "Unknown"))
                if (
                    intf.get("resolved") is False
                    and iname.casefold() not in KNOWN_INTERFACE_BUILTINS
                ):
                    evidence.append(f"{rule_label}: unresolved source interface {iname}")

            for name in _unknown_names(rule.get("resolved_addresses")):
                evidence.append(f"{rule_label}: unresolved source address {name}")
            for name in _unknown_names(rule.get("resolved_addresses6")):
                evidence.append(f"{rule_label}: unresolved source address (IPv6) {name}")

    unique_evidence = list(dict.fromkeys(evidence))
    if not unique_evidence:
        return []

    limited_evidence = unique_evidence[:MAX_INTEGRITY_EVIDENCE]
    if len(unique_evidence) > MAX_INTEGRITY_EVIDENCE:
        limited_evidence.append(
            f"Additional unresolved references not shown: "
            f"{len(unique_evidence) - MAX_INTEGRITY_EVIDENCE}"
        )

    return [
        _result(
            "Configuration Integrity",
            "LOW",
            "Configuration References Could Not Be Fully Resolved",
            "Some objects referenced by firewall policies could not be "
            "resolved by the current parser. Security analysis for those "
            "policies may therefore be incomplete.",
            "Review the unresolved examples and extend parser context where "
            "necessary. This result does not mean the FortiGate configuration "
            "itself is broken.",
            limited_evidence,
        )
    ]


def _proposal_text(value: object) -> str:
    """Format one or more configured proposals for safe evidence."""
    return ", ".join(_values(value)) or "-"


def _legacy_algorithms(value: object) -> list[str]:
    """Detect only the explicitly supported legacy proposal algorithms."""
    detected: set[str] = set()
    for proposal in _values(value):
        tokens = re.split(r"[^a-z0-9]+", proposal.casefold())
        for token in tokens:
            if token == "3des":
                detected.add("3DES")
            elif token == "des":
                detected.add("DES")
            elif token == "md5":
                detected.add("MD5")
    return sorted(detected)


def _dh_groups(value: object) -> set[int]:
    """Extract numeric Diffie-Hellman groups from common FortiOS forms."""
    return {
        int(group)
        for group in re.findall(r"\d+", " ".join(_values(value)))
    }


def _phase1_evidence(phase: dict) -> list[str]:
    evidence = [
        f"Phase 1 name: {_first(phase.get('name'), 'Unnamed')}",
    ]
    if phase.get("vdom") is not None:
        evidence.insert(0, f"VDOM: {phase.get('vdom')}")
    remote_gateway = _first(phase.get("remote-gw"), "")
    if remote_gateway:
        evidence.append(f"Configured remote gateway: {remote_gateway}")
    return evidence


def _phase2_evidence(phase: dict) -> list[str]:
    evidence = [
        f"Phase 2 name: {_first(phase.get('name'), 'Unnamed')}",
        f"Referenced Phase 1: {_first(phase.get('phase1name'))}",
    ]
    if phase.get("vdom") is not None:
        evidence.insert(0, f"VDOM: {phase.get('vdom')}")
    return evidence


def _legacy_crypto_check(phase: dict, phase_label: str) -> list[dict]:
    algorithms = _legacy_algorithms(phase.get("proposal"))
    if not algorithms:
        return []
    evidence = (
        _phase1_evidence(phase)
        if phase_label == "Phase 1"
        else _phase2_evidence(phase)
    )
    evidence.extend(
        [
            f"VPN phase: {phase_label}",
            f"Proposal: {_proposal_text(phase.get('proposal'))}",
            "Detected legacy algorithm: " + ", ".join(algorithms),
        ]
    )
    return [
        _result(
            "VPN / IPsec",
            "HIGH",
            "Legacy Cryptographic Algorithm Detected",
            "The current backup explicitly configures a legacy cryptographic "
            "algorithm in an IPsec proposal. This setting should be reviewed.",
            "Consider modern proposal algorithms supported by both VPN peers "
            "and follow the organization's cryptographic requirements.",
            evidence,
        )
    ]


def _legacy_dh_check(phase: dict, phase_label: str) -> list[dict]:
    legacy_groups = sorted(_dh_groups(phase.get("dhgrp")) & LEGACY_DH_GROUPS)
    if not legacy_groups:
        return []
    evidence = (
        _phase1_evidence(phase)
        if phase_label == "Phase 1"
        else _phase2_evidence(phase)
    )
    evidence.extend(
        [
            f"VPN phase: {phase_label}",
            "Configured DH groups: " + _proposal_text(phase.get("dhgrp")),
            "Detected legacy DH groups: "
            + ", ".join(str(group) for group in legacy_groups),
        ]
    )
    return [
        _result(
            "VPN / IPsec",
            "MEDIUM",
            "Legacy Diffie-Hellman Group Detected",
            "The current backup explicitly configures a legacy "
            "Diffie-Hellman group for this IPsec definition.",
            "Consider stronger DH groups where they are supported by both "
            "VPN peers.",
            evidence,
        )
    ]


def _is_ikev1(value: object) -> bool:
    values = " ".join(_values(value)).casefold()
    if not values:
        return False
    return "1" in re.findall(r"\d+", values)


def _is_all_network_selector(value: object) -> bool:
    """Recognize explicit IPv4/IPv6 all-network selector forms."""
    values = [item.strip().casefold() for item in _values(value) if item.strip()]
    if not values:
        return False
    joined = " ".join(values)
    return joined in {
        "0.0.0.0 0.0.0.0",
        "0.0.0.0/0",
        "::/0",
        "0:0:0:0:0:0:0:0/0",
    }


def _vpn_health_checks(config: dict) -> list[dict]:
    """Run static IPsec relationship and configuration-strength checks."""
    checks: list[dict] = []
    phase1_objects = [
        phase
        for phase in config.get("ipsec_phase1", [])
        if isinstance(phase, dict)
    ]
    phase2_objects = [
        phase
        for phase in config.get("ipsec_phase2", [])
        if isinstance(phase, dict)
    ]
    phase1_names = {
        (
            str(phase.get("vdom")).casefold()
            if phase.get("vdom") is not None
            else None,
            str(phase.get("name", "")).casefold(),
        )
        for phase in phase1_objects
        if phase.get("name") is not None
    }

    for phase in phase1_objects:
        checks.extend(_legacy_crypto_check(phase, "Phase 1"))
        checks.extend(_legacy_dh_check(phase, "Phase 1"))

        if _is_ikev1(phase.get("ike-version")):
            checks.append(
                _result(
                    "VPN / IPsec",
                    "LOW",
                    "IKEv1 Configuration Detected",
                    "The current backup explicitly configures IKEv1 for this "
                    "IPsec Phase 1 definition. This is a modernization review "
                    "item, not a claim that the VPN is insecure.",
                    "Consider IKEv2 for new deployments when it is compatible "
                    "with both VPN peers.",
                    _phase1_evidence(phase)
                    + [
                        f"Configured IKE version: "
                        f"{_proposal_text(phase.get('ike-version'))}"
                    ],
                )
            )

    for phase in phase2_objects:
        phase1_name = _first(phase.get("phase1name"), "")
        phase_vdom = (
            str(phase.get("vdom")).casefold()
            if phase.get("vdom") is not None
            else None
        )
        if phase1_name and (phase_vdom, phase1_name.casefold()) not in phase1_names:
            checks.append(
                _result(
                    "VPN / IPsec",
                    "MEDIUM",
                    "IPsec Phase 2 References Unknown Phase 1",
                    "The current parser found a Phase 2 definition whose "
                    "referenced Phase 1 definition could not be resolved.",
                    "Review the Phase 2 parent reference and confirm that the "
                    "relevant Phase 1 section is present in the backup.",
                    [
                        f"VDOM: {_first(phase.get('vdom'), 'global')}",
                        f"Phase 2 name: {_first(phase.get('name'), 'Unnamed')}",
                        f"Referenced Phase 1 name: {phase1_name}",
                    ],
                )
            )

        checks.extend(_legacy_crypto_check(phase, "Phase 2"))
        checks.extend(_legacy_dh_check(phase, "Phase 2"))

        if _normalized(phase.get("pfs")) & DISABLED_VALUES:
            checks.append(
                _result(
                    "VPN / IPsec",
                    "LOW",
                    "Perfect Forward Secrecy Disabled",
                    "Perfect Forward Secrecy is explicitly disabled for this "
                    "Phase 2 definition. This may be intentional for peer "
                    "compatibility.",
                    "Review whether PFS can be enabled to provide stronger key "
                    "separation while remaining compatible with both peers.",
                    _phase2_evidence(phase)
                    + [f"Explicit PFS value: {_first(phase.get('pfs'))}"],
                )
            )

        source_is_broad = _is_all_network_selector(
            phase.get("src-subnet")
        ) or "all" in _normalized(phase.get("src-name"))
        destination_is_broad = _is_all_network_selector(
            phase.get("dst-subnet")
        ) or "all" in _normalized(phase.get("dst-name"))
        if source_is_broad and destination_is_broad:
            checks.append(
                _result(
                    "VPN / IPsec",
                    "MEDIUM",
                    "Broad IPsec Traffic Selectors",
                    "The current backup configures all-network selectors in "
                    "both directions for this Phase 2 definition. Broad "
                    "selectors may be intentional for route-based VPN designs.",
                    "Review the selectors in the context of the VPN design and "
                    "confirm that their scope is intentional.",
                    _phase2_evidence(phase)
                    + [
                        "Source selector: "
                        + _proposal_text(
                            phase.get("src-subnet") or phase.get("src-name")
                        ),
                        "Destination selector: "
                        + _proposal_text(
                            phase.get("dst-subnet") or phase.get("dst-name")
                        ),
                    ],
                )
            )

    return checks


def _legacy_tls_versions(value: object) -> list[str]:
    """Return only explicitly configured legacy administrative TLS tokens."""
    legacy_aliases = {
        "ssl-v3",
        "sslv3",
        "ssl3",
        "tls-v1.0",
        "tls-v1-0",
        "tlsv1.0",
        "tlsv1-0",
        "tls1.0",
        "tls-v1.1",
        "tls-v1-1",
        "tlsv1.1",
        "tlsv1-1",
        "tls1.1",
    }
    detected: list[str] = []
    for item in _values(value):
        for token in re.split(r"[\s,]+", item):
            normalized = token.strip().casefold().replace("_", "-")
            if normalized in legacy_aliases and token not in detected:
                detected.append(token)
    return detected


def _administrator_security_checks(config: dict) -> list[dict]:
    """Check explicit administrator and administrative-service settings."""
    checks: list[dict] = []
    admins = config.get("admins", [])
    if isinstance(admins, list):
        for admin in admins:
            if not isinstance(admin, dict) or _is_disabled(admin):
                continue
            if "disable" not in _normalized(admin.get("two-factor")):
                continue
            checks.append(
                _scoped_result(
                    _result(
                        "Administrative Security",
                        "MEDIUM",
                        "Two-Factor Authentication Disabled for Administrator",
                        "Two-factor authentication is explicitly disabled for "
                        "this enabled administrator. This may be intentional, "
                        "but the account should be reviewed in context.",
                        "Review whether two-factor authentication can be enabled "
                        "for this administrator account.",
                        [
                            f"Administrator: {_first(admin.get('name'), 'Unnamed')}",
                            f"Access profile: {_first(admin.get('accprofile'))}",
                            f"two-factor: {_first(admin.get('two-factor'))}",
                        ],
                    ),
                    admin,
                )
            )

    system_global = config.get("system_global", {})
    if not isinstance(system_global, dict):
        return checks

    idle_timeout = _numeric_value(system_global.get("admintimeout"))
    if idle_timeout is not None and idle_timeout > 30:
        checks.append(
            _result(
                "Administrative Security",
                "LOW",
                "Long Administrator Idle Timeout",
                "The configured GUI/SSH administrator idle timeout exceeds "
                "the conservative 30-minute review threshold.",
                "Review the administrator idle timeout against operational "
                "requirements and shorten it where practical.",
                [f"admintimeout: {_first(system_global.get('admintimeout'))}"],
            )
        )

    if "enable" in _normalized(system_global.get("admin-telnet")):
        checks.append(
            _result(
                "Administrative Security",
                "HIGH",
                "Telnet Administration Enabled",
                "Telnet administration is explicitly enabled globally. Telnet "
                "does not provide encrypted administrative transport.",
                "Disable Telnet administration and use an encrypted management "
                "protocol where operationally possible.",
                ["admin-telnet: enable"],
            )
        )

    if "disable" in _normalized(system_global.get("admin-https-redirect")):
        checks.append(
            _result(
                "Administrative Security",
                "LOW",
                "HTTP-to-HTTPS Administrative Redirect Disabled",
                "The administrative HTTP-to-HTTPS redirect is explicitly "
                "disabled. This does not by itself prove that HTTP management "
                "is exposed.",
                "Review the intended management-access workflow and confirm "
                "that administrators use HTTPS directly.",
                ["admin-https-redirect: disable"],
            )
        )
    return checks


def _password_policy_checks(config: dict) -> list[dict]:
    """Check only explicit administrator password-policy settings."""
    checks: list[dict] = []
    for policy in _settings_blocks(
        config, "password_policies", "password_policy"
    ):
        status = _normalized(policy.get("status"))
        evidence = [
            f"VDOM: {_first(policy.get('vdom'), 'global')}",
            f"status: {_first(policy.get('status'))}",
        ]
        if status & DISABLED_VALUES:
            checks.append(
                _scoped_result(
                    _result(
                        "Administrative Security",
                        "MEDIUM",
                        "Administrator Password Policy Disabled",
                        "The administrator password policy is explicitly disabled "
                        "in the parsed configuration.",
                        "Review whether an administrator password policy should "
                        "be enabled based on organizational requirements.",
                        evidence,
                    ),
                    policy,
                )
            )
            continue

        minimum_length = _numeric_value(policy.get("minimum-length"))
        if "enable" in status and minimum_length is not None and minimum_length < 12:
            checks.append(
                _scoped_result(
                    _result(
                        "Administrative Security",
                        "LOW",
                        "Short Administrator Password Minimum Length",
                        "The enabled administrator password policy explicitly "
                        "sets a minimum length below the conservative 12-character "
                        "review threshold.",
                        "Review the minimum password length against organizational "
                        "authentication requirements.",
                        evidence
                        + [
                            "minimum-length: "
                            + _first(policy.get("minimum-length"))
                        ],
                    ),
                    policy,
                )
            )
    return checks


def _audit_logging_checks(config: dict) -> list[dict]:
    """Check explicit CLI-audit and implicit-policy logging settings."""
    checks: list[dict] = []
    system_global = config.get("system_global", {})
    if isinstance(system_global, dict) and "disable" in _normalized(
        system_global.get("cli-audit-log")
    ):
        checks.append(
            _result(
                "Logging",
                "MEDIUM",
                "CLI Audit Logging Disabled",
                "CLI audit logging is explicitly disabled, which may reduce "
                "visibility into administrative configuration activity.",
                "Review whether CLI audit logging should be enabled for "
                "administrative accountability and investigations.",
                ["cli-audit-log: disable"],
            )
        )

    for settings in _settings_blocks(config, "log_settings", "log_setting"):
        if "disable" not in _normalized(settings.get("implicit-log")):
            continue
        checks.append(
            _scoped_result(
                _result(
                    "Logging",
                    "LOW",
                    "Implicit Policy Logging Disabled",
                    "Implicit policy logging is explicitly disabled. This may "
                    "be intentional, but it can reduce visibility into traffic "
                    "handled by the implicit policy.",
                    "Review whether implicit-policy logging is appropriate for "
                    "the environment and expected traffic volume.",
                    [
                        f"VDOM: {_first(settings.get('vdom'), 'global')}",
                        "implicit-log: disable",
                    ],
                ),
                settings,
            )
        )
    return checks


def _policy_operational_checks(config: dict) -> list[dict]:
    """Report explicit policy packet-capture and offload operational settings."""
    checks: list[dict] = []
    policies = config.get("policies", [])
    if not isinstance(policies, list):
        return checks
    for policy in policies:
        if not isinstance(policy, dict) or _is_disabled(policy):
            continue
        evidence = [
            f"VDOM: {_first(policy.get('vdom'), 'global')}",
            f"Policy ID: {_first(policy.get('id'), 'Unknown')}",
            f"Policy name: {_first(policy.get('name'), 'Unnamed Policy')}",
        ]
        if "enable" in _normalized(policy.get("capture-packet")):
            result = _result(
                "Configuration Hygiene",
                "LOW",
                "Packet Capture Enabled on Firewall Policy",
                "Packet capture is explicitly enabled on this firewall policy. "
                "Persistent capture should be reviewed for operational and "
                "storage implications.",
                "Confirm that packet capture is still required and disable it "
                "after troubleshooting or monitoring needs are complete.",
                evidence + ["capture-packet: enable"],
            )
            result.update(
                {
                    "policy_id": policy.get("id"),
                    "policy_name": policy.get("name") or "Unnamed Policy",
                }
            )
            checks.append(_scoped_result(result, policy))

        if "disable" in _normalized(policy.get("auto-asic-offload")):
            result = _result(
                "Operational Review",
                "INFO",
                "Hardware Offload Disabled on Firewall Policy",
                "Hardware acceleration is explicitly disabled on this firewall "
                "policy. This is an operational observation, not a vulnerability.",
                "Review whether disabling hardware offload is still required "
                "for troubleshooting or feature compatibility.",
                evidence + ["auto-asic-offload: disable"],
            )
            result.update(
                {
                    "policy_id": policy.get("id"),
                    "policy_name": policy.get("name") or "Unnamed Policy",
                }
            )
            checks.append(_scoped_result(result, policy))
    return checks


def _inspection_fail_open_checks(config: dict) -> list[dict]:
    """Check explicit antivirus and IPS fail-open behavior."""
    checks: list[dict] = []
    av_enabled_values = {"enable", "enabled", "yes", "pass", "one-shot"}
    for settings in _settings_blocks(
        config, "antivirus_settings", "antivirus_setting"
    ):
        configured_field = None
        configured_value = ""
        for field in ("av-failopen", "fail-open"):
            values = _normalized(settings.get(field))
            if values & av_enabled_values:
                configured_field = field
                configured_value = _first(settings.get(field))
                break
        if configured_field is None:
            continue
        checks.append(
            _scoped_result(
                _result(
                    "Security Profiles",
                    "MEDIUM",
                    "Antivirus Fail-Open Behavior Enabled",
                    "Antivirus settings explicitly indicate fail-open behavior. "
                    "Depending on FortiOS behavior and configuration, traffic "
                    "may continue when antivirus inspection cannot complete.",
                    "Review the fail-open requirement and confirm that the "
                    "configured behavior matches the organization's risk tolerance.",
                    [
                        f"VDOM: {_first(settings.get('vdom'), 'global')}",
                        f"{configured_field}: {configured_value}",
                    ],
                ),
                settings,
            )
        )

    for settings in _settings_blocks(config, "ips_globals", "ips_global"):
        if "enable" not in _normalized(settings.get("fail-open")):
            continue
        checks.append(
            _scoped_result(
                _result(
                    "Security Profiles",
                    "MEDIUM",
                    "IPS Fail-Open Behavior Enabled",
                    "IPS fail-open behavior is explicitly enabled. Depending on "
                    "FortiOS behavior, traffic may continue when IPS inspection "
                    "cannot complete.",
                    "Review whether IPS fail-open behavior is required and "
                    "appropriate for the protected traffic.",
                    [
                        f"VDOM: {_first(settings.get('vdom'), 'global')}",
                        "fail-open: enable",
                    ],
                ),
                settings,
            )
        )
    return checks


def _system_hardening_checks(config: dict) -> list[dict]:
    """Check explicit system-global administrative hardening settings."""
    checks: list[dict] = []
    system_global = config.get("system_global", {})
    if not isinstance(system_global, dict):
        return checks

    if "enable" in _normalized(system_global.get("admin-ssh-v1")):
        checks.append(
            _result(
                "System Hardening",
                "HIGH",
                "SSH Version 1 Enabled for Administration",
                "SSH version 1 is explicitly enabled for administration in "
                "the current backup. SSHv1 is obsolete and should be reviewed.",
                "Disable administrative SSHv1 support unless a documented "
                "compatibility requirement still exists.",
                ["admin-ssh-v1: enable"],
            )
        )

    legacy_tls = _legacy_tls_versions(
        system_global.get("admin-https-ssl-versions")
    )
    if legacy_tls:
        checks.append(
            _result(
                "System Hardening",
                "MEDIUM",
                "Legacy TLS Version Enabled for Administrative HTTPS",
                "The backup explicitly enables one or more legacy TLS/SSL "
                "versions for administrative HTTPS access.",
                "Review administrative HTTPS compatibility requirements and "
                "disable legacy protocol versions where possible.",
                ["Detected legacy versions: " + ", ".join(legacy_tls)],
            )
        )

    if "disable" in _normalized(system_global.get("strong-crypto")):
        checks.append(
            _result(
                "System Hardening",
                "MEDIUM",
                "Strong Cryptography Mode Disabled",
                "Strong cryptography mode is explicitly disabled in the "
                "current backup. This setting should be reviewed in the "
                "context of FortiOS version and compatibility requirements.",
                "Review whether strong cryptography mode can be enabled for "
                "the deployed FortiOS version and connected systems.",
                ["strong-crypto: disable"],
            )
        )

    timeout_value = _first(system_global.get("admin-console-timeout"), "")
    try:
        timeout_minutes = float(timeout_value)
    except (TypeError, ValueError):
        timeout_minutes = 0
    if timeout_minutes > 30:
        checks.append(
            _result(
                "System Hardening",
                "LOW",
                "Long Administrative Session Timeout",
                "The explicitly configured administrative console timeout is "
                "longer than the conservative 30-minute review threshold. "
                "Long idle sessions may increase exposure on unattended "
                "management sessions.",
                "Review the timeout against operational needs and consider a "
                "shorter idle-session limit where practical.",
                [f"admin-console-timeout: {timeout_value} minutes"],
            )
        )

    return checks


def _ntp_health_checks(config: dict) -> list[dict]:
    """Check only explicit NTP synchronization configuration."""
    ntp = config.get("ntp", {})
    if not isinstance(ntp, dict) or not ntp.get("_configured"):
        return []

    input_assessment = (
        config.get("input_assessment")
        if isinstance(config.get("input_assessment"), dict)
        else None
    )
    if input_assessment is None:
        try:
            from .parser import assess_input_quality
        except ImportError:
            from parser import assess_input_quality
        input_assessment = assess_input_quality("", config)

    classification = input_assessment.get("classification", "UNKNOWN")
    is_full_backup = classification == "LIKELY_FULL_BACKUP"

    sync_values = _normalized(ntp.get("ntpsync"))
    if sync_values & DISABLED_VALUES:
        return [
            _result(
                "Time Synchronization",
                "MEDIUM",
                "NTP Synchronization Disabled",
                "NTP synchronization is explicitly disabled in the backup. "
                "Accurate time supports logs, event correlation, certificate "
                "handling, and incident investigation.",
                "Review whether NTP synchronization should be enabled and "
                "configured for the environment.",
                [f"ntpsync: {_first(ntp.get('ntpsync'))}"],
            )
        ]

    if "enable" not in sync_values:
        return []

    # NTP is enabled. Check if custom NTP servers are configured.
    servers = ntp.get("servers", [])
    configured_servers = (
        [
            _first(server.get("server"), "")
            for server in servers
            if isinstance(server, dict) and _first(server.get("server"), "")
        ]
        if isinstance(servers, list)
        else []
    )
    if configured_servers:
        return []

    # Check documented default inference for ntp.type
    explicit_type = _first(ntp.get("type"), "")
    default_inference = infer_field_default(
        config, "ntp", "type", explicit_type or None
    )

    # 1. Documented default applied:
    # A documented default is not itself a security finding.
    # It is recorded in documented_defaults, NOT as a security check.
    if (
        default_inference.get("applicable")
        and default_inference.get("effective_value") == "fortiguard"
    ):
        return []

    # 2. Insufficient input must not create a security finding
    # If NTP cannot be assessed because input is partial, empty, unrecognized,
    # or truncated, do not create an NTP security finding.
    if not is_full_backup:
        return []

    # 3. Unknown FortiOS version alone must not create a security finding
    fortios = input_assessment.get("fortios", {})
    if not fortios.get("detected") or fortios.get("major") is None:
        return []

    # 4. Genuine NTP ambiguity with sufficient source context:
    # In a full backup, ntpsync is explicitly enabled, type is explicitly "custom",
    # but no NTP servers were configured.
    if explicit_type.casefold() == "custom" and not configured_servers:
        return [
            _result(
                "Time Synchronization",
                "LOW",
                "NTP Server Configuration Could Not Be Confirmed",
                "NTP synchronization is explicitly enabled with custom type, "
                "but no NTP servers were configured in the supplied configuration.",
                "Configure one or more custom NTP servers under config system ntp "
                "or adjust synchronization type to match deployment requirements.",
                [
                    f"ntpsync: {_first(ntp.get('ntpsync'))}",
                    "NTP type: custom",
                    "Configured NTP servers: none",
                ],
            )
        ]

    return []


def _dns_health_checks(config: dict) -> list[dict]:
    """Report only an explicitly present DNS block with no parsed servers."""
    dns = config.get("dns", {})
    if not isinstance(dns, dict) or not dns.get("_configured"):
        return []
    configured_servers = _values(dns.get("primary")) + _values(
        dns.get("secondary")
    )
    if any(server.strip() for server in configured_servers):
        return []
    return [
        _result(
            "DNS",
            "LOW",
            "DNS Server Configuration Could Not Be Confirmed",
            "An explicit system DNS configuration block was detected, but "
            "neither a primary nor secondary DNS server could be confirmed "
            "from the parsed fields.",
            "Review the DNS configuration in the context of FortiOS defaults "
            "and the intended interface or provisioning method.",
            [
                "Explicit config system dns block: detected",
                "Primary DNS: not detected",
                "Secondary DNS: not detected",
            ],
        )
    ]


def run_health_check(
    config: dict,
    analysis_result: dict | None = None,
) -> dict:
    """Run FortiGate Configuration Health Check v4."""
    if analysis_result is None:
        analysis_result = analyze_configuration(config)

    checks: list[dict] = []
    management_checks, wan_management = _wan_management_checks(
        config.get("interfaces", []), config.get("ipsec_phase1", [])
    )
    checks.extend(management_checks)
    checks.extend(
        _administrator_trust_check(config.get("admins", []), wan_management)
    )
    checks.extend(_administrator_security_checks(config))
    checks.extend(_password_policy_checks(config))
    checks.extend(_audit_logging_checks(config))
    checks.extend(_security_profile_consistency_checks(config, analysis_result))
    checks.extend(_policy_health_checks(config, analysis_result))
    checks.extend(_policy_operational_checks(config))
    checks.extend(_disabled_policy_check(config.get("policies", [])))
    checks.extend(_configuration_integrity_check(config, analysis_result))
    checks.extend(_vpn_health_checks(config))
    checks.extend(_inspection_fail_open_checks(config))
    checks.extend(_system_hardening_checks(config))
    checks.extend(_ntp_health_checks(config))
    checks.extend(_dns_health_checks(config))

    input_assessment = (
        config.get("input_assessment")
        or (analysis_result.get("input_assessment") if isinstance(analysis_result, dict) else None)
        or {}
    )

    documented_defaults = (
        analysis_result.get("documented_defaults")
        if isinstance(analysis_result, dict) and "documented_defaults" in analysis_result
        else collect_applied_defaults(config)
    )

    summary = {"high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for check in checks:
        severity = str(check.get("severity", "")).casefold()
        if severity in summary and severity != "total":
            summary[severity] += 1
    summary["total"] = len(checks)
    return {
        "checks": checks,
        "summary": summary,
        "input_assessment": input_assessment,
        "documented_defaults": documented_defaults,
    }
