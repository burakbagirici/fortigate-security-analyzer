"""Centralized, conservative FortiOS version-aware defaults engine.

Preserves three distinct layers:
1. Explicit configuration fact (unmodified from parsed config)
2. Documented version-aware default inference (only for explicitly verified branches)
3. Technical/effective interpretation (explicit value always wins)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DefaultRule:
    rule_id: str
    section_key: str
    field_name: str
    default_value: Any
    verified_branches: frozenset[tuple[int, int]]
    branch_docs: dict[tuple[int, int], str]
    description: str


# Officially verified rules with branch-specific Fortinet documentation citations
VERIFIED_RULES: list[DefaultRule] = [
    DefaultRule(
        rule_id="system_ntp.type",
        section_key="ntp",
        field_name="type",
        default_value="fortiguard",
        verified_branches=frozenset({(7, 0), (7, 2), (7, 4)}),
        branch_docs={
            (7, 0): "FortiOS 7.0 CLI Reference: config system ntp -> set type {fortiguard | custom} (default: fortiguard)",
            (7, 2): "FortiOS 7.2 CLI Reference: config system ntp -> set type {fortiguard | custom} (default: fortiguard)",
            (7, 4): "FortiOS 7.4 CLI Reference: config system ntp -> set type {fortiguard | custom} (default: fortiguard)",
        },
        description="NTP synchronization type defaults to FortiGuard public NTP servers.",
    ),
    DefaultRule(
        rule_id="system_global.admintimeout",
        section_key="system_global",
        field_name="admintimeout",
        default_value="5",
        verified_branches=frozenset({(7, 0), (7, 2), (7, 4)}),
        branch_docs={
            (7, 0): "FortiOS 7.0 CLI Reference: config system global -> set admintimeout <integer> (default: 5)",
            (7, 2): "FortiOS 7.2 CLI Reference: config system global -> set admintimeout <integer> (default: 5)",
            (7, 4): "FortiOS 7.4 CLI Reference: config system global -> set admintimeout <integer> (default: 5)",
        },
        description="Administrative console idle timeout defaults to 5 minutes.",
    ),
    DefaultRule(
        rule_id="system_global.admin_sport",
        section_key="system_global",
        field_name="admin-sport",
        default_value="443",
        verified_branches=frozenset({(7, 0), (7, 2), (7, 4)}),
        branch_docs={
            (7, 0): "FortiOS 7.0 CLI Reference: config system global -> set admin-sport <integer> (default: 443)",
            (7, 2): "FortiOS 7.2 CLI Reference: config system global -> set admin-sport <integer> (default: 443)",
            (7, 4): "FortiOS 7.4 CLI Reference: config system global -> set admin-sport <integer> (default: 443)",
        },
        description="HTTPS administrative port defaults to 443.",
    ),
    DefaultRule(
        rule_id="system_global.admin_port",
        section_key="system_global",
        field_name="admin-port",
        default_value="80",
        verified_branches=frozenset({(7, 0), (7, 2), (7, 4)}),
        branch_docs={
            (7, 0): "FortiOS 7.0 CLI Reference: config system global -> set admin-port <integer> (default: 80)",
            (7, 2): "FortiOS 7.2 CLI Reference: config system global -> set admin-port <integer> (default: 80)",
            (7, 4): "FortiOS 7.4 CLI Reference: config system global -> set admin-port <integer> (default: 80)",
        },
        description="HTTP administrative port defaults to 80.",
    ),
    DefaultRule(
        rule_id="system_global.admin_ssh_port",
        section_key="system_global",
        field_name="admin-ssh-port",
        default_value="22",
        verified_branches=frozenset({(7, 0), (7, 2), (7, 4)}),
        branch_docs={
            (7, 0): "FortiOS 7.0 CLI Reference: config system global -> set admin-ssh-port <integer> (default: 22)",
            (7, 2): "FortiOS 7.2 CLI Reference: config system global -> set admin-ssh-port <integer> (default: 22)",
            (7, 4): "FortiOS 7.4 CLI Reference: config system global -> set admin-ssh-port <integer> (default: 22)",
        },
        description="SSH administrative port defaults to 22.",
    ),
]


RULE_INDEX: dict[tuple[str, str], DefaultRule] = {
    (rule.section_key, rule.field_name): rule for rule in VERIFIED_RULES
}


def get_rule(section_key: str, field_name: str) -> DefaultRule | None:
    """Return the registered default rule for a given section and field, if any."""
    return RULE_INDEX.get((section_key, field_name))


def infer_field_default(
    config: dict,
    section_key: str,
    field_name: str,
    explicit_value: Any = None,
) -> dict:
    """Infer a documented FortiOS default value strictly when all conditions are verified.

    Gating conditions:
    1. Explicit value ALWAYS wins (status=EXPLICIT_VALUE).
    2. Input must be LIKELY_FULL_BACKUP (partial input does not infer defaults from absence).
    3. The relevant configuration section must be present in the supplied input.
    4. FortiOS version must be detected.
    5. The FortiOS (major, minor) branch must be in the rule's verified_branches.
    """
    rule = get_rule(section_key, field_name)

    input_assessment = config.get("input_assessment", {})
    if not isinstance(input_assessment, dict):
        try:
            from .parser import assess_input_quality
        except ImportError:
            from parser import assess_input_quality
        input_assessment = assess_input_quality("", config)

    fortios = input_assessment.get("fortios", {})
    version_str = fortios.get("version", "unknown")
    major = fortios.get("major")
    minor = fortios.get("minor")

    # 1. Explicit value always wins
    has_explicit = explicit_value is not None and str(explicit_value).strip() != ""
    if has_explicit:
        return {
            "applicable": False,
            "status": "EXPLICIT_VALUE",
            "explicit_value": explicit_value,
            "effective_value": explicit_value,
            "value_source": "EXPLICIT_CONFIG",
            "rule_id": rule.rule_id if rule else None,
            "fortios_version": version_str,
            "documentation": None,
            "reason": "Explicit configuration value was provided and takes precedence over defaults.",
            "explicitly_configured": True,
        }

    # 2. Rule existence check
    if rule is None:
        return {
            "applicable": False,
            "status": "DEFAULT_NOT_APPLICABLE",
            "explicit_value": None,
            "effective_value": None,
            "value_source": "UNSPECIFIED",
            "rule_id": None,
            "fortios_version": version_str,
            "documentation": None,
            "reason": f"No documented default rule is registered for '{section_key}.{field_name}'.",
            "explicitly_configured": False,
        }

    # 3. Input classification & quality gating
    classification = input_assessment.get("classification", "UNKNOWN")
    if classification in ("EMPTY_INPUT", "UNRECOGNIZED_INPUT"):
        return {
            "applicable": False,
            "status": "INPUT_SCOPE_INSUFFICIENT",
            "explicit_value": None,
            "effective_value": None,
            "value_source": "UNSPECIFIED",
            "rule_id": rule.rule_id,
            "fortios_version": "unknown",
            "documentation": None,
            "reason": f"Input classification is '{classification}'; absence-based defaults cannot be inferred.",
            "explicitly_configured": False,
        }

    # 4. Section presence check
    section_presence = input_assessment.get("section_presence", {})
    # Map section_key if necessary
    presence_key = "system_global" if section_key == "system_global" else section_key
    if not section_presence.get(presence_key, False):
        # Also check if config has the block directly
        raw_block = config.get(section_key)
        has_block = bool(raw_block) if isinstance(raw_block, (dict, list)) else False
        if not has_block:
            return {
                "applicable": False,
                "status": "SECTION_NOT_SUPPLIED",
                "explicit_value": None,
                "effective_value": None,
                "value_source": "UNSPECIFIED",
                "rule_id": rule.rule_id,
                "fortios_version": version_str,
                "documentation": None,
                "reason": f"Configuration section '{section_key}' was not observed in supplied input.",
                "explicitly_configured": False,
            }

    # A PARTIAL_CONFIGURATION must not receive a default inference merely because a field is absent
    if classification != "LIKELY_FULL_BACKUP":
        return {
            "applicable": False,
            "status": "INPUT_SCOPE_INSUFFICIENT",
            "explicit_value": None,
            "effective_value": None,
            "value_source": "UNSPECIFIED",
            "rule_id": rule.rule_id,
            "fortios_version": version_str,
            "documentation": None,
            "reason": f"Input classification is '{classification}'; absence-based defaults are only inferred for LIKELY_FULL_BACKUP.",
            "explicitly_configured": False,
        }

    # 5. Version detection check
    if not fortios.get("detected") or major is None or minor is None:
        return {
            "applicable": False,
            "status": "VERSION_UNKNOWN",
            "explicit_value": None,
            "effective_value": None,
            "value_source": "UNSPECIFIED",
            "rule_id": rule.rule_id,
            "fortios_version": "unknown",
            "documentation": None,
            "reason": "FortiOS configuration version header is unknown or not detected.",
            "explicitly_configured": False,
        }

    # 6. Branch verification check
    branch = (major, minor)
    if branch not in rule.verified_branches:
        return {
            "applicable": False,
            "status": "UNSUPPORTED_VERSION",
            "explicit_value": None,
            "effective_value": None,
            "value_source": "UNSPECIFIED",
            "rule_id": rule.rule_id,
            "fortios_version": version_str,
            "documentation": None,
            "reason": f"FortiOS branch {major}.{minor} has not been individually verified for {rule.rule_id}.",
            "explicitly_configured": False,
        }

    # 7. Documented default applied
    doc_ref = rule.branch_docs.get(branch, rule.description)
    return {
        "applicable": True,
        "status": "DOCUMENTED_DEFAULT_APPLIED",
        "explicit_value": None,
        "effective_value": rule.default_value,
        "value_source": "DOCUMENTED_DEFAULT",
        "rule_id": rule.rule_id,
        "fortios_version": version_str,
        "documentation": doc_ref,
        "reason": f"Field '{field_name}' omitted in {section_key}; verified FortiOS {major}.{minor} documented default applies.",
        "explicitly_configured": False,
    }


def collect_applied_defaults(config: dict) -> list[dict]:
    """Evaluate all registered default rules and return those that successfully apply.

    A documented default is configuration/default metadata and interpretation,
    not a security finding.
    """
    applied = []
    for rule in VERIFIED_RULES:
        section = config.get(rule.section_key)
        explicit_value = None
        if isinstance(section, dict):
            explicit_value = section.get(rule.field_name)

        res = infer_field_default(
            config, rule.section_key, rule.field_name, explicit_value
        )
        if res.get("applicable") and res.get("status") == "DOCUMENTED_DEFAULT_APPLIED":
            applied.append(
                {
                    "section": rule.section_key,
                    "field": rule.field_name,
                    "effective_value": res["effective_value"],
                    "value_source": "DOCUMENTED_DEFAULT",
                    "rule_id": res["rule_id"],
                    "fortios_version": res["fortios_version"],
                    "documentation": res["documentation"],
                    "explicitly_configured": False,
                    "reason": res["reason"],
                }
            )
    return applied
