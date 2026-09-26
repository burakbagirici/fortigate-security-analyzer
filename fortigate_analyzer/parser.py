"""Lightweight parsers for selected FortiGate configuration sections."""

from __future__ import annotations

import re
import shlex


LIST_FIELDS = {
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "srcaddr6",
    "dstaddr6",
    "service",
    # Internet Service selectors are lists in FortiOS, even when a backup
    # contains only one value.  Enable/negate flags deliberately remain scalar.
    "internet-service-id",
    "internet-service-name",
    "internet-service-group",
    "internet-service-custom",
    "internet-service-custom-group",
    "internet-service-fortiguard",
    "internet-service-src-id",
    "internet-service-src-name",
    "internet-service-src-group",
    "internet-service-src-custom",
    "internet-service-src-custom-group",
    "internet-service-src-fortiguard",
}


def _split_line(line: str) -> list[str]:
    """Split a FortiGate configuration line while respecting quoted values."""
    if '"' not in line and "'" not in line and "\\" not in line:
        return line.split()
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        # A malformed quoted value should not prevent other policies from parsing.
        return []


def _policy_id(raw_id: str) -> int | str:
    """Return numeric policy IDs as integers, preserving unusual IDs as text."""
    try:
        return int(raw_id)
    except ValueError:
        return raw_id


def _annotated_config_lines(
    config_text: str,
) -> list[tuple[list[str], str | None]]:
    """Tokenize configuration lines and attach their active VDOM context."""
    annotated: list[tuple[list[str], str | None]] = []
    config_stack: list[tuple[str, ...]] = []
    active_vdom: str | None = None
    vdom_section = ("config", "vdom")

    for raw_line in config_text.splitlines():
        tokens = _split_line(raw_line.strip())
        if not tokens:
            continue
        normalized = tuple(token.casefold() for token in tokens)
        command = normalized[0]

        if (
            command == "edit"
            and len(tokens) >= 2
            and config_stack
            and config_stack[-1] == vdom_section
        ):
            active_vdom = tokens[1]

        annotated.append((tokens, active_vdom))

        if command == "config":
            config_stack.append(normalized)
        elif command == "next" and config_stack and config_stack[-1] == vdom_section:
            active_vdom = None
        elif command == "end" and config_stack:
            ended_section = config_stack.pop()
            if ended_section == vdom_section:
                active_vdom = None

    return annotated


def build_block_index(
    config_text: str,
) -> dict[tuple[str, ...], list[tuple[str | None, list[list[str]]]]]:
    """Single-pass structural block indexer mapping section targets to (vdom, body) blocks."""
    index: dict[tuple[str, ...], list[tuple[str | None, list[list[str]]]]] = {}
    annotated = _annotated_config_lines(config_text)
    line_index = 0
    total_lines = len(annotated)

    while line_index < total_lines:
        tokens, vdom = annotated[line_index]
        cmd = tokens[0].casefold()
        if cmd == "config" and len(tokens) > 1 and tokens[1].casefold() != "vdom":
            target = tuple(token.casefold() for token in tokens)
            body: list[list[str]] = []
            section_depth = 1
            line_index += 1
            while line_index < total_lines and section_depth:
                nested_tokens, _ = annotated[line_index]
                nested_cmd = nested_tokens[0].casefold()
                if nested_cmd == "config":
                    section_depth += 1
                elif nested_cmd == "end":
                    section_depth -= 1
                    if section_depth == 0:
                        line_index += 1
                        break
                body.append(nested_tokens)
                line_index += 1
            index.setdefault(target, []).append((vdom, body))
        else:
            line_index += 1

    return index


class ParserContext:
    """Shared parser state holding a single-pass structural block index."""

    def __init__(self, config_text: str):
        self.raw_text = config_text
        self.block_index = build_block_index(config_text)

    def get_sections(
        self, target: tuple[str, ...]
    ) -> list[tuple[str | None, list[list[str]]]]:
        normalized = tuple(token.casefold() for token in target)
        return self.block_index.get(normalized, [])

    def has_section(self, target: tuple[str, ...]) -> bool:
        normalized = tuple(token.casefold() for token in target)
        return normalized in self.block_index


def _matching_sections(
    config_text: str,
    section_name: tuple[str, ...],
    context: ParserContext | None = None,
) -> list[tuple[str | None, list[list[str]]]]:
    """Return every matching section body with its VDOM context."""
    if context is not None:
        return context.get_sections(section_name)
    return ParserContext(config_text).get_sections(section_name)


def _parse_named_section(
    config_text: str,
    section_name: tuple[str, ...],
    list_fields: set[str] | None = None,
    allowed_fields: set[str] | None = None,
    field_aliases: dict[str, str] | None = None,
    context: ParserContext | None = None,
) -> list[dict]:
    """Parse direct ``edit`` entries from every matching section."""
    objects: list[dict] = []
    normalized_list_fields = {
        field.casefold() for field in (list_fields or set())
    }
    normalized_allowed_fields = (
        {field.casefold() for field in allowed_fields}
        if allowed_fields is not None
        else None
    )
    normalized_aliases = {
        key.casefold(): value for key, value in (field_aliases or {}).items()
    }

    for vdom, section_lines in _matching_sections(
        config_text, section_name, context=context
    ):
        current_object: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()

            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                current_object = {"name": tokens[1], "vdom": vdom}
                continue
            if command == "next":
                if current_object is not None:
                    objects.append(current_object)
                    current_object = None
                continue
            if command != "set" or len(tokens) < 2 or current_object is None:
                continue

            key = tokens[1]
            normalized_key = key.casefold()
            if (
                normalized_allowed_fields is not None
                and normalized_key not in normalized_allowed_fields
            ):
                continue
            output_key = normalized_aliases.get(normalized_key, key)
            values = tokens[2:]
            if normalized_key in normalized_list_fields:
                current_object[output_key] = values
            elif len(values) > 1:
                current_object[output_key] = values
            else:
                current_object[output_key] = values[0] if values else ""

    return objects


def _parse_settings_section(
    config_text: str,
    section_name: tuple[str, ...],
    allowed_fields: set[str],
    include_presence: bool = False,
    context: ParserContext | None = None,
) -> dict:
    """Parse whitelisted direct settings from the first matching section."""
    settings: dict = {}
    allowed = {field.casefold() for field in allowed_fields}
    sections = _matching_sections(config_text, section_name, context=context)
    if not sections:
        return settings

    if include_presence:
        settings["_configured"] = True

    _, section_lines = sections[0]
    section_depth = 1
    for tokens in section_lines:
        command = tokens[0].casefold()
        if command == "config":
            section_depth += 1
            continue
        if command == "end":
            section_depth -= 1
            if section_depth == 0:
                break
            continue
        if section_depth != 1 or command != "set" or len(tokens) < 2:
            continue

        key = tokens[1]
        if key.casefold() not in allowed:
            continue
        values = tokens[2:]
        settings[key] = values if len(values) > 1 else (values[0] if values else "")

    return settings


def _parse_settings_sections(
    config_text: str,
    section_name: tuple[str, ...],
    allowed_fields: set[str],
    context: ParserContext | None = None,
) -> list[dict]:
    """Parse safe direct settings from every matching scoped section."""
    sections: list[dict] = []
    allowed = {field.casefold() for field in allowed_fields}
    for vdom, section_lines in _matching_sections(
        config_text, section_name, context=context
    ):
        settings: dict = {"vdom": vdom, "_configured": True}
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1 or command != "set" or len(tokens) < 2:
                continue
            key = tokens[1]
            if key.casefold() not in allowed:
                continue
            values = tokens[2:]
            settings[key] = (
                values if len(values) > 1 else (values[0] if values else "")
            )
        sections.append(settings)
    return sections


def _first_settings_section(sections: list[dict]) -> dict:
    """Return a global settings block first, then any available block."""
    return next(
        (section for section in sections if section.get("vdom") is None),
        sections[0] if sections else {},
    )


def parse_firewall_policies(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse policies from every ``config firewall policy`` section.

    Known FortiGate multi-value fields are always stored as lists. Other
    settings are stored as strings when they have zero or one value, and as
    lists when multiple values are present.
    """
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "policy"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                current_policy = {
                    "id": _policy_id(tokens[1]),
                    "sequence_index": sequence_index,
                    "vdom": vdom,
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    has_v6 = bool(
                        current_policy.get("srcaddr6")
                        or current_policy.get("dstaddr6")
                    )
                    has_v4 = bool(
                        current_policy.get("srcaddr")
                        or current_policy.get("dstaddr")
                    )
                    if has_v6 and has_v4:
                        current_policy["address_family"] = "MIXED_OR_AMBIGUOUS"
                    elif has_v6:
                        current_policy["address_family"] = "IPv6"
                    elif has_v4:
                        current_policy["address_family"] = "IPv4"
                    else:
                        current_policy["address_family"] = "UNKNOWN"
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            values = tokens[2:]
            if key.casefold() in LIST_FIELDS:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


def parse_interfaces(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse system interfaces, including role and addressing context."""
    return _parse_named_section(
        config_text,
        ("config", "system", "interface"),
        list_fields={"allowaccess"},
        field_aliases={"vdom": "configured_vdom"},
        context=context,
    )


def parse_zones(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse system zone definitions and their member interfaces."""
    zones = _parse_named_section(
        config_text,
        ("config", "system", "zone"),
        list_fields={"interface"},
        field_aliases={"vdom": "configured_vdom", "interface": "interfaces"},
        context=context,
    )
    for zone in zones:
        val = zone.get("interfaces")
        if val is None:
            zone["interfaces"] = []
        elif isinstance(val, list):
            zone["interfaces"] = val
        else:
            zone["interfaces"] = [str(val)]
    return zones


def parse_sdwan(
    config_text: str, context: ParserContext | None = None
) -> dict:
    """Parse SD-WAN configuration including zones and member interfaces."""
    all_zones: list[dict] = []
    all_members: list[dict] = []
    sdwan_info: dict = {"zones": all_zones, "members": all_members}

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "system", "sdwan"), context=context
    ):
        current_sub: str | None = None
        current_entry: dict | None = None
        section_depth = 1

        vdom_zones: dict[str, dict] = {}
        vdom_members: list[dict] = []

        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                if section_depth == 2 and len(tokens) >= 2:
                    current_sub = tokens[1].casefold()
                continue
            if command == "end":
                if section_depth == 2:
                    current_sub = None
                    current_entry = None
                section_depth -= 1
                continue

            if section_depth == 1 and command == "set" and len(tokens) >= 2:
                key = tokens[1].casefold()
                values = tokens[2:]
                sdwan_info[key] = values[0] if len(values) == 1 else values
                continue

            if section_depth == 2:
                if command == "edit" and len(tokens) >= 2:
                    entry_name = tokens[1]
                    if current_sub == "zone":
                        current_entry = {
                            "name": entry_name,
                            "vdom": vdom,
                            "interfaces": [],
                            "members": [],
                        }
                    elif current_sub == "members":
                        current_entry = {
                            "id": _policy_id(entry_name),
                            "vdom": vdom,
                            "interface": None,
                            "zone": "virtual-wan-link",
                            "gateway": None,
                        }
                    continue
                if command == "next":
                    if current_entry is not None:
                        if current_sub == "zone":
                            vdom_zones[current_entry["name"].casefold()] = current_entry
                        elif current_sub == "members":
                            vdom_members.append(current_entry)
                        current_entry = None
                    continue
                if command == "set" and len(tokens) >= 2 and current_entry is not None:
                    k = tokens[1].casefold()
                    val = tokens[2] if len(tokens) > 2 else ""
                    if current_sub == "members":
                        if k == "interface":
                            current_entry["interface"] = val
                        elif k == "zone":
                            current_entry["zone"] = val
                        elif k == "gateway":
                            current_entry["gateway"] = val
                        else:
                            current_entry[k] = tokens[2:] if len(tokens) > 3 else val
                    elif current_sub == "zone":
                        current_entry[k] = tokens[2:] if len(tokens) > 3 else val

        for m in vdom_members:
            zone_name = m.get("zone") or "virtual-wan-link"
            zone_key = zone_name.casefold()
            if zone_key not in vdom_zones:
                vdom_zones[zone_key] = {
                    "name": zone_name,
                    "vdom": vdom,
                    "interfaces": [],
                    "members": [],
                }
            intf = m.get("interface")
            if intf and intf not in vdom_zones[zone_key]["interfaces"]:
                vdom_zones[zone_key]["interfaces"].append(intf)
            vdom_zones[zone_key]["members"].append(m)

        all_zones.extend(vdom_zones.values())
        all_members.extend(vdom_members)

    return {
        "status": sdwan_info.get("status", "disable"),
        "zones": all_zones,
        "members": all_members,
    }


def parse_addresses(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse firewall address objects."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "address"),
        context=context,
    )


def parse_address_groups(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse firewall address groups with list-valued members."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "addrgrp"),
        list_fields={"member"},
        context=context,
    )


def parse_addresses6(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse IPv6 firewall address objects."""
    addresses = _parse_named_section(
        config_text,
        ("config", "firewall", "address6"),
        allowed_fields={
            "name",
            "ip6",
            "type",
            "start-ip",
            "end-ip",
            "fqdn",
            "associated-interface",
            "interface",
            "comment",
            "comments",
        },
        context=context,
    )
    for addr in addresses:
        addr["address_family"] = "IPv6"
    return addresses


def parse_address_groups6(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse IPv6 firewall address groups with list-valued members."""
    groups = _parse_named_section(
        config_text,
        ("config", "firewall", "addrgrp6"),
        list_fields={"member"},
        allowed_fields={"name", "member", "comment", "comments"},
        context=context,
    )
    for grp in groups:
        grp["address_family"] = "IPv6"
    return groups


def parse_custom_services(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse custom firewall service objects."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "service", "custom"),
        context=context,
    )


def parse_service_groups(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse firewall service groups with list-valued members."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "service", "group"),
        list_fields={"member"},
        context=context,
    )


def parse_vips(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse firewall virtual IP objects."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "vip"),
        context=context,
    )


def parse_vips6(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse IPv6 firewall virtual IP objects."""
    vips = _parse_named_section(
        config_text,
        ("config", "firewall", "vip6"),
        allowed_fields={
            "name",
            "extip",
            "mappedip",
            "extintf",
            "portforward",
            "protocol",
            "extport",
            "mappedport",
            "nat64",
            "nat66",
            "ipv4-mappedip",
            "type",
            "comment",
            "comments",
        },
        context=context,
    )
    for vip in vips:
        vip["address_family"] = "IPv6"
    return vips


def parse_internet_service_names(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe metadata exported for predefined Internet Service names."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "internet-service-name"),
        allowed_fields={
            "name",
            "internet-service-id",
            "type",
            "country-id",
            "region-id",
            "city-id",
        },
        field_aliases={"name": "display_name"},
        context=context,
    )


def parse_internet_service_groups(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse named predefined-ISDB groups without expanding their database."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "internet-service-group"),
        list_fields={"member"},
        allowed_fields={"member", "direction", "comment"},
        context=context,
    )


def parse_internet_service_customs(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe top-level metadata for locally defined Internet Services.

    Nested entries can contain address and port membership.  They are skipped
    intentionally: this MVP identifies and resolves the local object without
    claiming to reconstruct its complete traffic match set.
    """
    return _parse_named_section(
        config_text,
        ("config", "firewall", "internet-service-custom"),
        allowed_fields={"comment", "reputation"},
        context=context,
    )


def parse_internet_service_custom_groups(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse local custom Internet Service groups and member names."""
    return _parse_named_section(
        config_text,
        ("config", "firewall", "internet-service-custom-group"),
        list_fields={"member"},
        allowed_fields={"member", "comment"},
        context=context,
    )


def _parse_security_profile_section(
    config_text: str,
    section_name: tuple[str, ...],
    context: ParserContext | None = None,
) -> list[dict]:
    """Parse safe top-level security-profile metadata.

    Profile definitions commonly contain deeply nested rule blocks.  The
    generic named-section parser deliberately skips those blocks, and the
    whitelist prevents secret or certificate material from entering the
    configuration model.
    """
    return _parse_named_section(
        config_text,
        section_name,
        allowed_fields={"comment", "comments"},
        context=context,
    )


def parse_ips_sensors(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse IPS sensor names and safe descriptive metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "ips", "sensor"), context=context
    )


def parse_antivirus_profiles(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse antivirus profile names and safe descriptive metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "antivirus", "profile"), context=context
    )


def parse_webfilter_profiles(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse web-filter profile names and safe descriptive metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "webfilter", "profile"), context=context
    )


def parse_application_lists(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse application-control list names and safe metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "application", "list"), context=context
    )


def parse_ssl_ssh_profiles(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse SSL/SSH inspection profile names and safe metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "firewall", "ssl-ssh-profile"), context=context
    )


def parse_dnsfilter_profiles(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse DNS-filter profile names and safe descriptive metadata."""
    return _parse_security_profile_section(
        config_text, ("config", "dnsfilter", "profile"), context=context
    )


def parse_admins(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse non-secret administrator metadata used by health checks."""
    allowed_fields = {"accprofile", "vdom", "comments", "status", "two-factor"}
    allowed_fields.update({f"trusthost{number}" for number in range(1, 11)})
    return _parse_named_section(
        config_text,
        ("config", "system", "admin"),
        allowed_fields=allowed_fields,
        field_aliases={"vdom": "admin_vdom"},
        context=context,
    )


def parse_ipsec_phase1(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse non-secret IPsec Phase 1 interface and legacy definitions."""
    allowed_fields = {
        "interface",
        "ike-version",
        "remote-gw",
        "peertype",
        "mode",
        "proposal",
        "dhgrp",
        "nattraversal",
        "dpd",
        "comments",
    }
    interface_definitions = _parse_named_section(
        config_text,
        ("config", "vpn", "ipsec", "phase1-interface"),
        allowed_fields=allowed_fields,
        context=context,
    )
    legacy_definitions = _parse_named_section(
        config_text,
        ("config", "vpn", "ipsec", "phase1"),
        allowed_fields=allowed_fields,
        context=context,
    )
    for definition in interface_definitions:
        definition["definition_type"] = "phase1-interface"
    for definition in legacy_definitions:
        definition["definition_type"] = "phase1"
    return interface_definitions + legacy_definitions


def parse_ipsec_phase2(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse non-secret IPsec Phase 2 interface and legacy definitions."""
    allowed_fields = {
        "phase1name",
        "proposal",
        "dhgrp",
        "pfs",
        "src-subnet",
        "dst-subnet",
        "src-subnet6",
        "dst-subnet6",
        "src-name",
        "dst-name",
        "src-name6",
        "dst-name6",
        "src-addr-type",
        "dst-addr-type",
        "auto-negotiate",
        "comments",
    }
    interface_definitions = _parse_named_section(
        config_text,
        ("config", "vpn", "ipsec", "phase2-interface"),
        allowed_fields=allowed_fields,
        context=context,
    )
    legacy_definitions = _parse_named_section(
        config_text,
        ("config", "vpn", "ipsec", "phase2"),
        allowed_fields=allowed_fields,
        context=context,
    )
    for definition in interface_definitions:
        definition["definition_type"] = "phase2-interface"
    for definition in legacy_definitions:
        definition["definition_type"] = "phase2"
    return interface_definitions + legacy_definitions


def parse_system_global(
    config_text: str, context: ParserContext | None = None
) -> dict:
    """Parse selected non-secret system-global hardening settings."""
    return _parse_settings_section(
        config_text,
        ("config", "system", "global"),
        {
            "hostname",
            "admin-ssh-v1",
            "admin-https-ssl-versions",
            "admin-console-timeout",
            "admintimeout",
            "admin-telnet",
            "admin-ssh-port",
            "admin-sport",
            "admin-https-redirect",
            "login-banner",
            "gui-display-hostname",
            "login-timestamp",
            "cli-audit-log",
            "admin-scp",
            "strong-crypto",
            "timezone",
            "management-vdom",
            "vdom-mode",
        },
        context=context,
    )


def parse_dedicated_mgmt(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe system dedicated-management settings."""
    return _parse_settings_sections(
        config_text,
        ("config", "system", "dedicated-mgmt"),
        {"status", "interface", "dhcp-server"},
        context=context,
    )


def parse_ha_mgmt(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe HA management interface configuration without secrets."""
    ha_sections: list[dict] = []
    for vdom, section_lines in _matching_sections(
        config_text, ("config", "system", "ha"), context=context
    ):
        section_depth = 1
        sub_section: str | None = None
        status = ""
        interfaces: list[str] = []
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                if section_depth == 2 and len(tokens) >= 2:
                    sub_section = tokens[1].casefold()
                continue
            if command == "end":
                if section_depth == 2:
                    sub_section = None
                section_depth -= 1
                continue

            if section_depth == 1 and command == "set" and len(tokens) >= 2:
                if tokens[1].casefold() == "ha-mgmt-status":
                    status = tokens[2] if len(tokens) > 2 else ""
                continue

            if section_depth == 2 and sub_section == "ha-mgmt-interfaces":
                if command == "set" and len(tokens) >= 2:
                    if tokens[1].casefold() == "interface":
                        for val in tokens[2:]:
                            if val and val not in interfaces:
                                interfaces.append(val)

        ha_sections.append(
            {
                "vdom": vdom,
                "ha_mgmt_status": status,
                "interfaces": interfaces,
                "enabled": status.casefold() in {"enable", "enabled"},
            }
        )
    return ha_sections


def parse_password_policies(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe administrator password-policy settings."""
    return _parse_settings_sections(
        config_text,
        ("config", "system", "password-policy"),
        {
            "status",
            "minimum-length",
            "min-lower-case-letter",
            "min-upper-case-letter",
            "min-non-alphanumeric",
            "min-number",
            "expire-status",
            "expire-day",
        },
        context=context,
    )


def parse_log_settings(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse selected logging inventory and hardening settings."""
    return _parse_settings_sections(
        config_text,
        ("config", "log", "setting"),
        {"log-policy-name", "log-policy-comment", "implicit-log"},
        context=context,
    )


def parse_antivirus_settings(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe antivirus behavior settings."""
    return _parse_settings_sections(
        config_text,
        ("config", "antivirus", "settings"),
        {"av-failopen", "fail-open", "traffic-submit"},
        context=context,
    )


def parse_ips_globals(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse safe IPS global behavior settings."""
    return _parse_settings_sections(
        config_text,
        ("config", "ips", "global"),
        {"fail-open", "traffic-submit"},
        context=context,
    )


def parse_dos_policies(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse lightweight DoS-policy inventory, including anomaly names."""
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}
    list_fields = {"srcaddr", "dstaddr", "service"}

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "dos-policy"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        anomaly_depth: int | None = None
        for tokens in section_lines:
            command = tokens[0].casefold()
            normalized = tuple(token.casefold() for token in tokens)
            if command == "config":
                section_depth += 1
                if section_depth == 2 and normalized == ("config", "anomaly"):
                    anomaly_depth = section_depth
                continue
            if command == "end":
                if anomaly_depth == section_depth:
                    anomaly_depth = None
                section_depth -= 1
                continue

            if anomaly_depth == section_depth == 2:
                if command == "edit" and len(tokens) >= 2 and current_policy:
                    current_policy["anomalies"].append(tokens[1])
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                current_policy = {
                    "id": _policy_id(tokens[1]),
                    "name": None,
                    "vdom": vdom,
                    "sequence_index": sequence_index,
                    "anomalies": [],
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            if key.casefold() not in {
                "name",
                "interface",
                "srcaddr",
                "dstaddr",
                "service",
                "status",
                "comments",
            }:
                continue
            values = tokens[2:]
            if key.casefold() in list_fields:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


def parse_dns(
    config_text: str, context: ParserContext | None = None
) -> dict:
    """Parse selected DNS inventory fields without performing lookups."""
    return _parse_settings_section(
        config_text,
        ("config", "system", "dns"),
        {
            "primary",
            "secondary",
            "protocol",
            "domain",
            "interface-select-method",
            "source-ip",
        },
        include_presence=True,
        context=context,
    )


def parse_ntp(
    config_text: str, context: ParserContext | None = None
) -> dict:
    """Parse selected NTP settings and nested server entries."""
    ntp: dict = {}
    servers: list[dict] = []
    current_server: dict | None = None
    in_section = False
    section_depth = 0
    server_depth: int | None = None
    direct_fields = {"ntpsync", "type", "syncinterval", "server-mode"}
    server_fields = {"server", "ntpv3", "interface", "source-ip", "vrf"}

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "system", "ntp"), context=context
    ):
        in_section = True
        ntp["_configured"] = True
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            normalized_tokens = [token.casefold() for token in tokens]

            if command == "config":
                section_depth += 1
                if (
                    section_depth == 2
                    and normalized_tokens == ["config", "ntpserver"]
                ):
                    server_depth = section_depth
                continue

            if command == "end":
                if server_depth == section_depth:
                    server_depth = None
                    current_server = None
                section_depth -= 1
                continue

            if server_depth == section_depth:
                if command == "edit" and len(tokens) >= 2:
                    current_server = {"name": tokens[1]}
                elif command == "next":
                    if current_server is not None:
                        servers.append(current_server)
                        current_server = None
                elif (
                    command == "set"
                    and len(tokens) >= 2
                    and current_server is not None
                    and tokens[1].casefold() in server_fields
                ):
                    key = tokens[1]
                    values = tokens[2:]
                    current_server[key] = (
                        values if len(values) > 1 else (values[0] if values else "")
                    )
                continue

            if section_depth == 1 and command == "set" and len(tokens) >= 2:
                key = tokens[1]
                if key.casefold() not in direct_fields:
                    continue
                values = tokens[2:]
                ntp[key] = values if len(values) > 1 else (values[0] if values else "")

        break

    if in_section:
        ntp["servers"] = servers
    return ntp


def parse_user_groups(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse minimal, safe non-secret user group metadata for relationship resolution."""
    return _parse_named_section(
        config_text,
        ("config", "user", "group"),
        list_fields={"member"},
        allowed_fields={"name", "group-type", "member", "comments"},
        context=context,
    )


def parse_user_locals(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse minimal, safe non-secret local user metadata without credentials.

    Strictly suppresses passwords, hashes, tokens, OTP seeds, and secret material.
    """
    return _parse_named_section(
        config_text,
        ("config", "user", "local"),
        allowed_fields={"name", "type", "status", "two-factor", "comments"},
        context=context,
    )


def parse_ssl_vpn_portals(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse SSL-VPN web portal definitions per VDOM without runtime state."""
    list_fields = {
        "split-tunneling-routing-address",
        "split-tunneling-routing-address6",
        "ip-pools",
        "ipv6-pools",
    }
    allowed_fields = {
        "name",
        "tunnel-mode",
        "web-mode",
        "split-tunneling",
        "split-tunneling-routing-negate",
        "split-tunneling-routing-address",
        "split-tunneling-routing-address6",
        "ip-pools",
        "ipv6-pools",
        "dns-server1",
        "dns-server2",
        "heading",
        "theme",
        "comments",
    }
    return _parse_named_section(
        config_text,
        ("config", "vpn", "ssl", "web", "portal"),
        list_fields=list_fields,
        allowed_fields=allowed_fields,
        context=context,
    )


def parse_ssl_vpn_settings(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse SSL-VPN global settings and nested authentication rules per VDOM."""
    settings_list: list[dict] = []
    list_fields = {
        "source-interface",
        "source-address",
        "source-address-negate",
        "source-address6",
        "tunnel-ip-pools",
        "tunnel-ipv6-pools",
    }
    auth_list_fields = {
        "groups",
        "users",
        "source-interface",
        "source-address",
        "source-address6",
    }
    secret_fields = {
        "passwd",
        "password",
        "psksecret",
        "private-key",
        "pre-shared-key",
    }

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "vpn", "ssl", "settings"), context=context
    ):
        settings: dict = {
            "vdom": vdom,
            "_configured": True,
            "authentication_rules": [],
        }
        auth_rules: list[dict] = []
        current_rule: dict | None = None
        section_depth = 1
        auth_depth: int | None = None
        rule_sequence = 0

        for tokens in section_lines:
            command = tokens[0].casefold()

            if command == "config":
                section_depth += 1
                if (
                    section_depth == 2
                    and len(tokens) >= 2
                    and tokens[1].casefold() == "authentication-rule"
                ):
                    auth_depth = section_depth
                continue

            if command == "end":
                if auth_depth == section_depth:
                    auth_depth = None
                    current_rule = None
                section_depth -= 1
                continue

            # Nested authentication-rule handling
            if auth_depth == section_depth == 2:
                if command == "edit" and len(tokens) >= 2:
                    current_rule = {
                        "id": _policy_id(tokens[1]),
                        "sequence_index": rule_sequence,
                        "vdom": vdom,
                    }
                    rule_sequence += 1
                    continue
                if command == "next":
                    if current_rule is not None:
                        auth_rules.append(current_rule)
                        current_rule = None
                    continue
                if command == "set" and len(tokens) >= 2 and current_rule is not None:
                    key = tokens[1]
                    key_lower = key.casefold()
                    if key_lower in secret_fields:
                        continue
                    values = tokens[2:]
                    if key_lower in auth_list_fields:
                        current_rule[key] = values
                    elif len(values) > 1:
                        current_rule[key] = values
                    else:
                        current_rule[key] = values[0] if values else ""
                continue

            if section_depth != 1:
                continue

            if command == "set" and len(tokens) >= 2:
                key = tokens[1]
                key_lower = key.casefold()
                if key_lower in secret_fields:
                    continue
                values = tokens[2:]
                if key_lower in list_fields:
                    settings[key] = values
                elif len(values) > 1:
                    settings[key] = values
                else:
                    settings[key] = values[0] if values else ""

        settings["authentication_rules"] = auth_rules
        settings_list.append(settings)

    return settings_list


def parse_local_in_policies(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse policies from every ``config firewall local-in-policy`` section."""
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}
    list_fields = {
        "intf",
        "srcintf",
        "srcaddr",
        "dstaddr",
        "service",
        "internet-service-src-id",
        "internet-service-src-name",
        "internet-service-src-group",
        "internet-service-src-custom",
        "internet-service-src-custom-group",
        "internet-service-src-fortiguard",
    }

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "local-in-policy"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                current_policy = {
                    "id": _policy_id(tokens[1]),
                    "sequence_index": sequence_index,
                    "vdom": vdom,
                    "address_family": "IPv4",
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            values = tokens[2:]
            if key.casefold() in list_fields:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


def parse_local_in_policies6(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse policies from every ``config firewall local-in-policy6`` section."""
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}
    list_fields = {
        "intf",
        "srcintf",
        "srcaddr",
        "srcaddr6",
        "dstaddr",
        "dstaddr6",
        "service",
        "service6",
    }

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "local-in-policy6"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                current_policy = {
                    "id": _policy_id(tokens[1]),
                    "sequence_index": sequence_index,
                    "vdom": vdom,
                    "address_family": "IPv6",
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            values = tokens[2:]
            if key.casefold() in list_fields:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


def parse_interface_policies(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse policies from every ``config firewall interface-policy`` section."""
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}
    list_fields = {
        "srcaddr",
        "dstaddr",
        "service",
    }

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "interface-policy"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                policy_id_val = _policy_id(tokens[1])
                current_policy = {
                    "id": policy_id_val,
                    "policyid": policy_id_val,
                    "sequence_index": sequence_index,
                    "vdom": vdom,
                    "address_family": "IPv4",
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            key_lower = key.casefold()
            values = tokens[2:]
            if key_lower in list_fields:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


def parse_interface_policies6(
    config_text: str, context: ParserContext | None = None
) -> list[dict]:
    """Parse policies from every ``config firewall interface-policy6`` section."""
    policies: list[dict] = []
    sequence_by_vdom: dict[str | None, int] = {}
    list_fields = {
        "srcaddr6",
        "dstaddr6",
        "service6",
        "srcaddr",
        "dstaddr",
        "service",
    }

    for vdom, section_lines in _matching_sections(
        config_text, ("config", "firewall", "interface-policy6"), context=context
    ):
        current_policy: dict | None = None
        section_depth = 1
        for tokens in section_lines:
            command = tokens[0].casefold()
            if command == "config":
                section_depth += 1
                continue
            if command == "end":
                section_depth -= 1
                continue
            if section_depth != 1:
                continue

            if command == "edit" and len(tokens) >= 2:
                sequence_index = sequence_by_vdom.get(vdom, 0)
                policy_id_val = _policy_id(tokens[1])
                current_policy = {
                    "id": policy_id_val,
                    "policyid": policy_id_val,
                    "sequence_index": sequence_index,
                    "vdom": vdom,
                    "address_family": "IPv6",
                }
                sequence_by_vdom[vdom] = sequence_index + 1
                continue
            if command == "next":
                if current_policy is not None:
                    policies.append(current_policy)
                    current_policy = None
                continue
            if command != "set" or len(tokens) < 2 or current_policy is None:
                continue

            key = tokens[1]
            key_lower = key.casefold()
            values = tokens[2:]
            if key_lower in list_fields:
                current_policy[key] = values
            elif len(values) > 1:
                current_policy[key] = values
            else:
                current_policy[key] = values[0] if values else ""

    return policies


SECTION_TARGETS: dict[str, list[tuple[str, ...]]] = {
    "interfaces": [("config", "system", "interface")],
    "zones": [("config", "system", "zone")],
    "sdwan": [("config", "system", "sdwan")],
    "firewall_policies": [("config", "firewall", "policy")],
    "local_in_policies": [("config", "firewall", "local-in-policy")],
    "interface_policies": [("config", "firewall", "interface-policy")],
    "addresses": [("config", "firewall", "address")],
    "address_groups": [("config", "firewall", "addrgrp")],
    "addresses6": [("config", "firewall", "address6")],
    "address_groups6": [("config", "firewall", "addrgrp6")],
    "services": [("config", "firewall", "service", "custom")],
    "service_groups": [("config", "firewall", "service", "group")],
    "vips": [("config", "firewall", "vip")],
    "vips6": [("config", "firewall", "vip6")],
    "local_in_policies6": [("config", "firewall", "local-in-policy6")],
    "interface_policies6": [("config", "firewall", "interface-policy6")],
    "isdb": [
        ("config", "firewall", "internet-service-name"),
        ("config", "firewall", "internet-service-group"),
        ("config", "firewall", "internet-service-custom"),
        ("config", "firewall", "internet-service-custom-group"),
    ],
    "administrators": [("config", "system", "admin")],
    "system_global": [("config", "system", "global")],
    "dns": [("config", "system", "dns")],
    "ntp": [("config", "system", "ntp")],
    "ips_sensors": [("config", "ips", "sensor")],
    "antivirus_profiles": [("config", "antivirus", "profile")],
    "webfilter_profiles": [("config", "webfilter", "profile")],
    "application_lists": [("config", "application", "list")],
    "ssl_ssh_profiles": [("config", "firewall", "ssl-ssh-profile")],
    "dnsfilter_profiles": [("config", "dnsfilter", "profile")],
    "ipsec_phase1": [
        ("config", "vpn", "ipsec", "phase1-interface"),
        ("config", "vpn", "ipsec", "phase1"),
    ],
    "ipsec_phase2": [
        ("config", "vpn", "ipsec", "phase2-interface"),
        ("config", "vpn", "ipsec", "phase2"),
    ],
    "dedicated_mgmt": [("config", "system", "dedicated-mgmt")],
    "ha_mgmt": [("config", "system", "ha")],
    "log_settings": [
        ("config", "log", "setting"),
        ("config", "log", "sysgrp", "setting"),
        ("config", "log", "fortiguard", "setting"),
        ("config", "log", "memory", "setting"),
        ("config", "log", "disk", "setting"),
        ("config", "log", "null-device", "setting"),
    ],
    "password_policies": [("config", "system", "password-policy")],
    "dos_policies": [("config", "firewall", "DoS-policy")],
    "ssl_vpn_settings": [("config", "vpn", "ssl", "settings")],
    "ssl_vpn_portals": [("config", "vpn", "ssl", "web", "portal")],
    "user_groups": [("config", "user", "group")],
    "user_locals": [("config", "user", "local")],
}


def parse_fortios_version(config_text: str) -> dict:
    """Parse explicit FortiOS configuration version and build header metadata."""
    if not config_text or not config_text.strip():
        return {
            "detected": False,
            "version": "unknown",
            "major": None,
            "minor": None,
            "patch": None,
            "build": None,
            "platform": None,
            "source": "none",
            "raw_header": None,
        }

    header_pattern = re.compile(
        r"#\s*config-version\s*=\s*([^\r\n:]+)", re.IGNORECASE
    )

    for line in config_text.splitlines()[:30]:
        line_str = line.strip()
        if not line_str.startswith("#"):
            continue
        match = header_pattern.search(line_str)
        if match:
            raw_val = match.group(1).strip()
            version_match = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", raw_val)
            if not version_match:
                return {
                    "detected": False,
                    "version": "unknown",
                    "major": None,
                    "minor": None,
                    "patch": None,
                    "build": None,
                    "platform": None,
                    "source": "malformed_header",
                    "raw_header": line_str,
                }

            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = (
                int(version_match.group(3))
                if version_match.group(3) is not None
                else None
            )
            version_str = (
                f"{major}.{minor}.{patch}" if patch is not None else f"{major}.{minor}"
            )

            build_match = re.search(r"build[-_]?0*(\d+)", raw_val, re.IGNORECASE)
            build = int(build_match.group(1)) if build_match else None

            prefix = raw_val[: version_match.start()].strip("-_ ")
            platform = prefix if prefix else None

            return {
                "detected": True,
                "version": version_str,
                "major": major,
                "minor": minor,
                "patch": patch,
                "build": build,
                "platform": platform,
                "source": "header",
                "raw_header": line_str,
            }

    return {
        "detected": False,
        "version": "unknown",
        "major": None,
        "minor": None,
        "patch": None,
        "build": None,
        "platform": None,
        "source": "none",
        "raw_header": None,
    }


def detect_section_presence(
    config_text: str, context: ParserContext | None = None
) -> dict[str, bool]:
    """Detect raw presence of FortiOS section headers in configuration text."""
    presence: dict[str, bool] = {}
    if not config_text or not config_text.strip():
        for key in SECTION_TARGETS:
            presence[key] = False
        return presence

    if context is None:
        context = ParserContext(config_text)

    for key, targets in SECTION_TARGETS.items():
        presence[key] = any(context.has_section(target) for target in targets)

    return presence


def _detect_structural_warnings(config_text: str) -> list[str]:
    """Detect structural syntax warnings such as truncated quotes or unclosed blocks."""
    warnings: list[str] = []
    config_stack: list[str] = []
    in_edit: bool = False
    edit_name: str = ""

    lines = config_text.splitlines()
    for line_num, line in enumerate(lines, 1):
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        if '"' not in line_str and "'" not in line_str and "\\" not in line_str:
            tokens = line_str.split()
        else:
            try:
                tokens = shlex.split(line_str, comments=False, posix=True)
            except ValueError:
                warnings.append(f"Truncated or unclosed quoted value on line {line_num}")
                continue

        if not tokens:
            continue

        command = tokens[0].casefold()
        if command == "config":
            section_name = " ".join(tokens[1:]) if len(tokens) > 1 else "unknown"
            config_stack.append(section_name)
            in_edit = False
        elif command == "edit":
            in_edit = True
            edit_name = tokens[1] if len(tokens) > 1 else ""
        elif command == "next":
            in_edit = False
        elif command == "end":
            in_edit = False
            if config_stack:
                config_stack.pop()
            else:
                warnings.append(
                    f"Unexpected 'end' without matching 'config' section on line {line_num}"
                )

    if config_stack:
        warnings.append(
            f"Unclosed configuration section block(s): {', '.join('config ' + s for s in config_stack)}"
        )
    if in_edit and edit_name:
        warnings.append(f"Unterminated edit block for object '{edit_name}'")

    return warnings


def assess_input_quality(
    config_text: str,
    parsed_config: dict | None = None,
    context: ParserContext | None = None,
) -> dict:
    """Evaluate input quality, classification, FortiOS metadata, and domain scope."""
    if not config_text or not config_text.strip():
        version_meta = parse_fortios_version("")
        section_presence = detect_section_presence("", context=context)
        return {
            "input_type": "EMPTY_INPUT",
            "classification": "EMPTY_INPUT",
            "fortigate_detected": False,
            "fortios": version_meta,
            "section_presence": section_presence,
            "object_counts": {},
            "recognized_sections": [],
            "missing_analysis_sections": sorted(list(SECTION_TARGETS.keys())),
            "structural_warnings": [],
            "analysis_scope": {
                domain: {
                    "status": "UNAVAILABLE_NOT_SUPPLIED",
                    "evidence": "Supplied configuration input is empty.",
                }
                for domain in (
                    "firewall_policies",
                    "interfaces",
                    "administrators",
                    "ipsec_vpn",
                    "system_global",
                    "dns",
                    "ntp",
                    "local_in_policies",
                    "interface_policies",
                    "security_profiles",
                    "logging",
                    "management_context",
                    "ipv6",
                )
            },
            "explanation": [
                "Supplied configuration input is empty or contains only whitespace."
            ],
        }

    version_meta = parse_fortios_version(config_text)
    section_presence = detect_section_presence(config_text, context=context)
    structural_warnings = _detect_structural_warnings(config_text)

    recognized_sections = [
        sec for sec, present in section_presence.items() if present
    ]
    missing_analysis_sections = [
        sec for sec, present in section_presence.items() if not present
    ]

    if parsed_config is not None:
        object_counts = {
            "policies": len(parsed_config.get("policies", [])),
            "local_in_policies": len(parsed_config.get("local_in_policies", [])),
            "interface_policies": len(parsed_config.get("interface_policies", [])),
            "local_in_policies6": len(parsed_config.get("local_in_policies6", [])),
            "interface_policies6": len(parsed_config.get("interface_policies6", [])),
            "interfaces": len(parsed_config.get("interfaces", [])),
            "addresses": len(parsed_config.get("addresses", [])),
            "address_groups": len(parsed_config.get("address_groups", [])),
            "addresses6": len(parsed_config.get("addresses6", [])),
            "address_groups6": len(parsed_config.get("address_groups6", [])),
            "services": len(parsed_config.get("services", [])),
            "service_groups": len(parsed_config.get("service_groups", [])),
            "vips": len(parsed_config.get("vips", [])),
            "vips6": len(parsed_config.get("vips6", [])),
            "admins": len(parsed_config.get("admins", [])),
            "ipsec_phase1": len(parsed_config.get("ipsec_phase1", [])),
            "ipsec_phase2": len(parsed_config.get("ipsec_phase2", [])),
            "zones": len(parsed_config.get("zones", [])),
            "sdwan_zones": len(parsed_config.get("sdwan_zones", [])),
            "ips_sensors": len(parsed_config.get("ips_sensors", [])),
            "antivirus_profiles": len(parsed_config.get("antivirus_profiles", [])),
            "webfilter_profiles": len(parsed_config.get("webfilter_profiles", [])),
            "application_lists": len(parsed_config.get("application_lists", [])),
            "ssl_ssh_profiles": len(parsed_config.get("ssl_ssh_profiles", [])),
            "dnsfilter_profiles": len(parsed_config.get("dnsfilter_profiles", [])),
            "dos_policies": len(parsed_config.get("dos_policies", [])),
            "local_in_policies": len(parsed_config.get("local_in_policies", [])),
            "local_in_policies6": len(parsed_config.get("local_in_policies6", [])),
            "interface_policies": len(parsed_config.get("interface_policies", [])),
            "interface_policies6": len(parsed_config.get("interface_policies6", [])),
            "ssl_vpn_settings": len(parsed_config.get("ssl_vpn_settings", [])),
            "ssl_vpn_portals": len(parsed_config.get("ssl_vpn_portals", [])),
            "user_groups": len(parsed_config.get("user_groups", [])),
            "user_locals": len(parsed_config.get("user_locals", [])),
        }
    else:
        object_counts = {}

    has_header = version_meta["detected"]
    fortigate_syntax_tokens = ("config", "set", "edit", "next", "end")
    has_fortigate_syntax = any(
        kw in config_text.casefold() for kw in fortigate_syntax_tokens
    )

    domain_presence = {
        "firewall_policies": section_presence["firewall_policies"],
        "interfaces": section_presence["interfaces"],
        "administrators": section_presence["administrators"],
        "ipsec_vpn": (
            section_presence["ipsec_phase1"] or section_presence["ipsec_phase2"]
        ),
        "system_global": section_presence["system_global"],
        "dns": section_presence["dns"],
        "ntp": section_presence["ntp"],
        "local_in_policies": section_presence["local_in_policies"],
        "interface_policies": section_presence["interface_policies"],
        "ssl_vpn": (
            section_presence["ssl_vpn_settings"]
            or section_presence["ssl_vpn_portals"]
        ),
        "security_profiles": any(
            section_presence[sec]
            for sec in (
                "ips_sensors",
                "antivirus_profiles",
                "webfilter_profiles",
                "application_lists",
                "ssl_ssh_profiles",
                "dnsfilter_profiles",
            )
        ),
        "logging": section_presence["log_settings"],
        "management_context": (
            section_presence["interfaces"]
            or section_presence["dedicated_mgmt"]
            or section_presence["ha_mgmt"]
        ),
        "ipv6": (
            section_presence.get("addresses6", False)
            or section_presence.get("address_groups6", False)
            or section_presence.get("vips6", False)
            or section_presence.get("local_in_policies6", False)
            or section_presence.get("interface_policies6", False)
        ),
    }

    present_domain_count = sum(1 for present in domain_presence.values() if present)
    fortigate_detected = has_header or (
        has_fortigate_syntax and len(recognized_sections) > 0
    )

    explanation: list[str] = []

    if not fortigate_detected:
        classification = "UNRECOGNIZED_INPUT"
        explanation.append(
            "No recognized FortiOS configuration section headers or structural syntax detected."
        )
    elif (
        has_header
        and present_domain_count >= 3
        and not any("Truncated or unclosed" in w for w in structural_warnings)
    ):
        classification = "LIKELY_FULL_BACKUP"
        explanation.append(
            f"FortiGate configuration version header detected ('{version_meta.get('raw_header', '')}')."
        )
        explanation.append(
            f"Multiple major configuration domains detected ({present_domain_count} domain areas observed)."
        )
        explanation.append("No severe structural truncation detected.")
    elif structural_warnings and not recognized_sections:
        classification = "MALFORMED_OR_TRUNCATED_CONFIGURATION"
        explanation.append(
            "Structural syntax errors or severe truncation detected without parseable configuration sections."
        )
    elif has_header and structural_warnings:
        classification = "FORTIGATE_CONFIGURATION_UNKNOWN_COMPLETENESS"
        explanation.append(
            "FortiGate configuration version header detected, but structural truncation warnings were observed."
        )
    elif present_domain_count >= 3:
        classification = "FORTIGATE_CONFIGURATION_UNKNOWN_COMPLETENESS"
        explanation.append(
            f"Multiple configuration domains detected ({present_domain_count} domain areas observed), but no version header was found."
        )
    else:
        classification = "PARTIAL_CONFIGURATION"
        explanation.append(
            "Recognized FortiOS configuration syntax and sections detected."
        )
        if not has_header:
            explanation.append("No FortiGate configuration version header observed.")
        explanation.append(
            f"Limited configuration coverage ({present_domain_count} domain area(s) observed)."
        )

    analysis_scope: dict[str, dict] = {}
    is_full_backup = classification == "LIKELY_FULL_BACKUP"

    for domain, is_present in domain_presence.items():
        if is_present:
            if domain == "ntp" and not is_full_backup:
                analysis_scope[domain] = {
                    "status": "INCOMPLETE_SCOPE",
                    "evidence": "NTP review incomplete: configuration input is partial and full-device scope is unavailable.",
                }
            else:
                analysis_scope[domain] = {
                    "status": "COVERED",
                    "evidence": "Section observed in supplied input and available for static analysis.",
                }
        elif is_full_backup:
            analysis_scope[domain] = {
                "status": "UNOBSERVED_IN_INPUT",
                "evidence": "No configuration observed for this optional domain in supplied full backup.",
            }
        else:
            analysis_scope[domain] = {
                "status": "UNAVAILABLE_NOT_SUPPLIED",
                "evidence": "Source configuration section for this domain was not observed in supplied input.",
            }

    return {
        "input_type": classification,
        "classification": classification,
        "fortigate_detected": fortigate_detected,
        "fortios": version_meta,
        "section_presence": section_presence,
        "object_counts": object_counts,
        "recognized_sections": sorted(recognized_sections),
        "missing_analysis_sections": sorted(missing_analysis_sections),
        "structural_warnings": structural_warnings,
        "analysis_scope": analysis_scope,
        "explanation": explanation,
    }


def parse_configuration(
    config_text: str, context: ParserContext | None = None
) -> dict:
    """Return the selected FortiGate configuration context for the MVP."""
    if context is None:
        context = ParserContext(config_text)

    password_policies = parse_password_policies(config_text, context=context)
    log_settings = parse_log_settings(config_text, context=context)
    antivirus_settings = parse_antivirus_settings(config_text, context=context)
    ips_globals = parse_ips_globals(config_text, context=context)
    dedicated_mgmt = parse_dedicated_mgmt(config_text, context=context)
    ha_mgmt = parse_ha_mgmt(config_text, context=context)
    zones = parse_zones(config_text, context=context)
    sdwan = parse_sdwan(config_text, context=context)
    dos_policies = parse_dos_policies(config_text, context=context)
    dns = parse_dns(config_text, context=context)
    ntp = parse_ntp(config_text, context=context)
    ssl_vpn_settings = parse_ssl_vpn_settings(config_text, context=context)
    ssl_vpn_portals = parse_ssl_vpn_portals(config_text, context=context)
    user_groups = parse_user_groups(config_text, context=context)
    user_locals = parse_user_locals(config_text, context=context)
    addresses6 = parse_addresses6(config_text, context=context)
    address_groups6 = parse_address_groups6(config_text, context=context)
    vips6 = parse_vips6(config_text, context=context)
    local_in_policies6 = parse_local_in_policies6(config_text, context=context)
    interface_policies6 = parse_interface_policies6(config_text, context=context)
    parsed = {
        "policies": parse_firewall_policies(config_text, context=context),
        "local_in_policies": parse_local_in_policies(config_text, context=context),
        "interface_policies": parse_interface_policies(config_text, context=context),
        "local_in_policies6": local_in_policies6,
        "interface_policies6": interface_policies6,
        "interfaces": parse_interfaces(config_text, context=context),
        "zones": zones,
        "sdwan": sdwan,
        "sdwan_zones": sdwan.get("zones", []),
        "addresses": parse_addresses(config_text, context=context),
        "address_groups": parse_address_groups(config_text, context=context),
        "addresses6": addresses6,
        "address_groups6": address_groups6,
        "services": parse_custom_services(config_text, context=context),
        "service_groups": parse_service_groups(config_text, context=context),
        "vips": parse_vips(config_text, context=context),
        "vips6": vips6,
        "internet_service_names": parse_internet_service_names(
            config_text, context=context
        ),
        "internet_service_groups": parse_internet_service_groups(
            config_text, context=context
        ),
        "internet_service_customs": parse_internet_service_customs(
            config_text, context=context
        ),
        "internet_service_custom_groups": parse_internet_service_custom_groups(
            config_text, context=context
        ),
        "ips_sensors": parse_ips_sensors(config_text, context=context),
        "antivirus_profiles": parse_antivirus_profiles(config_text, context=context),
        "webfilter_profiles": parse_webfilter_profiles(config_text, context=context),
        "application_lists": parse_application_lists(config_text, context=context),
        "ssl_ssh_profiles": parse_ssl_ssh_profiles(config_text, context=context),
        "dnsfilter_profiles": parse_dnsfilter_profiles(config_text, context=context),
        "admins": parse_admins(config_text, context=context),
        "ipsec_phase1": parse_ipsec_phase1(config_text, context=context),
        "ipsec_phase2": parse_ipsec_phase2(config_text, context=context),
        "system_global": parse_system_global(config_text, context=context),
        "dedicated_mgmt": dedicated_mgmt,
        "dedicated_management": _first_settings_section(dedicated_mgmt),
        "ha_mgmt": ha_mgmt,
        "ha_management": _first_settings_section(ha_mgmt),
        "password_policies": password_policies,
        "password_policy": _first_settings_section(password_policies),
        "log_settings": log_settings,
        "log_setting": _first_settings_section(log_settings),
        "antivirus_settings": antivirus_settings,
        "antivirus_setting": _first_settings_section(antivirus_settings),
        "ips_globals": ips_globals,
        "ips_global": _first_settings_section(ips_globals),
        "dos_policies": dos_policies,
        "dns": dns,
        "ntp": ntp,
        "ssl_vpn_settings": ssl_vpn_settings,
        "ssl_vpn_portals": ssl_vpn_portals,
        "ssl_vpn": _first_settings_section(ssl_vpn_settings),
        "user_groups": user_groups,
        "user_locals": user_locals,
        "users": user_locals,
    }
    parsed["input_assessment"] = assess_input_quality(
        config_text, parsed, context=context
    )
    return parsed
