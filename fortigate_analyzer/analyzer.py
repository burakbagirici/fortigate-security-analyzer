"""Context-aware security analysis for selected FortiGate configuration data."""

from __future__ import annotations

import ipaddress
import re


INTERNAL_ROLES = {"LAN", "DMZ", "INTERNAL"}
ADMIN_SERVICES = {"RDP", "SSH", "TELNET"}
ADMIN_PORTS = {"22", "23", "3389"}
DISABLED_VALUES = {"disable", "disabled", "no"}

BUILTIN_SERVICES = {
    "HTTP": "TCP/80",
    "HTTPS": "TCP/443",
    "DNS": "UDP/TCP/53",
    "SSH": "TCP/22",
    "RDP": "TCP/3389",
    "TELNET": "TCP/23",
    "FTP": "TCP/21",
    "SMTP": "TCP/25",
    "IMAP": "TCP/143",
    "POP3": "TCP/110",
    "PING": "ICMP",
    "ALL": "All services",
}

SECURITY_PROFILE_FIELDS = {
    "ips": ("ips-sensor", "ips_sensors"),
    "antivirus": ("av-profile", "antivirus_profiles"),
    "web_filter": ("webfilter-profile", "webfilter_profiles"),
    "application_control": ("application-list", "application_lists"),
    "ssl_inspection": ("ssl-ssh-profile", "ssl_ssh_profiles"),
    "dns_filter": ("dnsfilter-profile", "dnsfilter_profiles"),
}

BUILTIN_SECURITY_PROFILES = {
    "ips": {"default"},
    "antivirus": {"default"},
    "web_filter": {"default"},
    "application_control": {"default"},
    "dns_filter": {"default"},
    "ssl_inspection": {
        "default",
        "certificate-inspection",
        "deep-inspection",
        "no-inspection",
    },
}

UNSUPPORTED_MATCH_FIELDS = {
    "users",
    "user",
    "groups",
    "user-group",
    "devices",
    "device",
    "srcaddr-negate",
    "dstaddr-negate",
    "service-negate",
    "srcintf-negate",
    "dstintf-negate",
    "srcaddr6-negate",
    "dstaddr6-negate",
    "internet-service",
    "internet-service-src",
    "internet-service-name",
    "internet-service-src-name",
    "internet-service6",
    "internet-service-src6",
    "src-vendor-mac",
    "src-mac",
    "src-device",
    "dst-device",
    "fsso-groups",
    "identity-based",
    "application",
    "application-id",
    "ztna-ems-tag",
}


def _values(value: object) -> list[str]:
    """Return a configuration value as an ordered list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _normalized_values(value: object) -> set[str]:
    """Return configuration values as case-insensitive strings."""
    return {item.casefold() for item in _values(value)}


def _first_value(value: object, default: str = "") -> str:
    """Return the first value from a scalar or multi-value setting."""
    values = _values(value)
    return values[0] if values else default


def _index_by_name(items: object) -> dict[str, dict]:
    """Index parsed objects by case-insensitive name."""
    if not isinstance(items, list):
        return {}
    return {
        str(item.get("name", "")).casefold(): item
        for item in items
        if isinstance(item, dict) and item.get("name") is not None
    }


def _vdom_key(value: object) -> str | None:
    """Return a case-insensitive VDOM scope key without inventing a scope."""
    if value is None or str(value).strip() == "":
        return None
    return str(value).casefold()


def _same_vdom(left: dict, right: dict) -> bool:
    """Return whether two parsed objects belong to the same VDOM scope."""
    return _vdom_key(left.get("vdom")) == _vdom_key(right.get("vdom"))


def _scoped_items(items: object, vdom: object) -> list[dict]:
    """Select objects from exactly one VDOM, including the global None scope."""
    if not isinstance(items, list):
        return []
    scope = _vdom_key(vdom)
    return [
        item
        for item in items
        if isinstance(item, dict) and _vdom_key(item.get("vdom")) == scope
    ]


def _scoped_interfaces(interfaces: object, policy_vdom: object) -> list[dict]:
    """Select interfaces matching policy VDOM scope conservatively.

    - Single-VDOM top-level policy (policy_vdom is None):
      Matches all top-level interfaces (interface vdom is None), regardless
      of whether 'configured_vdom' is set to 'root' or omitted.
    - Explicit policy VDOM (e.g. 'root' or 'VDOM-B'):
      Matches interfaces defined inside that VDOM (vdom == policy_vdom),
      or top-level interfaces explicitly assigned to that VDOM via
      'configured_vdom' (vdom is None and configured_vdom == policy_vdom).
      Never borrows interfaces assigned to a different VDOM.
    """
    if not isinstance(interfaces, list):
        return []
    target_scope = _vdom_key(policy_vdom)
    scoped: list[dict] = []
    for item in interfaces:
        if not isinstance(item, dict):
            continue
        item_scope = _vdom_key(item.get("vdom"))
        item_configured = _vdom_key(item.get("configured_vdom"))

        if target_scope is None:
            if item_scope is None:
                scoped.append(item)
        else:
            if item_scope == target_scope:
                scoped.append(item)
            elif item_scope is None and item_configured == target_scope:
                scoped.append(item)
    return scoped


def _scoped_zones(zones: object, policy_vdom: object) -> list[dict]:
    """Select zones matching policy VDOM scope conservatively."""
    if not isinstance(zones, list):
        return []
    target_scope = _vdom_key(policy_vdom)
    scoped: list[dict] = []
    for item in zones:
        if not isinstance(item, dict):
            continue
        item_scope = _vdom_key(item.get("vdom"))
        item_configured = _vdom_key(item.get("configured_vdom"))

        if target_scope is None:
            if item_scope is None:
                scoped.append(item)
        else:
            if item_scope == target_scope:
                scoped.append(item)
            elif item_scope is None and item_configured == target_scope:
                scoped.append(item)
    return scoped


ISDB_SELECTOR_FIELDS = {
    "destination": (
        ("internet-service-id", "id", "predefined"),
        ("internet-service-name", "name", "predefined"),
        ("internet-service-group", "group", "local_group"),
        ("internet-service-custom", "custom", "local_custom"),
        ("internet-service-custom-group", "custom_group", "local_custom_group"),
        ("internet-service-fortiguard", "fortiguard", "predefined"),
    ),
    "source": (
        ("internet-service-src-id", "id", "predefined"),
        ("internet-service-src-name", "name", "predefined"),
        ("internet-service-src-group", "group", "local_group"),
        ("internet-service-src-custom", "custom", "local_custom"),
        ("internet-service-src-custom-group", "custom_group", "local_custom_group"),
        ("internet-service-src-fortiguard", "fortiguard", "predefined"),
    ),
}


def _is_enabled(value: object) -> bool:
    return "enable" in _normalized_values(value)


def _internet_service_matching(policy: dict, config: dict) -> dict:
    """Describe ISDB matching without expanding the FortiGuard database."""
    vdom = policy.get("vdom")
    names = _scoped_items(config.get("internet_service_names", []), vdom)
    groups = _index_by_name(
        _scoped_items(config.get("internet_service_groups", []), vdom)
    )
    customs = _index_by_name(
        _scoped_items(config.get("internet_service_customs", []), vdom)
    )
    custom_groups = _index_by_name(
        _scoped_items(config.get("internet_service_custom_groups", []), vdom)
    )
    name_lookup: dict[str, dict] = {}
    id_lookup: dict[str, dict] = {}
    for item in names:
        for candidate in (item.get("name"), item.get("display_name")):
            if candidate is not None:
                name_lookup[str(candidate).casefold()] = item
        service_id = item.get("internet-service-id")
        if service_id is not None:
            id_lookup[str(service_id).casefold()] = item

    indexes = {
        "local_group": groups,
        "local_custom": customs,
        "local_custom_group": custom_groups,
    }
    result: dict[str, dict] = {}
    for side in ("source", "destination"):
        enabled_field = (
            "internet-service-src" if side == "source" else "internet-service"
        )
        selectors: list[dict] = []
        for field, selector_type, source_type in ISDB_SELECTOR_FIELDS[side]:
            for value in _values(policy.get(field)):
                key = value.casefold()
                parsed_object = None
                if selector_type == "id":
                    parsed_object = id_lookup.get(key)
                elif selector_type == "name":
                    parsed_object = name_lookup.get(key)
                elif source_type in indexes:
                    parsed_object = indexes[source_type].get(key)

                if source_type == "predefined":
                    resolution = (
                        "known_in_backup" if parsed_object else "predefined_offline"
                    )
                    resolved: bool | None = True if parsed_object else None
                else:
                    resolution = "local" if parsed_object else "unresolved"
                    resolved = bool(parsed_object)
                selector = {
                    "field": field,
                    "type": selector_type,
                    "value": value,
                    "resolution": resolution,
                    "resolved": resolved,
                }
                if parsed_object:
                    selector["object"] = parsed_object
                selectors.append(selector)

        result[side] = {
            "enabled": _is_enabled(policy.get(enabled_field)),
            "negated": _is_enabled(policy.get(f"{enabled_field}-negate")),
            "selectors": selectors,
            "replaces": (
                ["srcaddr"] if side == "source" else ["dstaddr", "service"]
            ),
        }
    return result


def resolve_policy_security_profiles(policy: dict, config: dict) -> dict:
    """Describe supported policy profile attachments and resolve their names.

    Resolution only establishes that a parsed custom object or an explicitly
    known FortiGate built-in name exists.  It does not assess the protection
    provided by the profile.
    """
    resolved_profiles: dict[str, dict] = {}
    for profile_type, (policy_field, config_key) in SECURITY_PROFILE_FIELDS.items():
        name = _first_value(policy.get(policy_field)).strip()
        if not name or name.casefold() in {"none", "disable", "disabled"}:
            resolved_profiles[profile_type] = {
                "attached": False,
                "name": None,
                "resolved": None,
                "source": None,
                "vdom": None,
            }
            continue

        normalized_name = name.casefold()
        custom_profiles = _index_by_name(
            _scoped_items(config.get(config_key, []), policy.get("vdom"))
        )
        if normalized_name in custom_profiles:
            is_resolved = True
            source = "custom"
            resolved_vdom = custom_profiles[normalized_name].get("vdom")
        elif normalized_name in BUILTIN_SECURITY_PROFILES.get(profile_type, set()):
            is_resolved = True
            source = "built-in"
            resolved_vdom = None
        else:
            is_resolved = False
            source = None
            resolved_vdom = None

        resolved_profiles[profile_type] = {
            "attached": True,
            "name": name,
            "resolved": is_resolved,
            "source": source,
            "vdom": resolved_vdom,
        }

    return resolved_profiles


def _finding(
    policy: dict,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
) -> dict:
    """Build a finding compatible with the Streamlit application."""
    return {
        "severity": severity,
        "title": title,
        "policy_id": policy.get("id"),
        "policy_name": policy.get("name") or "Unnamed Policy",
        "vdom": policy.get("vdom"),
        "description": description,
        "recommendation": recommendation,
        "review_required": True,
    }


def _infer_role_from_name(name: str) -> str:
    """Cautiously infer an interface role from a recognizable name."""
    normalized = name.casefold()
    if "dmz" in normalized:
        return "DMZ"
    if any(token in normalized for token in ("wan", "internet", "external")):
        return "WAN"
    if "lan" in normalized:
        return "LAN"
    if "internal" in normalized:
        return "INTERNAL"
    return "UNKNOWN"


def _check_management_evidence(
    name: str,
    interface: dict | None = None,
    dedicated_mgmt_list: list[dict] | None = None,
    ha_mgmt_list: list[dict] | None = None,
    vdom: object = None,
) -> tuple[bool, str | None]:
    """Check explicit static configuration evidence for MANAGEMENT context."""
    # A. Interface-level dedicated management
    if interface:
        dedicated_to = _first_value(interface.get("dedicated-to")).casefold()
        if dedicated_to == "management":
            return True, "interface_dedicated_to"

    name_key = name.casefold()

    # B. System dedicated management
    if dedicated_mgmt_list:
        scoped_blocks = _scoped_items(dedicated_mgmt_list, vdom)
        for block in scoped_blocks:
            status = _first_value(block.get("status")).casefold()
            if status in {"enable", "enabled"}:
                mgmt_intf = _first_value(block.get("interface")).casefold()
                if mgmt_intf and mgmt_intf == name_key:
                    return True, "system_dedicated_mgmt"

    # C. HA reserved management interface
    if ha_mgmt_list:
        scoped_ha = _scoped_items(ha_mgmt_list, vdom)
        for block in scoped_ha:
            status = _first_value(block.get("ha_mgmt_status")).casefold()
            is_enabled = block.get("enabled") or status in {"enable", "enabled"}
            if is_enabled:
                mgmt_intfs = {
                    _first_value(item).casefold()
                    for item in _values(block.get("interfaces"))
                }
                if name_key in mgmt_intfs:
                    return True, "ha_management"

    return False, None


def _resolve_interface_role(
    name: str,
    interface: dict | None,
    dedicated_mgmt_list: list[dict] | None = None,
    ha_mgmt_list: list[dict] | None = None,
    policy_vdom: object = None,
) -> tuple[str, bool, str | None, dict]:
    """Determine role, whether it was inferred, configured role, and management context.

    Explicit MANAGEMENT configuration evidence strictly takes precedence over:
    - set role
    - interface-name heuristics
    - alias heuristics
    """
    configured_role = _first_value(interface.get("role")) if interface else ""
    raw_configured_role = configured_role if configured_role else None

    is_mgmt, mgmt_source = _check_management_evidence(
        name, interface, dedicated_mgmt_list, ha_mgmt_list, policy_vdom
    )
    if is_mgmt:
        return (
            "MANAGEMENT",
            False,
            raw_configured_role,
            {"is_management": True, "source": mgmt_source},
        )

    mgmt_context = {"is_management": False, "source": None}

    role_map = {
        "wan": "WAN",
        "lan": "LAN",
        "dmz": "DMZ",
        "internal": "INTERNAL",
    }
    if configured_role.casefold() in role_map:
        return (
            role_map[configured_role.casefold()],
            False,
            raw_configured_role,
            mgmt_context,
        )

    role = _infer_role_from_name(name)
    if role != "UNKNOWN":
        return role, True, None, mgmt_context

    if interface:
        alias = _first_value(interface.get("alias"))
        if alias:
            alias_role = _infer_role_from_name(alias)
            if alias_role != "UNKNOWN":
                return alias_role, True, None, mgmt_context

    return "UNKNOWN", False, raw_configured_role, mgmt_context


def _infer_zone_role_from_members(
    member_contexts: list[dict],
    allow_vpn: bool = False,
    allow_management: bool = False,
) -> tuple[str, bool]:
    """Derive zone role strictly from resolved member interfaces.

    - all members WAN -> WAN
    - all LAN/internal-compatible members -> LAN/INTERNAL as appropriate
    - all DMZ -> DMZ
    - all MANAGEMENT -> MANAGEMENT (when allow_management is True)
    - mixed/unknown -> UNKNOWN
    """
    if not member_contexts:
        return "UNKNOWN", False

    if any(
        not m.get("resolved") or m.get("role") == "UNKNOWN"
        for m in member_contexts
    ):
        return "UNKNOWN", False

    roles = {m["role"] for m in member_contexts}
    if allow_management and roles == {"MANAGEMENT"}:
        return "MANAGEMENT", True
    if roles == {"WAN"}:
        return "WAN", True
    if roles == {"DMZ"}:
        return "DMZ", True
    if roles == {"LAN"}:
        return "LAN", True
    if roles == {"INTERNAL"}:
        return "INTERNAL", True
    if allow_vpn and roles == {"VPN"}:
        return "VPN", True
    if roles <= INTERNAL_ROLES:
        return "INTERNAL", True

    return "UNKNOWN", False


def _resolve_interface(
    name: str,
    interface_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    vpn_index: dict[str, dict] | None = None,
    visited: set[str] | None = None,
    config: dict | None = None,
) -> dict:
    """Resolve an interface, zone, SD-WAN zone, or built-in wildcard reference."""
    key = name.casefold()
    path = set(visited or set())
    dedicated_mgmt_list = (
        config.get("dedicated_mgmt", []) if isinstance(config, dict) else []
    )
    ha_mgmt_list = (
        config.get("ha_mgmt", []) if isinstance(config, dict) else []
    )

    # 1. Built-in wildcard 'any'
    if key == "any":
        return {
            "name": name,
            "role": "UNKNOWN",
            "role_inferred": False,
            "configured_role": None,
            "management_context": {"is_management": False, "source": None},
            "resolved": True,
            "type": "builtin",
            "source": "builtin",
        }

    # 2. Route-based IPsec interface.  This comes from the Phase1-interface
    # relationship, not from a name guess or the underlying physical WAN.
    if vpn_index and key in vpn_index:
        phase1 = vpn_index[key]
        return {
            "name": name,
            "role": "VPN",
            "role_inferred": False,
            "configured_role": None,
            "management_context": {"is_management": False, "source": None},
            "resolved": True,
            "type": "vpn",
            "source": "ipsec_phase1",
            "phase1_name": phase1.get("name"),
            "parent_interface": _first_value(phase1.get("interface")) or None,
            "remote_gateway": _first_value(phase1.get("remote-gw")) or None,
            "vdom": phase1.get("vdom"),
        }

    # 3. Physical / logical interface in interface_index
    if key in interface_index:
        intf = interface_index[key]
        intf_vdom = intf.get("vdom") or intf.get("configured_vdom")
        (
            role,
            inferred,
            configured_role,
            mgmt_context,
        ) = _resolve_interface_role(
            name, intf, dedicated_mgmt_list, ha_mgmt_list, intf_vdom
        )
        return {
            "name": name,
            "role": role,
            "role_inferred": inferred,
            "configured_role": configured_role,
            "management_context": mgmt_context,
            "resolved": True,
            "type": "interface",
            "source": "interface",
        }

    # 4. System Zone
    if zone_index and key in zone_index:
        if key in path:
            return {
                "name": name,
                "role": "UNKNOWN",
                "role_inferred": False,
                "configured_role": None,
                "management_context": {"is_management": False, "source": None},
                "resolved": True,
                "type": "zone",
                "source": "zone",
                "member_interfaces": [],
                "loop_detected": True,
            }
        path.add(key)
        zone = zone_index[key]
        member_names = _values(zone.get("interfaces"))
        member_contexts = [
            _resolve_interface(
                m,
                interface_index,
                zone_index,
                sdwan_zone_index,
                vpn_index,
                path,
                config=config,
            )
            for m in member_names
        ]
        role, inferred = _infer_zone_role_from_members(
            member_contexts, allow_vpn=True, allow_management=True
        )
        is_mgmt_zone = role == "MANAGEMENT"
        mgmt_context = {
            "is_management": is_mgmt_zone,
            "source": "system_zone_derived" if is_mgmt_zone else None,
        }
        return {
            "name": name,
            "role": role,
            "role_inferred": inferred,
            "configured_role": None,
            "management_context": mgmt_context,
            "resolved": True,
            "type": "zone",
            "source": "zone",
            "member_interfaces": member_names,
            "member_contexts": member_contexts,
        }

    # 5. SD-WAN Zone
    if sdwan_zone_index and key in sdwan_zone_index:
        if key in path:
            return {
                "name": name,
                "role": "UNKNOWN",
                "role_inferred": False,
                "configured_role": None,
                "management_context": {"is_management": False, "source": None},
                "resolved": True,
                "type": "sdwan_zone",
                "source": "sdwan_zone",
                "member_interfaces": [],
                "loop_detected": True,
            }
        path.add(key)
        sd_zone = sdwan_zone_index[key]
        member_names = _values(sd_zone.get("interfaces"))
        member_contexts = [
            _resolve_interface(
                m,
                interface_index,
                zone_index,
                sdwan_zone_index,
                vpn_index,
                path,
                config=config,
            )
            for m in member_names
        ]
        role, inferred = _infer_zone_role_from_members(member_contexts)
        return {
            "name": name,
            "role": role,
            "role_inferred": inferred,
            "configured_role": None,
            "management_context": {"is_management": False, "source": None},
            "resolved": True,
            "type": "sdwan_zone",
            "source": "sdwan_zone",
            "member_interfaces": member_names,
            "member_contexts": member_contexts,
        }

    # 6. Unresolved reference
    is_mgmt, mgmt_source = _check_management_evidence(
        name, None, dedicated_mgmt_list, ha_mgmt_list
    )
    if is_mgmt:
        return {
            "name": name,
            "role": "MANAGEMENT",
            "role_inferred": False,
            "configured_role": None,
            "management_context": {"is_management": True, "source": mgmt_source},
            "resolved": True,
            "type": "interface",
            "source": "system_management",
        }

    role = _infer_role_from_name(name)
    return {
        "name": name,
        "role": role,
        "role_inferred": role != "UNKNOWN",
        "configured_role": None,
        "management_context": {"is_management": False, "source": None},
        "resolved": False,
        "type": "unknown",
        "source": "unknown",
    }


def _interface_context(
    name: str,
    interface_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
) -> dict:
    """Resolve an interface role and retain whether it was inferred."""
    return _resolve_interface(
        name, interface_index, zone_index, sdwan_zone_index, vpn_index, config=config
    )


def classify_interface(interface: dict, config: dict | None = None) -> dict:
    """Classify one parsed interface using the analyzer's shared logic."""
    name = str(interface.get("name", ""))
    interface_index = {name.casefold(): interface} if name else {}
    return _resolve_interface(name, interface_index, config=config)


def _side_role(interface_contexts: list[dict]) -> str:
    """Reduce one or more interface roles to a traffic-direction label."""
    roles = {item["role"] for item in interface_contexts}
    if len(roles) == 1:
        return next(iter(roles))
    if roles and roles <= INTERNAL_ROLES:
        return "INTERNAL"
    return "UNKNOWN"


def _format_subnet(value: object) -> str | None:
    """Format a FortiGate address/netmask pair as a network when possible."""
    values = _values(value)
    if not values:
        return None
    if len(values) >= 2:
        try:
            return str(
                ipaddress.ip_network(f"{values[0]}/{values[1]}", strict=False)
            )
        except ValueError:
            return " ".join(values)
    return values[0]


def _resolve_vip(name: str, vip: dict, address_family: str = "IPv4") -> dict:
    """Return the useful publishing context for a VIP object."""
    return {
        "name": name,
        "type": "vip",
        "address_family": address_family,
        "external_ip": _first_value(vip.get("extip")) or None,
        "external_interface": _first_value(vip.get("extintf")) or None,
        "mapped_ip": _first_value(vip.get("mappedip")) or None,
        "port_forward": _first_value(vip.get("portforward")) or None,
        "external_port": _first_value(vip.get("extport")) or None,
        "mapped_port": _first_value(vip.get("mappedport")) or None,
        "protocol": _first_value(vip.get("protocol")) or None,
    }


def _resolve_address(
    name: str,
    address_index: dict[str, dict],
    group_index: dict[str, dict],
    vip_index: dict[str, dict],
    visited: set[str] | None = None,
    allow_vip: bool = False,
    address_family: str = "IPv4",
) -> dict:
    """Resolve an address, group, VIP, or unknown reference."""
    key = name.casefold()
    path = set(visited or set())

    if key in {"all", "all_ipv4", "all_ipv6"}:
        eff_family = "IPv6" if key == "all_ipv6" or (key == "all" and address_family == "IPv6") else "IPv4"
        return {"name": name, "type": "builtin", "value": key, "address_family": eff_family}

    if allow_vip and key in vip_index:
        return _resolve_vip(name, vip_index[key], address_family=address_family)

    if key in group_index:
        if key in path:
            return {
                "name": name,
                "type": "address_group",
                "address_family": address_family,
                "members": [],
                "loop_detected": True,
            }
        path.add(key)
        members = [
            _resolve_address(
                member,
                address_index,
                group_index,
                vip_index,
                path,
                allow_vip,
                address_family=address_family,
            )
            for member in _values(group_index[key].get("member"))
        ]
        return {
            "name": name,
            "type": "address_group",
            "address_family": address_family,
            "members": members,
        }

    address = address_index.get(key)
    if address is None:
        return {"name": name, "type": "unknown", "address_family": address_family}

    resolved = {"name": name, "type": "address", "address_family": address_family}
    ip6 = _first_value(address.get("ip6"))
    if ip6:
        resolved["ip6"] = ip6
        resolved["subnet"] = ip6
    subnet = _format_subnet(address.get("subnet"))
    if subnet:
        resolved["subnet"] = subnet
    start_ip = _first_value(address.get("start-ip"))
    end_ip = _first_value(address.get("end-ip"))
    if start_ip:
        resolved["start_ip"] = start_ip
    if end_ip:
        resolved["end_ip"] = end_ip
    fqdn = _first_value(address.get("fqdn"))
    if fqdn:
        resolved["fqdn"] = fqdn
    associated_interface = _first_value(
        address.get("associated-interface") or address.get("interface")
    )
    if associated_interface:
        resolved["interface"] = associated_interface
    object_type = _first_value(address.get("type"))
    if object_type:
        resolved["address_type"] = object_type
    return resolved


def _resolve_service(
    name: str,
    service_index: dict[str, dict],
    group_index: dict[str, dict],
    visited: set[str] | None = None,
) -> dict:
    """Resolve a built-in, custom, grouped, or unknown service reference."""
    key = name.casefold()
    upper_name = name.upper()
    path = set(visited or set())

    if upper_name in BUILTIN_SERVICES:
        return {
            "name": name,
            "type": "builtin_service",
            "definition": BUILTIN_SERVICES[upper_name],
        }

    if key in group_index:
        if key in path:
            return {
                "name": name,
                "type": "service_group",
                "members": [],
                "loop_detected": True,
            }
        path.add(key)
        members = [
            _resolve_service(member, service_index, group_index, path)
            for member in _values(group_index[key].get("member"))
        ]
        return {"name": name, "type": "service_group", "members": members}

    service = service_index.get(key)
    if service is None:
        return {"name": name, "type": "unknown"}

    resolved = {"name": name, "type": "custom_service"}
    protocol = _first_value(service.get("protocol"))
    if protocol:
        resolved["protocol"] = protocol
    tcp_ports = _values(service.get("tcp-portrange"))
    udp_ports = _values(service.get("udp-portrange"))
    if tcp_ports:
        resolved["tcp_ports"] = tcp_ports
    if udp_ports:
        resolved["udp_ports"] = udp_ports
    return resolved


def _service_leaves(services: list[dict]) -> list[dict]:
    """Flatten resolved service groups for classification and descriptions."""
    leaves: list[dict] = []
    for service in services:
        members = service.get("members")
        if isinstance(members, list):
            leaves.extend(_service_leaves(members))
        else:
            leaves.append(service)
    return leaves


def _contains_administrative_service(services: list[dict]) -> bool:
    """Identify the small administrative-service set supported by the MVP."""
    for service in _service_leaves(services):
        name = str(service.get("name", "")).upper()
        name_tokens = set(name.replace("-", "_").split("_"))
        if name in ADMIN_SERVICES or name_tokens & ADMIN_SERVICES:
            return True
        ports = _values(service.get("tcp_ports"))
        if any(port in ADMIN_PORTS for port in ports):
            return True
    return False


def _service_names(services: list[dict]) -> set[str]:
    """Return normalized leaf service names."""
    return {
        str(service.get("name", "")).upper()
        for service in _service_leaves(services)
        if service.get("name")
    }


def _determine_flow(
    source_role: str,
    destination_role: str,
    has_vip: bool,
) -> str:
    """Classify the general traffic flow from interface and VIP context."""
    if source_role == "MANAGEMENT" and destination_role == "MANAGEMENT":
        return "MANAGEMENT_TRANSIT"
    if destination_role == "MANAGEMENT":
        return "TO_MANAGEMENT"
    if source_role == "MANAGEMENT":
        return "FROM_MANAGEMENT"

    if source_role == "WAN" and (
        destination_role in INTERNAL_ROLES or has_vip
    ):
        return "INBOUND_PUBLIC"
    if source_role in INTERNAL_ROLES and destination_role == "WAN":
        return "OUTBOUND_INTERNET"
    if source_role in INTERNAL_ROLES and destination_role in INTERNAL_ROLES:
        return "INTERNAL_ACCESS"
    if source_role in INTERNAL_ROLES and destination_role == "VPN":
        return "TO_VPN"
    if source_role == "VPN" and destination_role == "DMZ":
        return "FROM_VPN_DMZ"
    if source_role == "VPN" and destination_role in {"LAN", "INTERNAL"}:
        return "FROM_VPN_INTERNAL"
    if source_role == "VPN" and destination_role == "VPN":
        return "VPN_TRANSIT"
    return "UNKNOWN"


def _direction_confidence(
    source_contexts: list[dict],
    destination_contexts: list[dict],
) -> str:
    """Estimate confidence in the interface-based direction classification."""
    contexts = source_contexts + destination_contexts
    if not contexts or any(item["role"] == "UNKNOWN" for item in contexts):
        return "LOW"
    if any(item["role_inferred"] for item in contexts):
        return "MEDIUM"
    return "HIGH"


def _infer_purpose(
    policy: dict,
    flow_type: str,
    direction_confidence: str,
    resolved_services: list[dict],
    has_vip: bool,
    broad_internal: bool,
) -> tuple[str, str]:
    """Infer a cautious technical purpose from several policy signals."""
    if "disable" in _normalized_values(policy.get("status")):
        return "Disabled Policy", "HIGH"

    service_names = _service_names(resolved_services)
    administrative = _contains_administrative_service(resolved_services)

    if flow_type == "TO_MANAGEMENT":
        return "Management Network Access", direction_confidence
    if flow_type == "FROM_MANAGEMENT":
        return "Management-to-Network Access", direction_confidence
    if flow_type == "MANAGEMENT_TRANSIT":
        return "Management Transit Access", direction_confidence

    if flow_type == "INBOUND_PUBLIC" and administrative:
        return "Remote Administrative Access", direction_confidence
    if flow_type == "INBOUND_PUBLIC" and has_vip:
        return "Public Server Publishing", direction_confidence
    if flow_type == "OUTBOUND_INTERNET":
        return "Internet Access", direction_confidence
    if flow_type == "TO_VPN":
        return "Site-to-Site VPN Access", direction_confidence
    if flow_type == "FROM_VPN_INTERNAL":
        return "VPN-to-Internal Access", direction_confidence
    if flow_type == "FROM_VPN_DMZ":
        return "VPN-to-DMZ Access", direction_confidence
    if flow_type == "VPN_TRANSIT":
        return "VPN Transit Access", direction_confidence
    if broad_internal:
        return "Broad Network Access", direction_confidence
    if flow_type == "INTERNAL_ACCESS":
        if administrative:
            return "Internal Server Access", "MEDIUM"
        if service_names & {"HTTP", "HTTPS"}:
            return "Web Access", "MEDIUM"
        if "DNS" in service_names:
            return "DNS Access", "MEDIUM"
        if service_names & {"SMTP", "IMAP", "POP3"}:
            return "Mail Access", "MEDIUM"
        if service_names & {"MYSQL", "MSSQL", "POSTGRESQL", "ORACLE"}:
            return "Database Access", "MEDIUM"
        return "Inter-VLAN Access", direction_confidence
    if "ALL" in service_names:
        return "Broad Network Access", "LOW"
    return "Custom / Unknown Access", "LOW"


def _join_names(values: object, fallback: str) -> str:
    """Join configured object names for a human-readable assessment."""
    names = _values(values)
    return ", ".join(names) if names else fallback


def _assessment_text(
    policy: dict,
    purpose: str,
    flow_type: str,
    resolved_services: list[dict],
    vip_references: list[dict],
    internet_service_matching: dict | None = None,
) -> str:
    """Create a cautious, human-readable description of a policy."""
    matching = internet_service_matching or {}
    destination_isdb = matching.get("destination", {})
    source_isdb = matching.get("source", {})
    services = ", ".join(
        service.get("name", "unknown")
        for service in _service_leaves(resolved_services)
    ) or "unspecified services"
    src_val = policy.get("srcaddr6") if policy.get("address_family") == "IPv6" else policy.get("srcaddr")
    dst_val = policy.get("dstaddr6") if policy.get("address_family") == "IPv6" else policy.get("dstaddr")
    sources = _join_names(src_val, "unspecified sources")
    destinations = _join_names(dst_val, "unspecified destinations")
    if source_isdb.get("enabled"):
        sources = "Internet Service-selected sources"
    if destination_isdb.get("enabled"):
        labels = [
            str(selector.get("value"))
            for selector in destination_isdb.get("selectors", [])
            if selector.get("value") is not None
        ]
        destinations = "Internet Service destination" + (
            f" ({', '.join(labels)})" if labels else ""
        )
        services = "ISDB-defined services"

    if purpose == "Disabled Policy":
        return (
            "This policy is disabled and does not currently appear to permit "
            "traffic."
        )
    if purpose == "Internet Access":
        if destination_isdb.get("enabled"):
            return (
                f"This policy appears to provide {sources} with access toward "
                f"external networks selected through {destinations}; service "
                "matching is defined by ISDB."
            )
        return (
            f"This policy appears to provide {sources} with {services} access "
            "toward external networks."
        )
    if purpose == "Public Server Publishing":
        vip_name = vip_references[0]["name"] if vip_references else destinations
        return (
            f"This policy appears to publish an internal destination through "
            f"VIP {vip_name} and allow {services} access from external networks."
        )
    if purpose == "Remote Administrative Access":
        return (
            f"This policy appears to allow remote administrative access using "
            f"{services} from {sources} to {destinations}."
        )
    if purpose == "Site-to-Site VPN Access":
        return (
            f"This policy is configured to permit {services} from {sources} "
            "toward a route-based IPsec interface. This describes static "
            "policy intent, not tunnel or routing state."
        )
    if purpose in {"VPN-to-Internal Access", "VPN-to-DMZ Access"}:
        return (
            f"This policy is configured to permit {services} from a "
            f"route-based IPsec interface to {destinations}. This describes "
            "static policy intent, not tunnel or routing state."
        )
    if purpose == "VPN Transit Access":
        return (
            "This policy is configured between route-based IPsec interfaces. "
            "This describes static policy intent, not tunnel or routing state."
        )
    if purpose == "Broad Network Access":
        return (
            "This policy appears to allow broad network access between its "
            "configured source and destination zones."
        )
    if flow_type == "INTERNAL_ACCESS":
        return (
            f"This policy appears to allow {services} access between internal "
            f"network segments from {sources} to {destinations}."
        )
    return (
        f"This policy appears to apply {services} access from {sources} to "
        f"{destinations}; additional network context may be required."
    )


def _security_observations(
    policy: dict,
    traffic_direction: str,
    flow_type: str,
    resolved_services: list[dict],
    vip_references: list[dict],
    source_role: str,
    internet_service_matching: dict | None = None,
) -> list[str]:
    """Create neutral facts without classifying them as vulnerabilities."""
    observations = [f"Traffic direction appears to be {traffic_direction}."]
    service_names = sorted(_service_names(resolved_services))
    matching = internet_service_matching or {}

    if flow_type == "OUTBOUND_INTERNET":
        observations.append("The policy permits outbound Internet access.")
    if matching.get("destination", {}).get("enabled"):
        observations.append(
            "Destination and service matching use Internet Service selectors."
        )
    if matching.get("source", {}).get("enabled"):
        observations.append("Source matching uses Internet Service selectors.")
    src_val = policy.get("srcaddr6") if policy.get("address_family") == "IPv6" else policy.get("srcaddr")
    if source_role == "WAN" and bool(_normalized_values(src_val) & {"all", "all_ipv4", "all_ipv6"}):
        observations.append("External source access is unrestricted.")
    if service_names == ["ALL"]:
        observations.append("Service scope includes all services.")
    elif service_names:
        observations.append(
            f"Service scope is limited to {', '.join(service_names)}."
        )
    for vip in vip_references:
        mapped_ip = vip.get("mapped_ip") or "an unspecified internal address"
        observations.append(
            f"Destination {vip['name']} is a VIP mapped to {mapped_ip}."
        )
    if _normalized_values(policy.get("logtraffic")) & DISABLED_VALUES:
        observations.append("Traffic logging is explicitly disabled.")
    if "disable" in _normalized_values(policy.get("status")):
        observations.append("The policy is currently disabled.")
    return observations


def _assess_policy(
    policy: dict,
    interface_index: dict[str, dict],
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    service_index: dict[str, dict],
    service_group_index: dict[str, dict],
    vip_index: dict[str, dict],
    security_profiles: dict,
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    internet_service_matching: dict | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
    address6_index: dict[str, dict] | None = None,
    address_group6_index: dict[str, dict] | None = None,
    vip6_index: dict[str, dict] | None = None,
) -> tuple[dict, list[dict]]:
    """Resolve, classify, explain, and evaluate one firewall policy."""
    source_interfaces = [
        _interface_context(
            name,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for name in _values(policy.get("srcintf"))
    ]
    destination_interfaces = [
        _interface_context(
            name,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for name in _values(policy.get("dstintf"))
    ]
    source_role = _side_role(source_interfaces)
    destination_role = _side_role(destination_interfaces)
    traffic_direction = f"{source_role} -> {destination_role}"
    direction_confidence = _direction_confidence(
        source_interfaces, destination_interfaces
    )

    internet_service_matching = internet_service_matching or {
        "source": {"enabled": False},
        "destination": {"enabled": False},
    }
    source_isdb_enabled = bool(
        internet_service_matching.get("source", {}).get("enabled")
    )
    destination_isdb_enabled = bool(
        internet_service_matching.get("destination", {}).get("enabled")
    )

    family = policy.get("address_family", "IPv4")
    if family == "IPv6":
        eff_addr_idx = address6_index or {}
        eff_grp_idx = address_group6_index or {}
        eff_vip_idx = vip6_index or {}
        resolved_sources = [] if source_isdb_enabled else [
            _resolve_address(
                name,
                eff_addr_idx,
                eff_grp_idx,
                eff_vip_idx,
                address_family="IPv6",
            )
            for name in _values(policy.get("srcaddr6"))
        ]
        resolved_destinations = [] if destination_isdb_enabled else [
            _resolve_address(
                name,
                eff_addr_idx,
                eff_grp_idx,
                eff_vip_idx,
                allow_vip=True,
                address_family="IPv6",
            )
            for name in _values(policy.get("dstaddr6"))
        ]
        unrestricted_source = (
            not source_isdb_enabled
            and bool(_normalized_values(policy.get("srcaddr6")) & {"all", "all_ipv6"})
        )
        unrestricted_destination = (
            not destination_isdb_enabled
            and bool(_normalized_values(policy.get("dstaddr6")) & {"all", "all_ipv6"})
        )
    elif family == "MIXED_OR_AMBIGUOUS":
        eff_addr_idx = address6_index or {}
        eff_grp_idx = address_group6_index or {}
        eff_vip_idx = vip6_index or {}
        resolved_sources = [
            _resolve_address(name, address_index, address_group_index, vip_index, address_family="IPv4")
            for name in _values(policy.get("srcaddr"))
        ] + [
            _resolve_address(name, eff_addr_idx, eff_grp_idx, eff_vip_idx, address_family="IPv6")
            for name in _values(policy.get("srcaddr6"))
        ]
        resolved_destinations = [
            _resolve_address(name, address_index, address_group_index, vip_index, allow_vip=True, address_family="IPv4")
            for name in _values(policy.get("dstaddr"))
        ] + [
            _resolve_address(name, eff_addr_idx, eff_grp_idx, eff_vip_idx, allow_vip=True, address_family="IPv6")
            for name in _values(policy.get("dstaddr6"))
        ]
        unrestricted_source = False
        unrestricted_destination = False
    else:
        resolved_sources = [] if source_isdb_enabled else [
            _resolve_address(
                name,
                address_index,
                address_group_index,
                vip_index,
                address_family="IPv4",
            )
            for name in _values(policy.get("srcaddr"))
        ]
        resolved_destinations = [] if destination_isdb_enabled else [
            _resolve_address(
                name,
                address_index,
                address_group_index,
                vip_index,
                allow_vip=True,
                address_family="IPv4",
            )
            for name in _values(policy.get("dstaddr"))
        ]
        unrestricted_source = (
            not source_isdb_enabled
            and bool(_normalized_values(policy.get("srcaddr")) & {"all", "all_ipv4"})
        )
        unrestricted_destination = (
            not destination_isdb_enabled
            and bool(_normalized_values(policy.get("dstaddr")) & {"all", "all_ipv4"})
        )

    vip_references = [
        destination
        for destination in resolved_destinations
        if destination.get("type") == "vip"
    ]
    resolved_services = [] if destination_isdb_enabled else [
        _resolve_service(name, service_index, service_group_index)
        for name in _values(policy.get("service"))
    ]

    flow_type = _determine_flow(
        source_role, destination_role, bool(vip_references)
    )
    unrestricted_service = (
        not destination_isdb_enabled
        and "all" in _normalized_values(policy.get("service"))
    )
    broad_internal = (
        flow_type == "INTERNAL_ACCESS"
        and unrestricted_source
        and unrestricted_destination
        and unrestricted_service
    )
    administrative = _contains_administrative_service(resolved_services)

    if family == "MIXED_OR_AMBIGUOUS":
        purpose = "Custom / Unknown Access"
        purpose_confidence = "LOW"
    else:
        purpose, purpose_confidence = _infer_purpose(
            policy,
            flow_type,
            direction_confidence,
            resolved_services,
            bool(vip_references),
            broad_internal,
        )
    assessment = {
        "policy_id": policy.get("id"),
        "policy_name": policy.get("name") or "Unnamed Policy",
        "vdom": policy.get("vdom"),
        "address_family": family,
        "purpose": purpose,
        "purpose_confidence": purpose_confidence,
        "traffic_direction": traffic_direction,
        "flow_type": flow_type,
        "assessment": _assessment_text(
            policy,
            purpose,
            flow_type,
            resolved_services,
            vip_references,
            internet_service_matching,
        ),
        "source_interfaces": source_interfaces,
        "destination_interfaces": destination_interfaces,
        "resolved_sources": resolved_sources,
        "resolved_destinations": resolved_destinations,
        "resolved_services": resolved_services,
        "vip_references": vip_references,
        "internet_service_matching": internet_service_matching,
        "policy_comments": _first_value(policy.get("comments")) or None,
        "operational_settings": {
            field: _first_value(policy.get(field)) or None
            for field in (
                "inspection-mode",
                "logtraffic-start",
                "capture-packet",
                "auto-asic-offload",
            )
        },
        "security_profiles": security_profiles,
        "security_observations": _security_observations(
            policy,
            traffic_direction,
            flow_type,
            resolved_services,
            vip_references,
            source_role,
            internet_service_matching,
        ),
    }

    findings: list[dict] = []
    if "disable" in _normalized_values(policy.get("status")):
        findings.append(
            _finding(
                policy,
                "LOW",
                "Disabled Policy",
                "This firewall policy is disabled. It may be intentionally "
                "retained, but inactive policies can make the configuration "
                "harder to maintain.",
                "Verify whether this policy is still required. If it is "
                "obsolete, consider removing it after appropriate review.",
            )
        )
        return assessment, findings

    if "accept" not in _normalized_values(policy.get("action")):
        return assessment, findings

    internet_admin_access = (
        flow_type == "INBOUND_PUBLIC"
        and administrative
        and unrestricted_source
    )
    broad_inbound = flow_type == "INBOUND_PUBLIC" and unrestricted_service

    if internet_admin_access:
        findings.append(
            _finding(
                policy,
                "HIGH",
                "Internet-Exposed Administrative Access",
                "This policy appears to allow administrative access from "
                "unrestricted external sources. This may be intentional, but "
                "the exposure deserves security review.",
                "Verify the requirement for direct external administrative "
                "access and restrict source access where possible.",
            )
        )

    if broad_inbound:
        findings.append(
            _finding(
                policy,
                "HIGH",
                "Broad Inbound Service Access",
                "This inbound ACCEPT policy allows all services toward an "
                "internal destination or VIP. This broad exposure may be "
                "intentional but deserves security review.",
                "Verify which inbound services are required and restrict the "
                "policy where possible.",
            )
        )

    if broad_internal:
        findings.append(
            _finding(
                policy,
                "MEDIUM",
                "Broad Internal Network Access",
                "This policy permits unrestricted access between internal "
                "network segments. Such breadth may increase lateral-movement "
                "opportunities if an internal system is compromised.",
                "Verify whether unrestricted internal access is required and "
                "segment source, destination, or service scope where possible.",
            )
        )

    logging_disabled = bool(
        _normalized_values(policy.get("logtraffic")) & DISABLED_VALUES
    )
    security_relevant = (
        flow_type == "INBOUND_PUBLIC" or administrative or broad_internal
    )
    if logging_disabled and security_relevant:
        findings.append(
            _finding(
                policy,
                "MEDIUM",
                "Logging Disabled on Security-Relevant Policy",
                "Traffic logging is explicitly disabled on a policy that "
                "appears to provide inbound, administrative, or broad internal "
                "access. This may reduce investigation visibility.",
                "Verify whether traffic logging should be enabled for this "
                "policy based on operational and security requirements.",
            )
        )

    return assessment, findings


def _canonical_values(value: object) -> tuple[str, ...]:
    """Normalize an unordered FortiGate match-value list."""
    return tuple(sorted(item.casefold() for item in _values(value)))


def _canonical_policy_schedule(policy: dict) -> tuple[str, ...]:
    """Normalize an omitted or empty firewall-policy schedule to ``always``."""
    configured_values = tuple(
        sorted(
            item.strip().casefold()
            for item in _values(policy.get("schedule"))
            if item.strip()
        )
    )
    return configured_values or ("always",)


def _enabled_policy(policy: dict) -> bool:
    return not bool(
        _normalized_values(policy.get("status")) & {"disable", "disabled"}
    )


def _has_unsupported_match_conditions(policy: dict) -> bool:
    """Identify explicit selectors this MVP cannot compare safely."""
    for key, value in policy.items():
        normalized_key = str(key).casefold()
        is_unsupported = (
            normalized_key in UNSUPPORTED_MATCH_FIELDS
            or normalized_key.startswith("internet-service-")
            or normalized_key.startswith("ztna-")
        )
        if not is_unsupported:
            continue
        normalized_value = _normalized_values(value)
        if normalized_value and not normalized_value <= {
            "disable",
            "disabled",
            "none",
        }:
            return True
    return False


def _has_required_match_fields(policy: dict) -> bool:
    family = policy.get("address_family", "IPv4")
    src_field = "srcaddr6" if family == "IPv6" else "srcaddr"
    dst_field = "dstaddr6" if family == "IPv6" else "dstaddr"
    return all(
        _values(policy.get(field))
        for field in (
            "srcintf",
            "dstintf",
            src_field,
            dst_field,
            "service",
            "action",
        )
    )


def _exact_policy_match(earlier: dict, later: dict) -> bool:
    """Compare only the matching dimensions defined for duplicate detection."""
    earlier_family = earlier.get("address_family", "IPv4")
    later_family = later.get("address_family", "IPv4")
    if earlier_family != later_family or earlier_family in {"MIXED_OR_AMBIGUOUS", "UNKNOWN"}:
        return False
    if not _has_required_match_fields(earlier) or not _has_required_match_fields(
        later
    ):
        return False
    src_field = "srcaddr6" if earlier_family == "IPv6" else "srcaddr"
    dst_field = "dstaddr6" if earlier_family == "IPv6" else "dstaddr"
    fields = (
        "srcintf",
        "dstintf",
        src_field,
        dst_field,
        "service",
        "action",
    )
    return (
        _canonical_policy_schedule(earlier)
        == _canonical_policy_schedule(later)
        and all(
            _canonical_values(earlier.get(field))
            == _canonical_values(later.get(field))
            for field in fields
        )
    )


def _interface_contains(earlier: object, later: object) -> bool:
    earlier_values = set(_canonical_values(earlier))
    later_values = set(_canonical_values(later))
    if not earlier_values or not later_values:
        return False
    if "any" in earlier_values:
        return True
    if "any" in later_values:
        return False
    return earlier_values >= later_values


def _address_reference_atoms(
    name: str,
    address_index: dict[str, dict],
    group_index: dict[str, dict],
    vip_index: dict[str, dict],
    visited: set[str] | None = None,
    family: str = "IPv4",
) -> list[tuple] | None:
    """Resolve one address reference into conservative comparable atoms."""
    key = name.casefold()
    path = set(visited or set())
    if key == "all":
        return [("all_ipv6",)] if family == "IPv6" else [("all_ipv4",)]
    if key == "all_ipv4":
        return [("all_ipv4",)]
    if key == "all_ipv6":
        return [("all_ipv6",)]
    if key in vip_index:
        return [("object", key)]
    if key in group_index:
        if key in path:
            return None
        path.add(key)
        members = _values(group_index[key].get("member"))
        if not members:
            return None
        atoms: list[tuple] = []
        for member in members:
            member_atoms = _address_reference_atoms(
                member,
                address_index,
                group_index,
                vip_index,
                path,
                family=family,
            )
            if member_atoms is None:
                return None
            atoms.extend(member_atoms)
        return atoms

    address = address_index.get(key)
    if address is None:
        return None
    address_type = _first_value(address.get("type")).casefold()
    if address_type in {
        "geography",
        "dynamic",
        "wildcard",
        "wildcard-fqdn",
        "mac",
    }:
        return None

    ip6_values = _values(address.get("ip6"))
    if ip6_values:
        try:
            subnet = ipaddress.ip_network(ip6_values[0], strict=False)
            return [("network", subnet)]
        except ValueError:
            return None

    subnet_values = _values(address.get("subnet"))
    if subnet_values:
        try:
            subnet = (
                ipaddress.ip_network(
                    f"{subnet_values[0]}/{subnet_values[1]}", strict=False
                )
                if len(subnet_values) >= 2
                else ipaddress.ip_network(subnet_values[0], strict=False)
            )
            return [("network", subnet)]
        except ValueError:
            return None

    start_ip = _first_value(address.get("start-ip"))
    end_ip = _first_value(address.get("end-ip"))
    if start_ip and end_ip:
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            if start.version != end.version or int(start) > int(end):
                return None
            return [("range", start, end)]
        except ValueError:
            return None

    if address.get("fqdn"):
        return [("object", key)]
    return None


def _address_atoms(
    references: object,
    address_index: dict[str, dict],
    group_index: dict[str, dict],
    vip_index: dict[str, dict],
    family: str = "IPv4",
) -> list[tuple] | None:
    names = _values(references)
    if not names:
        return None
    atoms: list[tuple] = []
    for name in names:
        resolved = _address_reference_atoms(
            name, address_index, group_index, vip_index, family=family
        )
        if resolved is None:
            return None
        atoms.extend(resolved)
    return atoms


def _address_atom_contains(earlier: tuple, later: tuple) -> bool:
    if earlier[0] == "all":
        return True
    if earlier[0] == "all_ipv4":
        if later[0] == "network":
            return later[1].version == 4
        if later[0] == "range":
            return later[1].version == 4
        return later[0] == "all_ipv4"
    if earlier[0] == "all_ipv6":
        if later[0] == "network":
            return later[1].version == 6
        if later[0] == "range":
            return later[1].version == 6
        return later[0] == "all_ipv6"
    if earlier[0] == "object" or later[0] == "object":
        return earlier == later
    if earlier[0] == "network" and later[0] == "network":
        return (
            earlier[1].version == later[1].version
            and later[1].subnet_of(earlier[1])
        )
    if earlier[0] == "network" and later[0] == "range":
        return (
            earlier[1].version == later[1].version
            and later[1] in earlier[1]
            and later[2] in earlier[1]
        )
    if earlier[0] == "range" and later[0] == "network":
        return (
            earlier[1].version == later[1].version
            and int(earlier[1]) <= int(later[1].network_address)
            and int(earlier[2]) >= int(later[1].broadcast_address)
        )
    if earlier[0] == "range" and later[0] == "range":
        return (
            earlier[1].version == later[1].version
            and int(earlier[1]) <= int(later[1])
            and int(earlier[2]) >= int(later[2])
        )
    return False


def _address_contains(earlier: list[tuple], later: list[tuple]) -> bool:
    return all(
        any(_address_atom_contains(candidate, item) for candidate in earlier)
        for item in later
    )


def _parse_port_ranges(value: object) -> list[tuple[int, int]] | None:
    raw_parts = re.split(r"[\s,]+", " ".join(_values(value)).strip())
    parts = [part for part in raw_parts if part]
    if not parts:
        return []
    ranges: list[tuple[int, int]] = []
    for part in parts:
        destination_part = part.split(":", 1)[0]
        try:
            if "-" in destination_part:
                start_text, end_text = destination_part.split("-", 1)
                start, end = int(start_text), int(end_text)
            else:
                start = end = int(destination_part)
        except ValueError:
            return None
        if not (0 <= start <= end <= 65535):
            return None
        ranges.append((start, end))
    return ranges


def _builtin_service_atoms(name: str) -> list[tuple] | None:
    upper_name = name.upper()
    if upper_name == "ALL":
        return [("all",)]
    if upper_name == "ALL_TCP":
        return [("tcp", 0, 65535)]
    if upper_name == "ALL_UDP":
        return [("udp", 0, 65535)]
    if upper_name in {"ALL_ICMP", "ALL_ICMP6", "PING"}:
        return [("icmp", 0, 0)]
    definition = BUILTIN_SERVICES.get(upper_name)
    if not definition:
        return None
    try:
        protocol_text, port_text = definition.rsplit("/", 1)
        port = int(port_text)
    except ValueError:
        return None
    return [
        (protocol.casefold(), port, port)
        for protocol in protocol_text.split("/")
    ]


def _service_reference_atoms(
    name: str,
    service_index: dict[str, dict],
    group_index: dict[str, dict],
    visited: set[str] | None = None,
) -> list[tuple] | None:
    builtin = _builtin_service_atoms(name)
    if builtin is not None:
        return builtin
    key = name.casefold()
    path = set(visited or set())
    if key in group_index:
        if key in path:
            return None
        path.add(key)
        members = _values(group_index[key].get("member"))
        if not members:
            return None
        atoms: list[tuple] = []
        for member in members:
            member_atoms = _service_reference_atoms(
                member, service_index, group_index, path
            )
            if member_atoms is None:
                return None
            atoms.extend(member_atoms)
        return atoms

    service = service_index.get(key)
    if service is None:
        return None
    atoms: list[tuple] = []
    for field, protocol in (
        ("tcp-portrange", "tcp"),
        ("udp-portrange", "udp"),
    ):
        ranges = _parse_port_ranges(service.get(field))
        if ranges is None:
            return None
        atoms.extend((protocol, start, end) for start, end in ranges)
    if atoms:
        return atoms
    if _first_value(service.get("protocol")).casefold() in {"icmp", "icmp6"}:
        return [("icmp", 0, 0)]
    return None


def _service_atoms(
    references: object,
    service_index: dict[str, dict],
    group_index: dict[str, dict],
) -> list[tuple] | None:
    names = _values(references)
    if not names:
        return None
    atoms: list[tuple] = []
    for name in names:
        resolved = _service_reference_atoms(name, service_index, group_index)
        if resolved is None:
            return None
        atoms.extend(resolved)
    return atoms


def _service_contains(earlier: list[tuple], later: list[tuple]) -> bool:
    return all(
        any(
            candidate[0] == "all"
            or (
                len(candidate) == 3
                and len(item) == 3
                and candidate[0] == item[0]
                and candidate[1] <= item[1]
                and candidate[2] >= item[2]
            )
            for candidate in earlier
        )
        for item in later
    )


def _schedule_compatible(earlier: dict, later: dict) -> bool:
    """Compare schedules after applying FortiGate's default ``always`` value."""
    return _canonical_policy_schedule(earlier) == _canonical_policy_schedule(
        later
    )


def _policy_covers(
    earlier: dict,
    later: dict,
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    service_index: dict[str, dict],
    service_group_index: dict[str, dict],
    vip_index: dict[str, dict],
) -> bool:
    """Return true only when every supported match dimension is contained."""
    earlier_family = earlier.get("address_family", "IPv4")
    later_family = later.get("address_family", "IPv4")
    if earlier_family != later_family or earlier_family in {"MIXED_OR_AMBIGUOUS", "UNKNOWN"}:
        return False
    if not _has_required_match_fields(earlier) or not _has_required_match_fields(
        later
    ):
        return False
    if not _schedule_compatible(earlier, later):
        return False
    if not _interface_contains(earlier.get("srcintf"), later.get("srcintf")):
        return False
    if not _interface_contains(earlier.get("dstintf"), later.get("dstintf")):
        return False

    src_field = "srcaddr6" if earlier_family == "IPv6" else "srcaddr"
    dst_field = "dstaddr6" if earlier_family == "IPv6" else "dstaddr"

    earlier_sources = _address_atoms(
        earlier.get(src_field), address_index, address_group_index, vip_index, family=earlier_family
    )
    later_sources = _address_atoms(
        later.get(src_field), address_index, address_group_index, vip_index, family=later_family
    )
    earlier_destinations = _address_atoms(
        earlier.get(dst_field), address_index, address_group_index, vip_index, family=earlier_family
    )
    later_destinations = _address_atoms(
        later.get(dst_field), address_index, address_group_index, vip_index, family=later_family
    )
    earlier_services = _service_atoms(
        earlier.get("service"), service_index, service_group_index
    )
    later_services = _service_atoms(
        later.get("service"), service_index, service_group_index
    )
    resolved_dimensions = (
        earlier_sources,
        later_sources,
        earlier_destinations,
        later_destinations,
        earlier_services,
        later_services,
    )
    if any(value is None for value in resolved_dimensions):
        return False
    return (
        _address_contains(earlier_sources, later_sources)
        and _address_contains(earlier_destinations, later_destinations)
        and _service_contains(earlier_services, later_services)
    )


def _relationship_finding(
    earlier: dict,
    later: dict,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    earlier_position: int,
    later_position: int,
) -> dict:
    finding = _finding(later, severity, title, description, recommendation)
    finding.update(
        {
            "shadowed_by_policy_id": earlier.get("id"),
            "shadowed_by_policy_name": earlier.get("name") or "Unnamed Policy",
            "earlier_sequence": earlier.get("sequence_index", earlier_position),
            "later_sequence": later.get("sequence_index", later_position),
        }
    )
    return finding


def _analyze_policy_order(config: dict) -> list[dict]:
    """Detect conservative duplicate and full-shadow relationships."""
    policies = [
        policy
        for policy in config.get("policies", [])
        if isinstance(policy, dict)
    ]
    findings: list[dict] = []

    for later_position, later in enumerate(policies):
        if not _enabled_policy(later) or _has_unsupported_match_conditions(later):
            continue
        later_family = later.get("address_family", "IPv4")
        if later_family in {"MIXED_OR_AMBIGUOUS", "UNKNOWN"}:
            continue
        for earlier_position in range(later_position):
            earlier = policies[earlier_position]
            if not _same_vdom(earlier, later):
                continue
            if not _enabled_policy(earlier) or _has_unsupported_match_conditions(
                earlier
            ):
                continue
            earlier_family = earlier.get("address_family", "IPv4")
            if earlier_family != later_family or earlier_family in {"MIXED_OR_AMBIGUOUS", "UNKNOWN"}:
                continue

            if _exact_policy_match(earlier, later):
                findings.append(
                    _relationship_finding(
                        earlier,
                        later,
                        "LOW",
                        "Duplicate Firewall Policy",
                        "This later policy appears to duplicate the matching "
                        "criteria and action of an earlier enabled policy and "
                        "may be redundant.",
                        "Review whether both policies are intentionally retained; "
                        "do not remove either rule without validating its purpose.",
                        earlier_position,
                        later_position,
                    )
                )
                break

            policy_vdom = later.get("vdom")
            if later_family == "IPv6":
                address_index = _index_by_name(
                    _scoped_items(config.get("addresses6", []), policy_vdom)
                )
                address_group_index = _index_by_name(
                    _scoped_items(config.get("address_groups6", []), policy_vdom)
                )
                vip_index = _index_by_name(
                    _scoped_items(config.get("vips6", []), policy_vdom)
                )
            else:
                address_index = _index_by_name(
                    _scoped_items(config.get("addresses", []), policy_vdom)
                )
                address_group_index = _index_by_name(
                    _scoped_items(config.get("address_groups", []), policy_vdom)
                )
                vip_index = _index_by_name(
                    _scoped_items(config.get("vips", []), policy_vdom)
                )
            service_index = _index_by_name(
                _scoped_items(config.get("services", []), policy_vdom)
            )
            service_group_index = _index_by_name(
                _scoped_items(config.get("service_groups", []), policy_vdom)
            )

            if not _policy_covers(
                earlier,
                later,
                address_index,
                address_group_index,
                service_index,
                service_group_index,
                vip_index,
            ):
                continue

            actions_match = _canonical_values(earlier.get("action")) == (
                _canonical_values(later.get("action"))
            )
            if actions_match:
                findings.append(
                    _relationship_finding(
                        earlier,
                        later,
                        "MEDIUM",
                        "Fully Shadowed Firewall Policy",
                        "This later policy appears to be fully covered by an "
                        "earlier enabled policy with the same action and may "
                        "never be evaluated for matching traffic.",
                        "Review the policy order and confirm whether the later "
                        "rule is intentionally retained.",
                        earlier_position,
                        later_position,
                    )
                )
            else:
                findings.append(
                    _relationship_finding(
                        earlier,
                        later,
                        "HIGH",
                        "Conflicting Policy Shadowing",
                        "This later policy appears to be fully covered by an "
                        "earlier enabled policy with a different action, so the "
                        "later rule's intended action may never be reached.",
                        "Review policy order and matching scope to confirm that "
                        "the intended action is reachable.",
                        earlier_position,
                        later_position,
                    )
                )
            break

    return findings


def _assess_local_in_policy(
    policy: dict,
    interface_index: dict[str, dict],
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    service_index: dict[str, dict],
    service_group_index: dict[str, dict],
    vip_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    internet_service_matching: dict | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
    address_family: str = "IPv4",
) -> dict:
    """Resolve, classify, explain, and evaluate one local-in firewall policy.

    Keeps configuration facts, resolved context, and technical interpretation
    in separate structured layers.
    """
    family = policy.get("address_family", address_family)
    intf_names = _values(policy.get("intf") or policy.get("srcintf"))
    source_interfaces = [
        _interface_context(
            name,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for name in intf_names
    ]
    interface_role = _side_role(source_interfaces)

    internet_service_matching = internet_service_matching or {
        "source": {"enabled": False},
        "destination": {"enabled": False},
    }
    isdb_source = internet_service_matching.get("source", {})
    source_isdb_enabled = bool(isdb_source.get("enabled"))

    srcaddr_vals = _values(policy.get("srcaddr6")) or _values(policy.get("srcaddr"))
    dstaddr_vals = _values(policy.get("dstaddr6")) or _values(policy.get("dstaddr"))
    service_vals = _values(policy.get("service6")) or _values(policy.get("service"))

    resolved_sources = [] if source_isdb_enabled else [
        _resolve_address(
            name,
            address_index,
            address_group_index,
            vip_index,
            address_family=family,
        )
        for name in srcaddr_vals
    ]
    resolved_destinations = [
        _resolve_address(
            name,
            address_index,
            address_group_index,
            vip_index,
            address_family=family,
        )
        for name in dstaddr_vals
    ]
    resolved_services = [
        _resolve_service(name, service_index, service_group_index)
        for name in service_vals
    ]

    action = _first_value(policy.get("action"), "deny").casefold()
    status = _first_value(policy.get("status"), "enable").casefold()
    is_disabled = status in {"disable", "disabled"}
    service_names = _service_names(resolved_services)
    administrative = _contains_administrative_service(resolved_services) or bool(
        service_names & {"SSH", "HTTPS", "HTTP", "TELNET"}
    )
    vpn_services = bool(
        service_names & {"IKE", "IPSEC", "L2TP", "PPTP"}
    ) or any("IKE" in s or "IPSEC" in s for s in service_names)

    if is_disabled:
        purpose = "Disabled Local-In Policy"
    elif interface_role == "MANAGEMENT" and administrative:
        purpose = "Management Interface Access to FortiGate"
    elif interface_role == "WAN" and administrative:
        purpose = "Administrative Service Access to FortiGate"
    elif interface_role == "VPN" or vpn_services:
        purpose = "VPN Service Access to FortiGate"
    elif "PING" in service_names:
        purpose = "Diagnostic Access to FortiGate"
    else:
        purpose = "Local Service Access to FortiGate"

    if is_disabled:
        assessment_text = (
            "This local-in policy is disabled and does not currently filter traffic."
        )
    elif action == "accept":
        assessment_text = (
            "This local-in policy is configured to accept matching local-in "
            "traffic bound for the FortiGate."
        )
    else:
        assessment_text = (
            "This local-in policy is configured to deny matching local-in "
            "traffic bound for the FortiGate."
        )

    observations = [
        "Local-in traffic target is the FortiGate unit itself.",
        f"Interface context is {interface_role}.",
    ]
    if is_disabled:
        observations.append("The policy is currently disabled.")
    elif action == "accept":
        observations.append("Configured action is ACCEPT for matching local-in traffic.")
    else:
        observations.append("Configured action is DENY for matching local-in traffic.")

    if _is_enabled(policy.get("srcaddr-negate")):
        observations.append("Source address matching is negated.")
    if _is_enabled(policy.get("dstaddr-negate")):
        observations.append("Destination address matching is negated.")
    if _is_enabled(policy.get("service-negate")):
        observations.append("Service matching is negated.")
    if _first_value(policy.get("ha-mgmt-intf-only")).casefold() in {"enable", "enabled"}:
        observations.append("Policy applies to HA management interface only.")
    if policy.get("virtual-patch"):
        observations.append("Virtual patch metadata is attached.")

    return {
        "policy_id": policy.get("id"),
        "sequence_index": policy.get("sequence_index"),
        "vdom": policy.get("vdom"),
        "address_family": family,
        "status": status,
        "action": action,
        "technical_context": "FORTIGATE_LOCAL_IN",
        "purpose": purpose,
        "assessment": assessment_text,
        "interface_context": interface_role,
        "source_interfaces": source_interfaces,
        "resolved_sources": resolved_sources,
        "resolved_destinations": resolved_destinations,
        "resolved_services": resolved_services,
        "internet_service_source": isdb_source,
        "srcaddr_negate": _is_enabled(policy.get("srcaddr-negate")),
        "dstaddr_negate": _is_enabled(policy.get("dstaddr-negate")),
        "service_negate": _is_enabled(policy.get("service-negate")),
        "ha_mgmt_intf_only": policy.get("ha-mgmt-intf-only"),
        "virtual_patch": policy.get("virtual-patch"),
        "configured_facts": {
            "intf": intf_names,
            "srcaddr": _values(policy.get("srcaddr")),
            "dstaddr": _values(policy.get("dstaddr")),
            "service": _values(policy.get("service")),
            "schedule": _first_value(policy.get("schedule")),
            "comments": _first_value(policy.get("comments")) or None,
        },
        "security_observations": observations,
    }


INTERFACE_POLICY_PROFILE_SPECS = {
    "ips": {
        "status_field": "ips-sensor-status",
        "name_field": "ips-sensor",
        "config_key": "ips_sensors",
        "label": "IPS",
    },
    "antivirus": {
        "status_field": "av-profile-status",
        "name_field": "av-profile",
        "config_key": "antivirus_profiles",
        "label": "Antivirus",
    },
    "web_filter": {
        "status_field": "webfilter-profile-status",
        "name_field": "webfilter-profile",
        "config_key": "webfilter_profiles",
        "label": "Web Filter",
    },
    "application_control": {
        "status_field": "application-list-status",
        "name_field": "application-list",
        "config_key": "application_lists",
        "label": "Application Control",
    },
    "email_filter": {
        "status_field": "emailfilter-profile-status",
        "name_field": "emailfilter-profile",
        "config_key": "emailfilter_profiles",
        "label": "Email Filter",
    },
    "dlp": {
        "status_fields": ("dlp-profile-status", "dlp-sensor-status"),
        "name_fields": ("dlp-profile", "dlp-sensor"),
        "config_key": "dlp_profiles",
        "label": "DLP",
    },
    "casb": {
        "status_field": "casb-profile-status",
        "name_field": "casb-profile",
        "config_key": "casb_profiles",
        "label": "CASB",
    },
}


def resolve_interface_policy_security_profiles(
    policy: dict, config: dict
) -> dict[str, dict]:
    """Resolve interface-policy inspection profiles with strict separation of facts.

    Preserves:
    - configured_reference (name of profile if configured, or None)
    - activation_status ("ENABLED", "DISABLED", "NOT_OBSERVED")
    - active (True only if policy is enabled AND activation_status is "ENABLED" AND reference exists)
    - resolved (True, False, or None if reference is absent)
    - source ("custom", "built-in", or None)
    - vdom
    """
    resolved_profiles: dict[str, dict] = {}
    policy_vdom = policy.get("vdom")
    policy_status = _first_value(policy.get("status"), "enable").casefold()
    is_policy_enabled = policy_status not in {"disable", "disabled"}

    for profile_type, spec in INTERFACE_POLICY_PROFILE_SPECS.items():
        # 1. Determine activation status from status field
        status_val = None
        if "status_field" in spec:
            raw_status = policy.get(spec["status_field"])
            if raw_status is not None:
                status_val = _first_value(raw_status).casefold()
        elif "status_fields" in spec:
            for field in spec["status_fields"]:
                if policy.get(field) is not None:
                    status_val = _first_value(policy.get(field)).casefold()
                    break

        if status_val in {"enable", "enabled"}:
            activation_status = "ENABLED"
        elif status_val in {"disable", "disabled"}:
            activation_status = "DISABLED"
        elif status_val is not None and str(status_val).strip() != "":
            activation_status = status_val.upper()
        else:
            activation_status = "NOT_OBSERVED"

        # 2. Determine configured reference from name field
        name = None
        if "name_field" in spec:
            raw_name = policy.get(spec["name_field"])
            if raw_name is not None and str(raw_name).strip() != "":
                name = _first_value(raw_name).strip()
        elif "name_fields" in spec:
            for field in spec["name_fields"]:
                raw_name = policy.get(field)
                if raw_name is not None and str(raw_name).strip() != "":
                    name = _first_value(raw_name).strip()
                    break

        # 3. Determine resolution
        if name:
            normalized_name = name.casefold()
            config_key = spec["config_key"]
            custom_profiles = _index_by_name(
                _scoped_items(config.get(config_key, []), policy_vdom)
            )
            builtins = BUILTIN_SECURITY_PROFILES.get(profile_type, set())
            if normalized_name in custom_profiles:
                is_resolved = True
                source = "custom"
                resolved_vdom = custom_profiles[normalized_name].get("vdom")
            elif normalized_name in builtins or normalized_name == "default":
                is_resolved = True
                source = "built-in"
                resolved_vdom = None
            else:
                is_resolved = False
                source = None
                resolved_vdom = None
        else:
            is_resolved = None
            source = None
            resolved_vdom = None

        # 4. Determine whether active
        if not is_policy_enabled:
            active = False
        elif activation_status == "ENABLED" and name:
            active = True
        elif activation_status == "NOT_OBSERVED" and name:
            active = "unknown"
        else:
            active = False

        resolved_profiles[profile_type] = {
            "profile_type": profile_type,
            "label": spec["label"],
            "name": name,
            "configured_reference": name,
            "activation_status": activation_status,
            "active": active,
            "resolved": is_resolved,
            "source": source,
            "vdom": resolved_vdom,
        }

    return resolved_profiles


def _assess_interface_policy(
    policy: dict,
    interface_index: dict[str, dict],
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    service_index: dict[str, dict],
    service_group_index: dict[str, dict],
    vip_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
    address_family: str = "IPv4",
) -> dict:
    """Assess one interface inspection policy safely and neutrally."""
    family = policy.get("address_family", address_family)
    policy_id = policy.get("id")
    sequence_index = policy.get("sequence_index")
    vdom = policy.get("vdom")
    status = _first_value(policy.get("status"), "enable").casefold()
    is_disabled = status in {"disable", "disabled"}

    # 1. Interface resolution
    intf_raw = policy.get("interface") or policy.get("intf")
    intf_names = _values(intf_raw)
    resolved_interfaces = [
        _interface_context(
            name,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for name in intf_names
    ]
    if resolved_interfaces:
        primary_intf = resolved_interfaces[0]
        intf_name = primary_intf.get("name")
        effective_context = primary_intf.get("role", "UNKNOWN")
    else:
        intf_name = None
        effective_context = "UNKNOWN"
        primary_intf = {
            "name": None,
            "role": "UNKNOWN",
            "role_inferred": False,
            "configured_role": None,
            "management_context": {"is_management": False, "source": None},
            "resolved": False,
            "type": "unknown",
            "source": "unknown",
        }

    # 2. Address & Service resolution
    src_keys = policy.get("srcaddr6") if family == "IPv6" else policy.get("srcaddr")
    dst_keys = policy.get("dstaddr6") if family == "IPv6" else policy.get("dstaddr")
    svc_keys = (
        (policy.get("service6") or policy.get("service"))
        if family == "IPv6"
        else policy.get("service")
    )
    resolved_sources = [
        _resolve_address(
            name,
            address_index,
            address_group_index,
            vip_index,
            address_family=family,
        )
        for name in _values(src_keys)
    ]
    resolved_destinations = [
        _resolve_address(
            name,
            address_index,
            address_group_index,
            vip_index,
            address_family=family,
        )
        for name in _values(dst_keys)
    ]
    resolved_services = [
        _resolve_service(name, service_index, service_group_index)
        for name in _values(svc_keys)
    ]

    # 3. Inspection profiles resolution
    cfg = config if isinstance(config, dict) else {}
    inspection_profiles = resolve_interface_policy_security_profiles(policy, cfg)

    # Active profiles: profiles where active is True
    active_profile_types = [
        ptype
        for ptype, pinfo in inspection_profiles.items()
        if pinfo.get("active") is True
    ]

    # 4. Neutral Purpose determination
    if is_disabled:
        purpose = "Disabled Interface Policy"
    elif "ips" in active_profile_types and len(active_profile_types) == 1:
        purpose = "Interface Traffic IPS Inspection"
    elif "antivirus" in active_profile_types and len(active_profile_types) == 1:
        purpose = "Interface Traffic Malware Inspection"
    elif len(active_profile_types) > 1:
        purpose = "Interface Traffic Security Inspection"
    else:
        purpose = "Interface Traffic Monitoring / Inspection Policy"

    # 5. Neutral Security Observations
    observations = [
        "Interface inspection policy applied prior to standard firewall policy processing.",
        f"Attached interface: {intf_name or 'unspecified'} (effective context: {effective_context}).",
    ]
    if is_disabled:
        observations.append("The interface policy is currently disabled.")
    elif active_profile_types:
        labels = [inspection_profiles[pt]["label"] for pt in active_profile_types]
        observations.append(f"Active inspection profiles: {', '.join(labels)}.")
    else:
        observations.append("No active inspection profiles are enabled.")

    logtraffic = _first_value(policy.get("logtraffic"))
    if logtraffic:
        observations.append(f"Traffic logging: {logtraffic}.")

    dsri = _first_value(policy.get("dsri"))
    if dsri:
        observations.append(f"DSRI (Direct Server Return Immunity): {dsri}.")

    comments = _first_value(policy.get("comments"))

    return {
        "policy_id": policy_id,
        "sequence_index": sequence_index,
        "vdom": vdom,
        "address_family": family,
        "status": status,
        "technical_context": "INTERFACE_INSPECTION_POLICY",
        "purpose": purpose,
        "interface": intf_name,
        "interface_context": primary_intf,
        "interfaces": resolved_interfaces,
        "resolved_sources": resolved_sources,
        "resolved_destinations": resolved_destinations,
        "resolved_services": resolved_services,
        "inspection_profiles": inspection_profiles,
        "active_profiles": active_profile_types,
        "configured_facts": {
            "interface": intf_names,
            "srcaddr": _values(src_keys),
            "dstaddr": _values(dst_keys),
            "service": _values(svc_keys),
            "logtraffic": logtraffic or None,
            "dsri": dsri or None,
            "comments": comments or None,
        },
        "security_observations": observations,
    }


BUILTIN_SSL_VPN_PORTALS = {
    "full-access",
    "web-access",
    "tunnel-access",
}


def _assess_ssl_vpn_portal(
    portal: dict,
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
) -> dict:
    """Assess one SSL-VPN web portal definition neutrally."""
    name = portal.get("name")
    vdom = portal.get("vdom")

    tunnel_raw = _first_value(portal.get("tunnel-mode"))
    if tunnel_raw.casefold() in {"enable", "enabled"}:
        tunnel_mode = "ENABLED"
    elif tunnel_raw.casefold() in {"disable", "disabled"}:
        tunnel_mode = "DISABLED"
    else:
        tunnel_mode = "NOT_OBSERVED"

    web_raw = _first_value(portal.get("web-mode"))
    if web_raw.casefold() in {"enable", "enabled"}:
        web_mode = "ENABLED"
    elif web_raw.casefold() in {"disable", "disabled"}:
        web_mode = "DISABLED"
    else:
        web_mode = "NOT_OBSERVED"

    split_raw = _first_value(portal.get("split-tunneling"))
    if split_raw.casefold() in {"enable", "enabled"}:
        split_tunneling = "ENABLED"
    elif split_raw.casefold() in {"disable", "disabled"}:
        split_tunneling = "DISABLED"
    else:
        split_tunneling = "NOT_OBSERVED"

    split_routing_addresses = _values(portal.get("split-tunneling-routing-address"))
    resolved_split_addresses = [
        _resolve_address(addr, address_index, address_group_index, {})
        for addr in split_routing_addresses
    ]

    ip_pools = _values(portal.get("ip-pools"))
    ipv6_pools = _values(portal.get("ipv6-pools"))

    if tunnel_mode == "ENABLED" and web_mode == "ENABLED":
        mode_summary = "DUAL_MODE"
        purpose = "SSL-VPN Dual-Mode Portal"
    elif tunnel_mode == "ENABLED":
        mode_summary = "TUNNEL"
        purpose = "SSL-VPN Tunnel Portal"
    elif web_mode == "ENABLED":
        mode_summary = "WEB"
        purpose = "SSL-VPN Web Portal"
    elif tunnel_mode == "DISABLED" and web_mode == "DISABLED":
        mode_summary = "DISABLED"
        purpose = "Disabled SSL-VPN Portal"
    else:
        mode_summary = "NOT_OBSERVED"
        purpose = "SSL-VPN Web Portal"

    return {
        "name": name,
        "vdom": vdom,
        "tunnel_mode": tunnel_mode,
        "web_mode": web_mode,
        "mode_summary": mode_summary,
        "split_tunneling": split_tunneling,
        "split_routing_addresses": split_routing_addresses,
        "resolved_split_routing_addresses": resolved_split_addresses,
        "ip_pools": ip_pools,
        "ipv6_pools": ipv6_pools,
        "purpose": purpose,
        "technical_context": "SSL_VPN_PORTAL",
        "configured_facts": {
            "tunnel-mode": portal.get("tunnel-mode"),
            "web-mode": portal.get("web-mode"),
            "split-tunneling": portal.get("split-tunneling"),
            "split-tunneling-routing-address": split_routing_addresses,
            "ip-pools": ip_pools,
            "comments": portal.get("comments"),
        },
    }


def _assess_ssl_vpn_auth_rule(
    rule: dict,
    portal_index: dict[str, dict],
    group_index: dict[str, dict],
    user_index: dict[str, dict],
    interface_index: dict[str, dict],
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
    address6_index: dict[str, dict] | None = None,
    address_group6_index: dict[str, dict] | None = None,
) -> dict:
    """Assess one SSL-VPN authentication rule neutrally."""
    rule_id = rule.get("id")
    seq_index = rule.get("sequence_index")
    vdom = rule.get("vdom")

    portal_name = _first_value(rule.get("portal"))
    if not portal_name:
        portal_resolution = {
            "name": None,
            "resolved": False,
            "source": None,
        }
    elif portal_name.casefold() in portal_index:
        portal_resolution = {
            "name": portal_name,
            "resolved": True,
            "source": "custom",
        }
    elif portal_name.casefold() in BUILTIN_SSL_VPN_PORTALS:
        portal_resolution = {
            "name": portal_name,
            "resolved": True,
            "source": "builtin",
        }
    else:
        portal_resolution = {
            "name": portal_name,
            "resolved": False,
            "source": "unresolved",
        }

    group_names = _values(rule.get("groups"))
    resolved_groups = [
        {
            "name": gname,
            "resolved": gname.casefold() in group_index,
        }
        for gname in group_names
    ]

    user_names = _values(rule.get("users"))
    resolved_users = [
        {
            "name": uname,
            "resolved": uname.casefold() in user_index,
        }
        for uname in user_names
    ]

    intf_names = _values(rule.get("source-interface"))
    resolved_interfaces = [
        _interface_context(
            iname,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for iname in intf_names
    ]

    addr_names = _values(rule.get("source-address"))
    resolved_addresses = [
        _resolve_address(
            aname,
            address_index,
            address_group_index,
            {},
            address_family="IPv4",
        )
        for aname in addr_names
    ]

    addr6_names = _values(rule.get("source-address6"))
    resolved_addresses6 = [
        _resolve_address(
            aname,
            address6_index or {},
            address_group6_index or {},
            {},
            address_family="IPv6",
        )
        for aname in addr6_names
    ]

    client_cert = _first_value(rule.get("client-cert"))
    cipher = _first_value(rule.get("cipher"))

    return {
        "id": rule_id,
        "rule_id": rule_id,
        "sequence_index": seq_index,
        "vdom": vdom,
        "portal": portal_name or None,
        "portal_resolution": portal_resolution,
        "groups": group_names,
        "resolved_groups": resolved_groups,
        "users": user_names,
        "resolved_users": resolved_users,
        "interfaces": resolved_interfaces,
        "source_interfaces": resolved_interfaces,
        "resolved_addresses": resolved_addresses,
        "source_addresses": resolved_addresses,
        "resolved_addresses6": resolved_addresses6,
        "source_addresses6": resolved_addresses6,
        "client_cert": client_cert or None,
        "cipher": cipher or None,
        "purpose": "SSL-VPN Authentication Rule",
        "technical_context": "SSL_VPN_AUTHENTICATION_RULE",
        "configured_facts": {
            "portal": portal_name or None,
            "groups": group_names,
            "users": user_names,
            "source-interface": intf_names,
            "source-address": addr_names,
            "source-address6": addr6_names,
            "client-cert": client_cert or None,
            "cipher": cipher or None,
        },
    }


def _assess_ssl_vpn_settings(
    settings: dict,
    portals: list[dict],
    user_groups: list[dict],
    user_locals: list[dict],
    interface_index: dict[str, dict],
    address_index: dict[str, dict],
    address_group_index: dict[str, dict],
    zone_index: dict[str, dict] | None = None,
    sdwan_zone_index: dict[str, dict] | None = None,
    vpn_index: dict[str, dict] | None = None,
    config: dict | None = None,
    address6_index: dict[str, dict] | None = None,
    address_group6_index: dict[str, dict] | None = None,
) -> dict:
    """Assess SSL-VPN global configuration, portals, and authentication rules for one VDOM."""
    vdom = settings.get("vdom")

    portal_index = _index_by_name(portals)
    group_index = _index_by_name(user_groups)
    user_index = _index_by_name(user_locals)

    status_raw = _first_value(settings.get("status"))
    if status_raw.casefold() in {"enable", "enabled"}:
        status = "ENABLED"
    elif status_raw.casefold() in {"disable", "disabled"}:
        status = "DISABLED"
    else:
        status = "NOT_OBSERVED"

    # Default portal resolution
    default_portal_name = _first_value(settings.get("default-portal"))
    if not default_portal_name:
        default_portal_resolution = {
            "name": None,
            "resolved": False,
            "source": None,
        }
    elif default_portal_name.casefold() in portal_index:
        default_portal_resolution = {
            "name": default_portal_name,
            "resolved": True,
            "source": "custom",
        }
    elif default_portal_name.casefold() in BUILTIN_SSL_VPN_PORTALS:
        default_portal_resolution = {
            "name": default_portal_name,
            "resolved": True,
            "source": "builtin",
        }
    else:
        default_portal_resolution = {
            "name": default_portal_name,
            "resolved": False,
            "source": "unresolved",
        }

    # Listening source interfaces
    intf_names = _values(settings.get("source-interface"))
    interface_contexts = [
        _interface_context(
            iname,
            interface_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config=config,
        )
        for iname in intf_names
    ]

    # Source addresses
    srcaddr_names = _values(settings.get("source-address"))
    resolved_sources = [
        _resolve_address(
            aname,
            address_index,
            address_group_index,
            {},
            address_family="IPv4",
        )
        for aname in srcaddr_names
    ]

    srcaddr6_names = _values(settings.get("source-address6"))
    resolved_sources6 = [
        _resolve_address(
            aname,
            address6_index or {},
            address_group6_index or {},
            {},
            address_family="IPv6",
        )
        for aname in srcaddr6_names
    ]

    # Portals assessment
    assessed_portals = [
        _assess_ssl_vpn_portal(p, address_index, address_group_index)
        for p in portals
    ]

    # Authentication rules assessment
    raw_rules = settings.get("authentication_rules", [])
    assessed_rules = [
        _assess_ssl_vpn_auth_rule(
            rule,
            portal_index,
            group_index,
            user_index,
            interface_index,
            address_index,
            address_group_index,
            zone_index,
            sdwan_zone_index,
            vpn_index,
            config,
            address6_index=address6_index,
            address_group6_index=address_group6_index,
        )
        for rule in raw_rules
    ]

    port = settings.get("port")
    servercert = _first_value(settings.get("servercert"))
    ssl_min_proto_ver = _first_value(settings.get("ssl-min-proto-ver"))
    banned_cipher = settings.get("banned-cipher")
    ciphersuite = settings.get("ciphersuite") or settings.get("algorithm")
    dtls_tunnel = _first_value(settings.get("dtls-tunnel"))
    tunnel_ipv6_pools = _values(settings.get("tunnel-ipv6-pools"))

    # Neutral security observations
    observations = [
        "SSL-VPN Remote Access Configuration.",
    ]
    if status != "NOT_OBSERVED":
        observations.append(f"SSL-VPN service status: {status}.")
    if port:
        observations.append(f"Configured listening port: {port}.")
    if servercert:
        observations.append(f"Server certificate reference: {servercert}.")
    if ssl_min_proto_ver:
        observations.append(f"Configured minimum TLS version: {ssl_min_proto_ver}.")
    if interface_contexts:
        intf_roles = [f"{c.get('name')} ({c.get('role', 'UNKNOWN')})" for c in interface_contexts]
        observations.append(f"Listening interfaces: {', '.join(intf_roles)}.")
    if assessed_rules:
        observations.append(f"Authentication rules defined: {len(assessed_rules)}.")
    if assessed_portals:
        observations.append(f"Portals defined: {len(assessed_portals)}.")

    return {
        "vdom": vdom,
        "status": status,
        "port": port,
        "servercert": servercert or None,
        "ssl_min_proto_ver": ssl_min_proto_ver or None,
        "min_tls_version": ssl_min_proto_ver or None,
        "banned_cipher": banned_cipher,
        "ciphersuite": ciphersuite,
        "dtls_tunnel": dtls_tunnel or None,
        "default_portal": default_portal_name or None,
        "default_portal_resolution": default_portal_resolution,
        "interface_contexts": interface_contexts,
        "source_interfaces": interface_contexts,
        "resolved_sources": resolved_sources,
        "source_addresses": resolved_sources,
        "resolved_sources6": resolved_sources6,
        "source_addresses6": resolved_sources6,
        "tunnel_ipv6_pools": tunnel_ipv6_pools,
        "portals": assessed_portals,
        "authentication_rules": assessed_rules,
        "purpose": "SSL-VPN Remote Access Configuration",
        "technical_context": "SSL_VPN_REMOTE_ACCESS",
        "configured_facts": {
            "status": settings.get("status"),
            "port": port,
            "servercert": servercert,
            "ssl-min-proto-ver": ssl_min_proto_ver,
            "source-interface": intf_names,
            "source-address": srcaddr_names,
            "source-address6": srcaddr6_names,
            "tunnel-ip-pools": _values(settings.get("tunnel-ip-pools")),
            "tunnel-ipv6-pools": tunnel_ipv6_pools,
            "default-portal": default_portal_name,
            "dtls-tunnel": dtls_tunnel,
        },
        "security_observations": observations,
    }


def analyze_configuration(config: dict) -> dict:
    """Analyze parsed FortiGate context and return assessments and findings."""
    policies = config.get("policies", [])
    if not isinstance(policies, list):
        policies = []

    assessments: list[dict] = []
    findings: list[dict] = []
    vdom_cache: dict[str | None, dict] = {}
    sdwan_zones = config.get("sdwan_zones") or (
        config.get("sdwan", {}).get("zones", [])
        if isinstance(config.get("sdwan"), dict)
        else []
    )

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_vdom = policy.get("vdom")
        if policy_vdom not in vdom_cache:
            vdom_cache[policy_vdom] = {
                "interface_index": _index_by_name(
                    _scoped_interfaces(config.get("interfaces", []), policy_vdom)
                ),
                "zone_index": _index_by_name(
                    _scoped_zones(config.get("zones", []), policy_vdom)
                ),
                "sdwan_zone_index": _index_by_name(
                    _scoped_zones(sdwan_zones, policy_vdom)
                ),
                "address_index": _index_by_name(
                    _scoped_items(config.get("addresses", []), policy_vdom)
                ),
                "address_group_index": _index_by_name(
                    _scoped_items(config.get("address_groups", []), policy_vdom)
                ),
                "service_index": _index_by_name(
                    _scoped_items(config.get("services", []), policy_vdom)
                ),
                "service_group_index": _index_by_name(
                    _scoped_items(config.get("service_groups", []), policy_vdom)
                ),
                "vip_index": _index_by_name(
                    _scoped_items(config.get("vips", []), policy_vdom)
                ),
                "vpn_index": _index_by_name(
                    [
                        phase1
                        for phase1 in _scoped_items(
                            config.get("ipsec_phase1", []), policy_vdom
                        )
                        if phase1.get("definition_type") == "phase1-interface"
                    ]
                ),
                "address6_index": (
                    _index_by_name(
                        _scoped_items(config.get("addresses6", []), policy_vdom)
                    )
                    if config.get("addresses6")
                    else {}
                ),
                "address_group6_index": (
                    _index_by_name(
                        _scoped_items(config.get("address_groups6", []), policy_vdom)
                    )
                    if config.get("address_groups6")
                    else {}
                ),
                "vip6_index": (
                    _index_by_name(
                        _scoped_items(config.get("vips6", []), policy_vdom)
                    )
                    if config.get("vips6")
                    else {}
                ),
            }
        v_idx = vdom_cache[policy_vdom]
        interface_index = v_idx["interface_index"]
        zone_index = v_idx["zone_index"]
        sdwan_zone_index = v_idx["sdwan_zone_index"]
        address_index = v_idx["address_index"]
        address_group_index = v_idx["address_group_index"]
        service_index = v_idx["service_index"]
        service_group_index = v_idx["service_group_index"]
        vip_index = v_idx["vip_index"]
        vpn_index = v_idx["vpn_index"]
        address6_index = v_idx["address6_index"]
        address_group6_index = v_idx["address_group6_index"]
        vip6_index = v_idx["vip6_index"]

        security_profiles = resolve_policy_security_profiles(policy, config)
        internet_service_matching = _internet_service_matching(policy, config)
        assessment, policy_findings = _assess_policy(
            policy,
            interface_index,
            address_index,
            address_group_index,
            service_index,
            service_group_index,
            vip_index,
            security_profiles,
            zone_index,
            sdwan_zone_index,
            internet_service_matching,
            vpn_index,
            config=config,
            address6_index=address6_index,
            address_group6_index=address_group6_index,
            vip6_index=vip6_index,
        )
        assessments.append(assessment)
        findings.extend(policy_findings)

    findings.extend(_analyze_policy_order(config))

    local_in_policies = config.get("local_in_policies", [])
    if not isinstance(local_in_policies, list):
        local_in_policies = []

    local_in_assessments: list[dict] = []
    for policy in local_in_policies:
        if not isinstance(policy, dict):
            continue
        policy_vdom = policy.get("vdom")
        interface_index = _index_by_name(
            _scoped_interfaces(config.get("interfaces", []), policy_vdom)
        )
        zone_index = _index_by_name(
            _scoped_zones(config.get("zones", []), policy_vdom)
        )
        sdwan_zones = config.get("sdwan_zones") or (
            config.get("sdwan", {}).get("zones", [])
            if isinstance(config.get("sdwan"), dict)
            else []
        )
        sdwan_zone_index = _index_by_name(
            _scoped_zones(sdwan_zones, policy_vdom)
        )
        address_index = _index_by_name(
            _scoped_items(config.get("addresses", []), policy_vdom)
        )
        address_group_index = _index_by_name(
            _scoped_items(config.get("address_groups", []), policy_vdom)
        )
        service_index = _index_by_name(
            _scoped_items(config.get("services", []), policy_vdom)
        )
        service_group_index = _index_by_name(
            _scoped_items(config.get("service_groups", []), policy_vdom)
        )
        vip_index = _index_by_name(
            _scoped_items(config.get("vips", []), policy_vdom)
        )
        vpn_index = _index_by_name(
            [
                phase1
                for phase1 in _scoped_items(
                    config.get("ipsec_phase1", []), policy_vdom
                )
                if phase1.get("definition_type") == "phase1-interface"
            ]
        )
        internet_service_matching = _internet_service_matching(policy, config)
        local_in_assessments.append(
            _assess_local_in_policy(
                policy,
                interface_index,
                address_index,
                address_group_index,
                service_index,
                service_group_index,
                vip_index,
                zone_index,
                sdwan_zone_index,
                internet_service_matching,
                vpn_index,
                config=config,
                address_family="IPv4",
            )
        )

    local_in_policies6 = config.get("local_in_policies6", [])
    if not isinstance(local_in_policies6, list):
        local_in_policies6 = []

    local_in_policy6_assessments: list[dict] = []
    for policy in local_in_policies6:
        if not isinstance(policy, dict):
            continue
        policy_vdom = policy.get("vdom")
        interface_index = _index_by_name(
            _scoped_interfaces(config.get("interfaces", []), policy_vdom)
        )
        zone_index = _index_by_name(
            _scoped_zones(config.get("zones", []), policy_vdom)
        )
        sdwan_zones = config.get("sdwan_zones") or (
            config.get("sdwan", {}).get("zones", [])
            if isinstance(config.get("sdwan"), dict)
            else []
        )
        sdwan_zone_index = _index_by_name(
            _scoped_zones(sdwan_zones, policy_vdom)
        )
        address6_index = _index_by_name(
            _scoped_items(config.get("addresses6", []), policy_vdom)
        )
        address_group6_index = _index_by_name(
            _scoped_items(config.get("address_groups6", []), policy_vdom)
        )
        service_index = _index_by_name(
            _scoped_items(config.get("services", []), policy_vdom)
        )
        service_group_index = _index_by_name(
            _scoped_items(config.get("service_groups", []), policy_vdom)
        )
        vip6_index = _index_by_name(
            _scoped_items(config.get("vips6", []), policy_vdom)
        )
        vpn_index = _index_by_name(
            [
                phase1
                for phase1 in _scoped_items(
                    config.get("ipsec_phase1", []), policy_vdom
                )
                if phase1.get("definition_type") == "phase1-interface"
            ]
        )
        internet_service_matching = _internet_service_matching(policy, config)
        assessment = _assess_local_in_policy(
            policy,
            interface_index,
            address6_index,
            address_group6_index,
            service_index,
            service_group_index,
            vip6_index,
            zone_index,
            sdwan_zone_index,
            internet_service_matching,
            vpn_index,
            config=config,
            address_family="IPv6",
        )
        local_in_assessments.append(assessment)
        local_in_policy6_assessments.append(assessment)

    interface_policies = config.get("interface_policies", [])
    if not isinstance(interface_policies, list):
        interface_policies = []

    interface_policy_assessments: list[dict] = []
    for policy in interface_policies:
        if not isinstance(policy, dict):
            continue
        policy_vdom = policy.get("vdom")
        interface_index = _index_by_name(
            _scoped_interfaces(config.get("interfaces", []), policy_vdom)
        )
        zone_index = _index_by_name(
            _scoped_zones(config.get("zones", []), policy_vdom)
        )
        sdwan_zones = config.get("sdwan_zones") or (
            config.get("sdwan", {}).get("zones", [])
            if isinstance(config.get("sdwan"), dict)
            else []
        )
        sdwan_zone_index = _index_by_name(
            _scoped_zones(sdwan_zones, policy_vdom)
        )
        address_index = _index_by_name(
            _scoped_items(config.get("addresses", []), policy_vdom)
        )
        address_group_index = _index_by_name(
            _scoped_items(config.get("address_groups", []), policy_vdom)
        )
        service_index = _index_by_name(
            _scoped_items(config.get("services", []), policy_vdom)
        )
        service_group_index = _index_by_name(
            _scoped_items(config.get("service_groups", []), policy_vdom)
        )
        vip_index = _index_by_name(
            _scoped_items(config.get("vips", []), policy_vdom)
        )
        vpn_index = _index_by_name(
            [
                phase1
                for phase1 in _scoped_items(
                    config.get("ipsec_phase1", []), policy_vdom
                )
                if phase1.get("definition_type") == "phase1-interface"
            ]
        )
        interface_policy_assessments.append(
            _assess_interface_policy(
                policy,
                interface_index,
                address_index,
                address_group_index,
                service_index,
                service_group_index,
                vip_index,
                zone_index,
                sdwan_zone_index,
                vpn_index,
                config=config,
                address_family="IPv4",
            )
        )

    interface_policies6 = config.get("interface_policies6", [])
    if not isinstance(interface_policies6, list):
        interface_policies6 = []

    interface_policy6_assessments: list[dict] = []
    for policy in interface_policies6:
        if not isinstance(policy, dict):
            continue
        policy_vdom = policy.get("vdom")
        interface_index = _index_by_name(
            _scoped_interfaces(config.get("interfaces", []), policy_vdom)
        )
        zone_index = _index_by_name(
            _scoped_zones(config.get("zones", []), policy_vdom)
        )
        sdwan_zones = config.get("sdwan_zones") or (
            config.get("sdwan", {}).get("zones", [])
            if isinstance(config.get("sdwan"), dict)
            else []
        )
        sdwan_zone_index = _index_by_name(
            _scoped_zones(sdwan_zones, policy_vdom)
        )
        address6_index = _index_by_name(
            _scoped_items(config.get("addresses6", []), policy_vdom)
        )
        address_group6_index = _index_by_name(
            _scoped_items(config.get("address_groups6", []), policy_vdom)
        )
        service_index = _index_by_name(
            _scoped_items(config.get("services", []), policy_vdom)
        )
        service_group_index = _index_by_name(
            _scoped_items(config.get("service_groups", []), policy_vdom)
        )
        vip6_index = _index_by_name(
            _scoped_items(config.get("vips6", []), policy_vdom)
        )
        vpn_index = _index_by_name(
            [
                phase1
                for phase1 in _scoped_items(
                    config.get("ipsec_phase1", []), policy_vdom
                )
                if phase1.get("definition_type") == "phase1-interface"
            ]
        )
        interface_policy6_assessments.append(
            _assess_interface_policy(
                policy,
                interface_index,
                address6_index,
                address_group6_index,
                service_index,
                service_group_index,
                vip6_index,
                zone_index,
                sdwan_zone_index,
                vpn_index,
                config=config,
                address_family="IPv6",
            )
        )

    ssl_vpn_settings_list = config.get("ssl_vpn_settings", [])
    if not isinstance(ssl_vpn_settings_list, list):
        ssl_vpn_settings_list = []
    ssl_vpn_portals_list = config.get("ssl_vpn_portals", [])
    if not isinstance(ssl_vpn_portals_list, list):
        ssl_vpn_portals_list = []
    user_groups_list = config.get("user_groups", [])
    if not isinstance(user_groups_list, list):
        user_groups_list = []
    user_locals_list = config.get("user_locals", [])
    if not isinstance(user_locals_list, list):
        user_locals_list = []

    ssl_vpn_assessments: list[dict] = []
    for settings in ssl_vpn_settings_list:
        if not isinstance(settings, dict):
            continue
        vdom = settings.get("vdom")
        scoped_portals = _scoped_items(ssl_vpn_portals_list, vdom)
        scoped_groups = _scoped_items(user_groups_list, vdom)
        scoped_users = _scoped_items(user_locals_list, vdom)
        interface_index = _index_by_name(
            _scoped_interfaces(config.get("interfaces", []), vdom)
        )
        zone_index = _index_by_name(
            _scoped_zones(config.get("zones", []), vdom)
        )
        sdwan_zones = config.get("sdwan_zones") or (
            config.get("sdwan", {}).get("zones", [])
            if isinstance(config.get("sdwan"), dict)
            else []
        )
        sdwan_zone_index = _index_by_name(
            _scoped_zones(sdwan_zones, vdom)
        )
        address_index = _index_by_name(
            _scoped_items(config.get("addresses", []), vdom)
        )
        address_group_index = _index_by_name(
            _scoped_items(config.get("address_groups", []), vdom)
        )
        address6_index = _index_by_name(
            _scoped_items(config.get("addresses6", []), vdom)
        )
        address_group6_index = _index_by_name(
            _scoped_items(config.get("address_groups6", []), vdom)
        )
        vpn_index = _index_by_name(
            [
                phase1
                for phase1 in _scoped_items(
                    config.get("ipsec_phase1", []), vdom
                )
                if phase1.get("definition_type") == "phase1-interface"
            ]
        )
        ssl_vpn_assessments.append(
            _assess_ssl_vpn_settings(
                settings,
                scoped_portals,
                scoped_groups,
                scoped_users,
                interface_index,
                address_index,
                address_group_index,
                zone_index,
                sdwan_zone_index,
                vpn_index,
                config=config,
                address6_index=address6_index,
                address_group6_index=address_group6_index,
            )
        )

    ssl_vpn_summary = ssl_vpn_assessments[0] if ssl_vpn_assessments else {}

    input_assessment = config.get("input_assessment")
    if not isinstance(input_assessment, dict):
        try:
            from .parser import assess_input_quality
        except ImportError:
            from parser import assess_input_quality
        input_assessment = assess_input_quality("", config)

    try:
        from .fortios_defaults import collect_applied_defaults
    except ImportError:
        from fortios_defaults import collect_applied_defaults
    documented_defaults = collect_applied_defaults(config)

    return {
        "policy_assessments": assessments,
        "local_in_assessments": local_in_assessments,
        "local_in_policy6_assessments": local_in_policy6_assessments,
        "interface_policy_assessments": interface_policy_assessments,
        "interface_policy6_assessments": interface_policy6_assessments,
        "ssl_vpn_assessments": ssl_vpn_assessments,
        "ssl_vpn": ssl_vpn_summary,
        "findings": findings,
        "input_assessment": input_assessment,
        "documented_defaults": documented_defaults,
    }


def analyze_policies(policies: list[dict]) -> list[dict]:
    """Compatibility wrapper for callers without full configuration context."""
    return analyze_configuration({"policies": policies})["findings"]
