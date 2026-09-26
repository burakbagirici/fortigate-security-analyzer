"""FortiGate Runtime Health Analysis module.

Parses and analyzes text output captured from live FortiGate CLI commands.
This is a static text analyzer and does not connect to live devices.
"""

from __future__ import annotations

import re


SUPPORTED_COMMANDS = {
    "get system status",
    "get system fortiguard-service status",
    "diagnose autoupdate status",
    "diagnose autoupdate versions",
    "get system ha status",
    "diagnose system ntp status",
    "execute sensor list",
    "execute sensor detail",
    "diagnose hardware deviceinfo psu",
    "diagnose hardware deviceinfo rps",
    "diagnose debug crashlog read",
    "diagnose debug config-error-log read",
    "get router info routing-table all",
}


def normalize_command_name(raw_name: str) -> str:
    """Normalize a FortiGate CLI command name conservatively."""
    tokens = raw_name.strip().casefold().split()
    expanded: list[str] = []
    for token in tokens:
        if token == "sys":
            expanded.append("system")
        elif token == "diag":
            expanded.append("diagnose")
        elif token == "exec":
            expanded.append("execute")
        else:
            expanded.append(token)
    return " ".join(expanded)


def sanitize_evidence_text(text: str) -> str:
    """Sanitize sensitive credentials, PSKs, passwords, and tokens from evidence."""
    sanitized = text
    # Mask private keys
    sanitized = re.sub(
        r"-----BEGIN[A-Z\s]+KEY-----.*?-----END[A-Z\s]+KEY-----",
        "[REDACTED PRIVATE KEY]",
        sanitized,
        flags=re.DOTALL | re.IGNORECASE,
    )
    # Mask password/secret/psk/token/community fields
    patterns = [
        (r"(?i)\b(password|passwd|pwd)\s*[:= ]\s*\S+", r"\1: [REDACTED]"),
        (r"(?i)\b(psk|psksecret|preshared[-_]?key)\s*[:= ]\s*\S+", r"\1: [REDACTED]"),
        (r"(?i)\b(secret|api[-_]?key|token|auth[-_]?token)\s*[:= ]\s*\S+", r"\1: [REDACTED]"),
        (r"(?i)\b(community)\s*[:= ]\s*\S+", r"\1: [REDACTED]"),
        (r"(?i)\b(enc\s+[A-Za-z0-9+/=]{16,})", r"[REDACTED ENCRYPTED HASH]"),
    ]
    for pattern, repl in patterns:
        sanitized = re.sub(pattern, repl, sanitized)
    if len(sanitized) > 200:
        sanitized = sanitized[:197] + "..."
    return sanitized


def sanitize_evidence_list(evidence: list[str]) -> list[str]:
    """Sanitize each evidence string in a list."""
    return [sanitize_evidence_text(item) for item in evidence]


def parse_runtime_output(text: str) -> dict:
    """Parse section-based CLI command outputs into a structured dictionary.

    Format expected:
    === COMMAND: <command_name> ===
    <output>
    """
    commands: dict[str, str] = {}
    commands_received: list[str] = []
    unsupported_commands: list[str] = []
    raw_sections: list[dict] = []

    if not text or not text.strip():
        return {
            "commands": commands,
            "commands_received": commands_received,
            "unsupported_commands": unsupported_commands,
            "raw_sections": raw_sections,
        }

    section_header_pattern = re.compile(r"^={3,}\s*COMMAND:\s*(.*?)\s*={3,}$", re.IGNORECASE)

    current_command: str | None = None
    current_raw_command: str | None = None
    current_lines: list[str] = []

    for line in text.splitlines():
        match = section_header_pattern.match(line.strip())
        if match:
            if current_command is not None:
                output = "\n".join(current_lines).strip()
                commands[current_command] = output
                raw_sections.append({
                    "command": current_command,
                    "raw_command": current_raw_command,
                    "output": output,
                })
            raw_cmd = match.group(1).strip()
            current_raw_command = raw_cmd
            current_command = normalize_command_name(raw_cmd)
            current_lines = []
            if current_command not in commands_received:
                commands_received.append(current_command)
            if current_command not in SUPPORTED_COMMANDS and current_command not in unsupported_commands:
                unsupported_commands.append(current_command)
        else:
            if current_command is not None:
                current_lines.append(line)

    if current_command is not None:
        output = "\n".join(current_lines).strip()
        commands[current_command] = output
        raw_sections.append({
            "command": current_command,
            "raw_command": current_raw_command,
            "output": output,
        })

    return {
        "commands": commands,
        "commands_received": commands_received,
        "unsupported_commands": unsupported_commands,
        "raw_sections": raw_sections,
    }


def _check(
    category: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: list[str],
    source_command: str,
) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "evidence": sanitize_evidence_list(evidence),
        "source_command": source_command,
        "review_required": True,
    }


def _analyze_system_status(output: str) -> dict:
    inventory = {
        "hostname": None,
        "version": None,
        "model": None,
        "serial_number": None,
        "system_time": None,
    }
    for line in output.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue
        if re.match(r"^Hostname:\s*", line_clean, re.IGNORECASE):
            inventory["hostname"] = re.sub(r"^Hostname:\s*", "", line_clean, flags=re.IGNORECASE).strip()
        elif re.match(r"^Version:\s*", line_clean, re.IGNORECASE):
            ver = re.sub(r"^Version:\s*", "", line_clean, flags=re.IGNORECASE).strip()
            inventory["version"] = ver
            match = re.search(r"((?:FortiGate|FortiWiFi|FG|FW)-[A-Za-z0-9\-]+|FortiGate-VM\w*)", ver, re.IGNORECASE)
            if match:
                inventory["model"] = match.group(1)
        elif re.match(r"^Serial-Number:\s*", line_clean, re.IGNORECASE):
            inventory["serial_number"] = re.sub(r"^Serial-Number:\s*", "", line_clean, flags=re.IGNORECASE).strip()
        elif re.match(r"^System time:\s*", line_clean, re.IGNORECASE):
            inventory["system_time"] = re.sub(r"^System time:\s*", "", line_clean, flags=re.IGNORECASE).strip()
        elif re.match(r"^(?:Platform|Model):\s*", line_clean, re.IGNORECASE):
            if not inventory["model"]:
                inventory["model"] = re.sub(r"^(?:Platform|Model):\s*", "", line_clean, flags=re.IGNORECASE).strip()
    return inventory


def _is_fortiguard_failure_line(line: str) -> bool:
    line_lower = line.lower()
    if re.search(r"\b(failed|failures?)\s*(?:attempts?)?\s*:\s*0\b", line_lower):
        return False
    if re.search(r"\b0\s*(?:failed|failures?)\b", line_lower):
        return False
    if re.search(r"\b(no\s+failures?|no\s+errors?)\b", line_lower):
        return False

    failure_patterns = [
        r"\b(?:connection|service|daemon|update|status)\s*:\s*(?:failed|failure|error|unreachable|down)\b",
        r"\b(?:failed|failure)\s+to\s+(?:connect|communicate|update|reach)\b",
        r"\b(?:server|service)\s+(?:is\s+)?unreachable\b",
        r"\b(?:cannot|could\s+not)\s+connect\b",
        r"\bconnection\s+error\b",
        r"\bcommunication\s+(?:failed|failure)\b",
    ]
    return any(re.search(pat, line_lower) for pat in failure_patterns)


def _analyze_fortiguard(commands: dict[str, str]) -> tuple[dict, list[dict]]:
    inventory = {"status": "unknown"}
    checks: list[dict] = []

    relevant_cmds = [
        "get system fortiguard-service status",
        "diagnose autoupdate status",
        "diagnose autoupdate versions",
    ]

    for cmd in relevant_cmds:
        if cmd not in commands:
            continue
        output = commands[cmd]
        failure_lines: list[str] = []
        for line in output.splitlines():
            line_clean = line.strip()
            if _is_fortiguard_failure_line(line_clean):
                failure_lines.append(line_clean)

        if failure_lines:
            inventory["status"] = "failed"
            checks.append(
                _check(
                    category="FortiGuard / Updates",
                    severity="MEDIUM",
                    title="FortiGuard or Update Service Reports a Failure",
                    description="FortiGuard or autoupdate service explicitly reported a communication or update failure.",
                    recommendation="Review FortiGuard connectivity, DNS resolution, and routing to update servers.",
                    evidence=failure_lines[:5],
                    source_command=cmd,
                )
            )
            break
        else:
            if inventory["status"] == "unknown":
                inventory["status"] = "normal"

    return inventory, checks


def _analyze_ha(output: str) -> tuple[dict, list[dict]]:
    inventory = {
        "ha_mode": "unknown",
        "cluster_members": [],
        "sync_status": "unknown",
    }
    checks: list[dict] = []

    lines = [l.strip() for l in output.splitlines() if l.strip()]

    # Extract mode
    for line in lines:
        mode_match = re.match(r"^(?:Current\s+)?(?:HA\s+)?Mode:\s*([A-Za-z0-9\-]+)", line, re.IGNORECASE)
        if mode_match:
            inventory["ha_mode"] = mode_match.group(1).casefold()
            break

    # If standalone, do not generate HA health warnings
    if inventory["ha_mode"] == "standalone":
        return inventory, checks

    out_of_sync_lines: list[str] = []
    member_problem_lines: list[str] = []

    for line in lines:
        line_lower = line.lower()
        # Check out of sync
        if re.search(r"\b(out-of-sync|out of sync|not in sync|sync failed)\b", line_lower):
            out_of_sync_lines.append(line)
        elif re.search(r"\bin-sync\b", line_lower):
            if inventory["sync_status"] != "out-of-sync":
                inventory["sync_status"] = "in-sync"

        # Check member failure
        member_prob_patterns = [
            r"\b(?:dead|failed|down|heartbeat lost|unreachable)\b",
        ]
        if any(re.search(pat, line_lower) for pat in member_prob_patterns):
            # Ensure not a benign line like "Failed attempts: 0"
            if not re.search(r"\b(failed\s*:\s*0|0\s*failed)\b", line_lower):
                member_problem_lines.append(line)

    if out_of_sync_lines:
        inventory["sync_status"] = "out-of-sync"
        checks.append(
            _check(
                category="High Availability",
                severity="MEDIUM",
                title="HA Synchronization Issue Reported",
                description="The HA cluster status reports that one or more cluster members are out of synchronization.",
                recommendation="Review HA cluster configuration and verify network links between cluster members to re-establish synchronization.",
                evidence=out_of_sync_lines[:5],
                source_command="get system ha status",
            )
        )

    if member_problem_lines:
        checks.append(
            _check(
                category="High Availability",
                severity="HIGH",
                title="HA Member Problem Reported",
                description="The HA cluster status reports that a cluster member is failed, dead, or unavailable.",
                recommendation="Investigate the physical status, power, and heartbeat connectivity of the affected cluster member.",
                evidence=member_problem_lines[:5],
                source_command="get system ha status",
            )
        )

    return inventory, checks


def _analyze_ntp(output: str) -> tuple[dict, list[dict]]:
    inventory = {
        "synchronization_state": "unknown",
        "server": None,
        "stratum": None,
        "offset": None,
    }
    checks: list[dict] = []

    unsync_lines: list[str] = []
    for line in output.splitlines():
        line_clean = line.strip()
        line_lower = line_clean.lower()
        if not line_clean:
            continue

        if re.search(r"\b(?:synchronized:\s*yes|clock is synchronized|synchronised:\s*yes)\b", line_lower):
            inventory["synchronization_state"] = "synchronized"
        elif re.search(r"\b(?:unsynchronized|not synchronized|synchronized:\s*no|synchronised:\s*no)\b", line_lower):
            inventory["synchronization_state"] = "unsynchronized"
            unsync_lines.append(line_clean)

        srv_match = re.search(r"\bserver:\s*([A-Za-z0-9\.\-_:]+)", line_clean, re.IGNORECASE)
        if srv_match and not inventory["server"]:
            inventory["server"] = srv_match.group(1)

        stratum_match = re.search(r"\bstratum:\s*(\d+)", line_clean, re.IGNORECASE)
        if stratum_match and inventory["stratum"] is None:
            inventory["stratum"] = int(stratum_match.group(1))

        offset_match = re.search(r"\boffset:\s*([0-9\.\-]+\s*[A-Za-z]+)", line_clean, re.IGNORECASE)
        if offset_match and not inventory["offset"]:
            inventory["offset"] = offset_match.group(1)

    if inventory["synchronization_state"] == "unsynchronized" or unsync_lines:
        inventory["synchronization_state"] = "unsynchronized"
        evidence = unsync_lines if unsync_lines else [output.splitlines()[0].strip()]
        checks.append(
            _check(
                category="Time Synchronization",
                severity="MEDIUM",
                title="NTP Runtime Synchronization Problem",
                description="The FortiGate reports that its runtime system clock is currently unsynchronized with configured NTP sources.",
                recommendation="Review NTP server reachability, local firewall policies, and UDP port 123 routing to re-establish synchronization.",
                evidence=evidence[:3],
                source_command="diagnose system ntp status",
            )
        )

    return inventory, checks


def _analyze_hardware(commands: dict[str, str]) -> tuple[dict, list[dict]]:
    inventory = {"sensors": [], "psu_status": "unknown"}
    checks: list[dict] = []

    hw_cmds = [
        "execute sensor list",
        "execute sensor detail",
        "diagnose hardware deviceinfo psu",
        "diagnose hardware deviceinfo rps",
    ]

    for cmd in hw_cmds:
        if cmd not in commands:
            continue
        output = commands[cmd]
        psu_failures: list[str] = []
        sensor_alarms: list[str] = []

        for line in output.splitlines():
            line_clean = line.strip()
            line_lower = line_clean.lower()
            if not line_clean:
                continue

            # Skip benign / table header lines
            if "alarm threshold" in line_lower or "alarm: none" in line_lower:
                continue

            is_psu = "psu" in line_lower or "power supply" in line_lower or "ps1" in line_lower or "ps2" in line_lower
            has_fault = bool(re.search(r"\b(failed|fail|fault|critical|alarm|dead|down)\b", line_lower))

            if has_fault:
                if is_psu:
                    psu_failures.append(line_clean)
                else:
                    sensor_alarms.append(line_clean)

        if psu_failures:
            inventory["psu_status"] = "failed"
            checks.append(
                _check(
                    category="Hardware Health",
                    severity="HIGH",
                    title="Hardware Fault Reported: Power Supply Failure",
                    description="A power supply unit reported an explicit failure or fault state in hardware monitoring output.",
                    recommendation="Inspect power cables, power sources, and replace faulty power supply units immediately.",
                    evidence=psu_failures[:5],
                    source_command=cmd,
                )
            )

        if sensor_alarms:
            checks.append(
                _check(
                    category="Hardware Health",
                    severity="HIGH",
                    title="Hardware Sensor Alarm Reported",
                    description="One or more hardware sensors reported an explicit alarm, fault, or critical state.",
                    recommendation="Inspect appliance fans, temperatures, and physical operating environment.",
                    evidence=sensor_alarms[:5],
                    source_command=cmd,
                )
            )

    return inventory, checks


def _analyze_crashlog(output: str) -> tuple[dict, list[dict]]:
    inventory = {"crash_count": 0, "crashes": []}
    checks: list[dict] = []

    if not output or not output.strip():
        return inventory, checks

    lines = [l.strip() for l in output.splitlines() if l.strip()]
    crash_lines: list[str] = []

    for line in lines:
        line_lower = line.lower()
        if re.search(r"\b(crashed with signal|crashed|segmentation fault|kernel panic|bus error|sigsegv|sigbus|sigabrt)\b", line_lower):
            crash_lines.append(line)

    if crash_lines:
        inventory["crash_count"] = len(crash_lines)
        inventory["crashes"] = crash_lines[:5]
        checks.append(
            _check(
                category="System Stability",
                severity="MEDIUM",
                title="Crash Log Entries Detected",
                description=f"The device crash log contains recorded process crash events ({len(crash_lines)} event(s) detected).",
                recommendation="Review process crash history with Fortinet support or investigate daemon stability in firmware release notes.",
                evidence=crash_lines[:3],
                source_command="diagnose debug crashlog read",
            )
        )

    return inventory, checks


def _analyze_config_error_log(output: str) -> tuple[dict, list[dict]]:
    inventory = {"error_count": 0, "errors": []}
    checks: list[dict] = []

    if not output or not output.strip():
        return inventory, checks

    lines = [l.strip() for l in output.splitlines() if l.strip()]
    error_lines: list[str] = []

    for line in lines:
        line_lower = line.lower()
        if line.startswith(">>>") or re.search(r"(?:unknown attribute|command parse error|parse error|: error)", line_lower):
            error_lines.append(line)

    if error_lines:
        inventory["error_count"] = len(error_lines)
        inventory["errors"] = error_lines[:5]
        checks.append(
            _check(
                category="Configuration Integrity",
                severity="MEDIUM",
                title="Runtime Configuration Errors Reported",
                description=f"The device configuration error log contains runtime parsing or validation errors ({len(error_lines)} error(s) detected).",
                recommendation="Review the configuration error log entries to update or remove deprecated or invalid commands.",
                evidence=error_lines[:5],
                source_command="diagnose debug config-error-log read",
            )
        )

    return inventory, checks


def _analyze_routing(output: str) -> tuple[dict, list[dict]]:
    inventory = {
        "route_count": 0,
        "has_default_route": False,
        "default_gateway": None,
        "default_route_interface": None,
    }
    checks: list[dict] = []

    if not output or not output.strip():
        return inventory, checks

    lines = output.splitlines()
    route_count = 0
    has_default_route = False

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        # Skip header/code lines
        if line_clean.startswith("Codes:") or line_clean.startswith("O -") or line_clean.startswith("N1 -") or line_clean.startswith("E1 -") or line_clean.startswith("* -"):
            continue

        # Route line match: starts with code letter (S, C, O, B, etc.) and contains an IP/prefix
        if re.match(r"^[A-Za-z*>]+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", line_clean):
            route_count += 1
            if "0.0.0.0/0" in line_clean:
                has_default_route = True
                gw_match = re.search(r"\bvia\s+([0-9.]+)", line_clean)
                if gw_match:
                    inventory["default_gateway"] = gw_match.group(1)
                intf_match = re.search(r",\s*([A-Za-z0-9\-._]+)$", line_clean)
                if intf_match:
                    inventory["default_route_interface"] = intf_match.group(1)

    inventory["route_count"] = route_count
    inventory["has_default_route"] = has_default_route

    # If routing table was clearly parsed and has routes, but lacks an IPv4 default route
    if route_count > 0 and not has_default_route:
        checks.append(
            _check(
                category="Routing",
                severity="LOW",
                title="Default Route Not Detected in Supplied Routing Table",
                description="The supplied routing table was analyzed, but no IPv4 default route (0.0.0.0/0) was detected in the active routing table. This may be intentional in isolated or specialized network topologies.",
                recommendation="Verify whether an IPv4 default gateway is required for this device's operational role.",
                evidence=[
                    f"Total active routes detected: {route_count}",
                    "IPv4 default route (0.0.0.0/0): not detected",
                ],
                source_command="get router info routing-table all",
            )
        )

    return inventory, checks


def analyze_runtime_health(runtime_data: dict) -> dict:
    """Analyze structured FortiGate runtime command outputs.

    Returns structured health checks, extracted inventory, and severity summary.
    """
    commands = runtime_data.get("commands", {}) if isinstance(runtime_data, dict) else {}
    commands_received = runtime_data.get("commands_received", []) if isinstance(runtime_data, dict) else []
    unsupported_commands = runtime_data.get("unsupported_commands", []) if isinstance(runtime_data, dict) else []

    checks: list[dict] = []
    inventory: dict = {}

    # 1. System Status
    if "get system status" in commands:
        inventory["system_status"] = _analyze_system_status(commands["get system status"])

    # 2. FortiGuard / Updates
    fg_inventory, fg_checks = _analyze_fortiguard(commands)
    if fg_inventory["status"] != "unknown":
        inventory["fortiguard"] = fg_inventory
    checks.extend(fg_checks)

    # 3. High Availability
    if "get system ha status" in commands:
        ha_inventory, ha_checks = _analyze_ha(commands["get system ha status"])
        inventory["ha"] = ha_inventory
        checks.extend(ha_checks)

    # 4. NTP Runtime Status
    if "diagnose system ntp status" in commands:
        ntp_inventory, ntp_checks = _analyze_ntp(commands["diagnose system ntp status"])
        inventory["ntp"] = ntp_inventory
        checks.extend(ntp_checks)

    # 5. Hardware Health
    hw_inventory, hw_checks = _analyze_hardware(commands)
    if hw_inventory.get("sensors") or hw_inventory.get("psu_status") != "unknown":
        inventory["hardware"] = hw_inventory
    checks.extend(hw_checks)

    # 6. Crash Log
    if "diagnose debug crashlog read" in commands:
        crash_inventory, crash_checks = _analyze_crashlog(commands["diagnose debug crashlog read"])
        inventory["crashlog"] = crash_inventory
        checks.extend(crash_checks)

    # 7. Config Error Log
    if "diagnose debug config-error-log read" in commands:
        err_inventory, err_checks = _analyze_config_error_log(commands["diagnose debug config-error-log read"])
        inventory["config_error_log"] = err_inventory
        checks.extend(err_checks)

    # 8. Routing Table
    if "get router info routing-table all" in commands:
        routing_inventory, routing_checks = _analyze_routing(commands["get router info routing-table all"])
        inventory["routing"] = routing_inventory
        checks.extend(routing_checks)

    summary = {"high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for check in checks:
        sev = str(check.get("severity", "")).casefold()
        if sev in summary and sev != "total":
            summary[sev] += 1
    summary["total"] = len(checks)

    return {
        "checks": checks,
        "inventory": inventory,
        "summary": summary,
        "commands_received": commands_received,
        "unsupported_commands": unsupported_commands,
    }
