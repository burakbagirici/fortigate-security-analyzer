"""Unit tests for runtime_health.py."""

from __future__ import annotations

import os
import unittest

from runtime_health import (
    analyze_runtime_health,
    normalize_command_name,
    parse_runtime_output,
    sanitize_evidence_text,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> str:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


class TestRuntimeHealth(unittest.TestCase):

    def setUp(self):
        self.healthy_raw = read_fixture("runtime_healthy.txt")
        self.healthy_data = parse_runtime_output(self.healthy_raw)
        self.healthy_result = analyze_runtime_health(self.healthy_data)

        self.problematic_raw = read_fixture("runtime_problematic.txt")
        self.problematic_data = parse_runtime_output(self.problematic_raw)
        self.problematic_result = analyze_runtime_health(self.problematic_data)

    def test_command_section_parsing(self):
        self.assertIn("get system status", self.healthy_data["commands"])
        self.assertIn("get system ha status", self.healthy_data["commands"])
        self.assertIn("diagnose system ntp status", self.healthy_data["commands"])
        self.assertGreaterEqual(len(self.healthy_data["commands_received"]), 8)

    def test_unknown_command_tolerance(self):
        raw = """
=== COMMAND: get system status ===
Hostname: FGT-TEST

=== COMMAND: unsupported some random command ===
Some output text here

=== COMMAND: diagnose test unknown 123 ===
More test output
"""
        parsed = parse_runtime_output(raw)
        self.assertIn("unsupported some random command", parsed["unsupported_commands"])
        self.assertIn("diagnose test unknown 123", parsed["unsupported_commands"])
        result = analyze_runtime_health(parsed)
        # Should not crash and should not generate speculative findings for unsupported commands
        self.assertEqual(len(result["checks"]), 0)
        self.assertIn("unsupported some random command", result["unsupported_commands"])

    def test_system_status_inventory_extraction(self):
        sys_status = self.healthy_result["inventory"]["system_status"]
        self.assertEqual(sys_status["hostname"], "FGT-PRIMARY-01")
        self.assertIn("v7.2.5", sys_status["version"])
        self.assertEqual(sys_status["model"], "FortiGate-100F")
        self.assertEqual(sys_status["serial_number"], "FG100FTK21000001")
        self.assertEqual(sys_status["system_time"], "Tue Sep 22 23:59:59 2026")

    def test_healthy_fortiguard_update_state(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "FortiGuard / Updates"]
        self.assertEqual(len(checks), 0)
        self.assertEqual(self.healthy_result["inventory"]["fortiguard"]["status"], "normal")

    def test_explicit_fortiguard_update_failure(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "FortiGuard / Updates"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "MEDIUM")
        self.assertEqual(check["title"], "FortiGuard or Update Service Reports a Failure")
        self.assertTrue(any("failed" in e.lower() or "error" in e.lower() for e in check["evidence"]))

    def test_healthy_ha_state(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "High Availability"]
        self.assertEqual(len(checks), 0)
        self.assertEqual(self.healthy_result["inventory"]["ha"]["sync_status"], "in-sync")

    def test_out_of_sync_ha_member(self):
        checks = [c for c in self.problematic_result["checks"] if c["title"] == "HA Synchronization Issue Reported"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "MEDIUM")
        self.assertEqual(check["category"], "High Availability")
        self.assertTrue(any("out-of-sync" in e.lower() for e in check["evidence"]))

    def test_failed_down_ha_member(self):
        checks = [c for c in self.problematic_result["checks"] if c["title"] == "HA Member Problem Reported"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "HIGH")
        self.assertEqual(check["category"], "High Availability")
        self.assertTrue(any("dead" in e.lower() for e in check["evidence"]))

    def test_synchronized_ntp(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "Time Synchronization"]
        self.assertEqual(len(checks), 0)
        self.assertEqual(self.healthy_result["inventory"]["ntp"]["synchronization_state"], "synchronized")

    def test_unsynchronized_ntp(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "Time Synchronization"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "MEDIUM")
        self.assertEqual(check["title"], "NTP Runtime Synchronization Problem")
        self.assertTrue(any("synchronized: no" in e.lower() or "unreachable" in e.lower() for e in check["evidence"]))

    def test_healthy_hardware_status(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "Hardware Health"]
        self.assertEqual(len(checks), 0)

    def test_explicit_psu_sensor_failure(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "Hardware Health"]
        self.assertGreaterEqual(len(checks), 1)
        titles = {c["title"] for c in checks}
        self.assertIn("Hardware Fault Reported: Power Supply Failure", titles)
        psu_check = next(c for c in checks if c["title"] == "Hardware Fault Reported: Power Supply Failure")
        self.assertEqual(psu_check["severity"], "HIGH")

    def test_empty_crash_log(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "System Stability"]
        self.assertEqual(len(checks), 0)

    def test_crash_entries_detected(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "System Stability"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "MEDIUM")
        self.assertEqual(check["title"], "Crash Log Entries Detected")
        self.assertEqual(self.problematic_result["inventory"]["crashlog"]["crash_count"], 2)

    def test_empty_configuration_error_log(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "Configuration Integrity"]
        self.assertEqual(len(checks), 0)

    def test_configuration_errors_detected(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "Configuration Integrity"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "MEDIUM")
        self.assertEqual(check["title"], "Runtime Configuration Errors Reported")
        self.assertEqual(self.problematic_result["inventory"]["config_error_log"]["error_count"], 2)

    def test_routing_table_with_ipv4_default_route(self):
        checks = [c for c in self.healthy_result["checks"] if c["category"] == "Routing"]
        self.assertEqual(len(checks), 0)
        routing = self.healthy_result["inventory"]["routing"]
        self.assertTrue(routing["has_default_route"])
        self.assertEqual(routing["default_gateway"], "203.0.113.1")
        self.assertEqual(routing["default_route_interface"], "port1")

    def test_routing_table_without_default_route(self):
        checks = [c for c in self.problematic_result["checks"] if c["category"] == "Routing"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["severity"], "LOW")
        self.assertEqual(check["title"], "Default Route Not Detected in Supplied Routing Table")
        routing = self.problematic_result["inventory"]["routing"]
        self.assertFalse(routing["has_default_route"])

    def test_missing_command_does_not_create_finding(self):
        # Supply ONLY get system status
        raw = """
=== COMMAND: get system status ===
Version: FortiGate-60F v7.2.4
Hostname: FGT-MINIMAL
Serial-Number: FGT60F0000000000
"""
        parsed = parse_runtime_output(raw)
        result = analyze_runtime_health(parsed)
        # No HA, NTP, Hardware, FortiGuard, Routing, Crashlog command supplied -> 0 findings!
        self.assertEqual(len(result["checks"]), 0)
        self.assertEqual(result["summary"]["total"], 0)
        self.assertIn("system_status", result["inventory"])

    def test_secret_evidence_sanitization(self):
        raw = """
=== COMMAND: diagnose debug config-error-log read ===
>>> "set password SuperSecretPassword123" : command parse error
>>> "set psksecret SuperSecretPSK456" : error
>>> "set snmp community MyPublicCommunity" : error
"""
        parsed = parse_runtime_output(raw)
        result = analyze_runtime_health(parsed)
        checks = result["checks"]
        self.assertEqual(len(checks), 1)
        check = checks[0]
        for item in check["evidence"]:
            self.assertNotIn("SuperSecretPassword123", item)
            self.assertNotIn("SuperSecretPSK456", item)
            self.assertNotIn("MyPublicCommunity", item)
            self.assertTrue("[REDACTED]" in item)

    def test_malformed_incomplete_runtime_input_does_not_crash(self):
        malformed_inputs = [
            "",
            "   \n\n   ",
            "This is just random garbage text without any command delimiters\nline 2",
            "=== COMMAND: ===\nempty command header",
            "=== COMMAND: get sys ha status ===\n",
            "=== COMMAND: get system status ===\nrandom content\n=== COMMAND: incomplete",
        ]
        for text in malformed_inputs:
            parsed = parse_runtime_output(text)
            self.assertIsInstance(parsed, dict)
            result = analyze_runtime_health(parsed)
            self.assertIsInstance(result, dict)
            self.assertIn("checks", result)
            self.assertIn("summary", result)
            self.assertIn("inventory", result)

    def test_runtime_severity_summary_counts_correctly(self):
        summary = self.problematic_result["summary"]
        high_checks = [c for c in self.problematic_result["checks"] if c["severity"] == "HIGH"]
        med_checks = [c for c in self.problematic_result["checks"] if c["severity"] == "MEDIUM"]
        low_checks = [c for c in self.problematic_result["checks"] if c["severity"] == "LOW"]

        self.assertEqual(summary["high"], len(high_checks))
        self.assertEqual(summary["medium"], len(med_checks))
        self.assertEqual(summary["low"], len(low_checks))
        self.assertEqual(summary["total"], len(self.problematic_result["checks"]))
        self.assertGreater(summary["total"], 0)

    def test_standalone_ha_not_reported_as_unhealthy(self):
        raw = """
=== COMMAND: get sys ha status ===
HA Health Status: OK
Model: FortiGate-60F
Mode: standalone
Group: 0
"""
        parsed = parse_runtime_output(raw)
        result = analyze_runtime_health(parsed)
        ha_checks = [c for c in result["checks"] if c["category"] == "High Availability"]
        self.assertEqual(len(ha_checks), 0)
        self.assertEqual(result["inventory"]["ha"]["ha_mode"], "standalone")


if __name__ == "__main__":
    unittest.main()
