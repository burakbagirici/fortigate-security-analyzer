"""Lightweight tests for pure Streamlit UI integration helpers."""

import os
import unittest
from unittest.mock import patch

try:
    import streamlit
    from streamlit.testing.v1 import AppTest
    import app
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False
    AppTest = None
    app = None


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> str:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as file:
        return file.read()


@unittest.skipUnless(STREAMLIT_AVAILABLE, "Streamlit is not installed (optional UI dependency)")
class TestAppIntegration(unittest.TestCase):

    def test_application_imports_and_empty_state_renders(self):
        rendered = AppTest.from_file("app.py").run(timeout=10)

        self.assertEqual(len(rendered.exception), 0)
        self.assertTrue(
            any(
                "Start with a FortiGate configuration backup" in item.value
                for item in rendered.info
            )
        )

    def test_pipeline_analyzes_once_and_reuses_result_for_health(self):
        config = {"policies": []}
        analysis = {"policy_assessments": [], "findings": []}
        health = {"checks": [], "summary": {}}

        with (
            patch("app.parse_configuration", return_value=config) as parse_mock,
            patch("app.analyze_configuration", return_value=analysis) as analyze_mock,
            patch("app.run_health_check", return_value=health) as health_mock,
        ):
            payload = app._run_analysis_pipeline("config system global\nend")

        parse_mock.assert_called_once()
        analyze_mock.assert_called_once_with(config)
        health_mock.assert_called_once_with(config, analysis_result=analysis)
        self.assertIs(payload["analysis_result"], analysis)

    def test_single_vdom_configuration_pipeline(self):
        payload = app._run_analysis_pipeline(read_fixture("basic.conf"))

        self.assertEqual(app._detected_vdoms(payload["config"]), [])
        self.assertTrue(payload["analysis_result"]["policy_assessments"])
        self.assertIn("checks", payload["health_result"])

    def test_multivdom_detection_and_filtering(self):
        payload = app._run_analysis_pipeline(read_fixture("multivdom.conf"))
        config = payload["config"]

        self.assertEqual(app._detected_vdoms(config), ["root", "VDOM-B"])
        root_policies = app._filter_vdom_items(config["policies"], "root")
        branch_policies = app._filter_vdom_items(config["policies"], "VDOM-B")
        self.assertEqual(len(root_policies), 3)
        self.assertEqual(len(branch_policies), 2)
        self.assertTrue(all(policy["vdom"] == "root" for policy in root_policies))

    def test_health_filter_keeps_global_and_selected_vdom_results(self):
        checks = [
            {"title": "Global", "evidence": ["Global setting"]},
            {"title": "Root", "evidence": ["VDOM: root; Policy ID: 1"]},
            {"title": "Branch", "evidence": ["VDOM: VDOM-B; Policy ID: 2"]},
            {
                "title": "Aggregated",
                "evidence": [
                    "VDOM: root; Policy ID: 3",
                    "VDOM: VDOM-B; Policy ID: 4",
                ],
            },
        ]

        filtered = app._filter_health_checks(checks, "root")
        titles = {check["title"] for check in filtered}
        aggregated = next(check for check in filtered if check["title"] == "Aggregated")
        self.assertEqual(titles, {"Global", "Root", "Aggregated"})
        self.assertEqual(aggregated["evidence"], ["VDOM: root; Policy ID: 3"])

    def test_policy_inventory_contains_requested_columns_and_missing_markers(self):
        rows = app._policy_inventory_rows(
            [
                {
                    "id": 1,
                    "vdom": "root",
                    "sequence_index": 0,
                    "srcintf": ["lan"],
                    "dstintf": ["wan"],
                    "service": ["HTTPS", "SSH"],
                    "inspection-mode": "flow",
                    "logtraffic-start": "enable",
                    "capture-packet": "enable",
                    "auto-asic-offload": "disable",
                }
            ]
        )

        self.assertEqual(rows[0]["VDOM"], "root")
        self.assertEqual(rows[0]["Service"], "HTTPS, SSH")
        self.assertEqual(rows[0]["Schedule"], "-")
        self.assertIn("SSL/SSH Profile", rows[0])
        self.assertEqual(rows[0]["Inspection Mode"], "flow")
        self.assertEqual(rows[0]["Log Traffic Start"], "enable")
        self.assertEqual(rows[0]["Packet Capture"], "enable")
        self.assertEqual(rows[0]["ASIC Offload"], "disable")

    def test_relationship_and_vpn_results_are_available_to_ui(self):
        shadow_payload = app._run_analysis_pipeline(read_fixture("shadowing.conf"))
        relationship_titles = {
            finding["title"]
            for finding in shadow_payload["analysis_result"]["findings"]
            if finding["title"] in app.RELATIONSHIP_TITLES
        }
        vpn_payload = app._run_analysis_pipeline(read_fixture("vpn.conf"))
        vpn_checks = [
            check
            for check in vpn_payload["health_result"]["checks"]
            if check.get("category") == "VPN / IPsec"
        ]

        self.assertIn("Duplicate Firewall Policy", relationship_titles)
        self.assertIn("Fully Shadowed Firewall Policy", relationship_titles)
        self.assertIn("Conflicting Policy Shadowing", relationship_titles)
        self.assertTrue(vpn_checks)

    def test_empty_configuration_pipeline_is_safe(self):
        payload = app._run_analysis_pipeline("")

        self.assertEqual(payload["config"]["policies"], [])
        self.assertEqual(payload["analysis_result"]["policy_assessments"], [])
        self.assertEqual(payload["health_result"]["checks"], [])

    def test_no_numeric_security_score_is_present(self):
        with open("app.py", "r", encoding="utf-8") as file:
            source = file.read().casefold()

        self.assertNotIn("configuration security score", source)
        self.assertNotIn("runtime security score", source)
        self.assertNotIn("needs attention", source)
        self.assertNotIn("score calculation", source)

    def test_runtime_health_analysis_mode_and_empty_state_renders(self):
        at = AppTest.from_file("app.py").run(timeout=10)
        self.assertEqual(len(at.exception), 0)
        self.assertEqual(at.radio[0].value, "Configuration Analysis")

        # Switch to Runtime Health Analysis mode
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        self.assertEqual(len(at.exception), 0)
        self.assertEqual(at.radio[0].value, "Runtime Health Analysis")
        self.assertTrue(
            any("Start with FortiGate CLI diagnostic command outputs" in item.value for item in at.info)
        )
        # Verify template and raw commands in code blocks
        code_blocks = [c.value for c in at.code]
        self.assertTrue(any("=== COMMAND: get system status ===" in block for block in code_blocks))
        self.assertTrue(any("get sys fortiguard-service status" in block for block in code_blocks))

    def test_runtime_pipeline_execution(self):
        healthy_text = read_fixture("runtime_healthy.txt")
        payload = app._run_runtime_pipeline(healthy_text)
        self.assertIn("runtime_data", payload)
        self.assertIn("runtime_result", payload)
        self.assertIn("system_status", payload["runtime_result"]["inventory"])
        self.assertEqual(payload["runtime_result"]["summary"]["total"], 0)

    def test_healthy_runtime_fixture_renders(self):
        at = AppTest.from_file("app.py").run(timeout=10)
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        healthy_payload = app._run_runtime_pipeline(read_fixture("runtime_healthy.txt"))
        at.session_state["runtime_payload"] = healthy_payload
        at.session_state["runtime_filename"] = "runtime_healthy.txt"
        at.session_state["runtime_file_size"] = 1200
        at.run(timeout=10)

        self.assertEqual(len(at.exception), 0)
        self.assertTrue(
            any("No problems were detected in the supplied output" in item.value for item in at.success)
        )
        # Check metrics
        metric_labels = [m.label for m in at.metric]
        self.assertIn("Total Findings", metric_labels)
        self.assertIn("HIGH", metric_labels)
        self.assertIn("MEDIUM", metric_labels)
        self.assertIn("LOW", metric_labels)
        total_metric = next(m for m in at.metric if m.label == "Total Findings")
        self.assertEqual(total_metric.value, "0")

    def test_problematic_runtime_fixture_renders(self):
        at = AppTest.from_file("app.py").run(timeout=10)
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        problem_payload = app._run_runtime_pipeline(read_fixture("runtime_problematic.txt"))
        at.session_state["runtime_payload"] = problem_payload
        at.session_state["runtime_filename"] = "runtime_problematic.txt"
        at.session_state["runtime_file_size"] = 2500
        at.run(timeout=10)

        self.assertEqual(len(at.exception), 0)
        self.assertTrue(
            any("Runtime observations were detected in the supplied CLI output" in item.value for item in at.warning)
        )
        total_metric = next(m for m in at.metric if m.label == "Total Findings")
        self.assertNotEqual(total_metric.value, "0")

    def test_runtime_inventory_and_findings_render(self):
        at = AppTest.from_file("app.py").run(timeout=10)
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        healthy_payload = app._run_runtime_pipeline(read_fixture("runtime_healthy.txt"))
        at.session_state["runtime_payload"] = healthy_payload
        at.session_state["runtime_filename"] = "runtime_healthy.txt"
        at.session_state["runtime_file_size"] = 1200
        at.run(timeout=10)

        subheader_texts = [s.value for s in at.subheader]
        self.assertTrue(any("Runtime Health Overview" in text or "Runtime Findings" in text or "Runtime Inventory" in text for text in subheader_texts))

    def test_standalone_ha_does_not_display_false_warning(self):
        standalone_text = """=== COMMAND: get system status ===
Hostname: FGT-STANDALONE

=== COMMAND: get sys ha status ===
HA Health Status: OK
Model: FortiGate-60F
Mode: standalone
Group: 0
"""
        payload = app._run_runtime_pipeline(standalone_text)
        ha_checks = [c for c in payload["runtime_result"]["checks"] if c["category"] == "High Availability"]
        self.assertEqual(len(ha_checks), 0)
        self.assertEqual(payload["runtime_result"]["inventory"]["ha"]["ha_mode"], "standalone")

    def test_unsupported_command_does_not_crash_ui(self):
        raw_text = """=== COMMAND: get system status ===
Hostname: FGT-1

=== COMMAND: some random unsupported command ===
Some output
"""
        payload = app._run_runtime_pipeline(raw_text)
        at = AppTest.from_file("app.py").run(timeout=10)
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        at.session_state["runtime_payload"] = payload
        at.session_state["runtime_filename"] = "test.txt"
        at.session_state["runtime_file_size"] = 100
        at.run(timeout=10)

        self.assertEqual(len(at.exception), 0)
        self.assertIn("some random unsupported command", payload["runtime_result"]["unsupported_commands"])
        self.assertEqual(len(payload["runtime_result"]["checks"]), 0)

    def test_missing_runtime_command_not_displayed_as_security_finding(self):
        # Only system status provided
        raw_text = """=== COMMAND: get system status ===
Hostname: FGT-MINIMAL
Version: FortiGate-60F v7.2.4
Serial-Number: FGT60FTK00000001
"""
        payload = app._run_runtime_pipeline(raw_text)
        self.assertEqual(len(payload["runtime_result"]["checks"]), 0)
        self.assertEqual(payload["runtime_result"]["summary"]["total"], 0)

    def test_static_and_runtime_session_states_remain_separate(self):
        at = AppTest.from_file("app.py").run(timeout=10)
        static_payload = app._run_analysis_pipeline(read_fixture("basic.conf"))
        runtime_payload = app._run_runtime_pipeline(read_fixture("runtime_healthy.txt"))

        at.session_state["analysis_payload"] = static_payload
        at.session_state["analysis_filename"] = "basic.conf"
        at.session_state["runtime_payload"] = runtime_payload
        at.session_state["runtime_filename"] = "runtime_healthy.txt"

        # Check in Configuration Analysis mode
        at.radio[0].set_value("Configuration Analysis").run(timeout=10)
        self.assertIs(at.session_state["analysis_payload"], static_payload)
        self.assertIs(at.session_state["runtime_payload"], runtime_payload)

        # Switch to Runtime Health Analysis mode
        at.radio[0].set_value("Runtime Health Analysis").run(timeout=10)
        self.assertIs(at.session_state["analysis_payload"], static_payload)
        self.assertIs(at.session_state["runtime_payload"], runtime_payload)


if __name__ == "__main__":
    unittest.main()
