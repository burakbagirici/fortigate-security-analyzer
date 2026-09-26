"""Unit and integration tests for FortiGate Analyzer CLI, JSON Export, and Packaging."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from unittest.mock import patch

import fortigate_analyzer
from fortigate_analyzer import (
    __version__,
    analyze_configuration,
    generate_static_report,
    parse_configuration,
    run_health_check,
    run_static_analysis,
)
from fortigate_analyzer.cli import (
    EXIT_FILE_READ_ERROR,
    EXIT_PROCESSING_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE_ERROR,
    build_parser,
    main,
    read_config_file,
)
from fortigate_analyzer.json_export import SCHEMA_VERSION, project_json_report


class TestCLIAndJSONExport(unittest.TestCase):
    """Verify CLI commands, arguments, exit codes, and JSON schema v1.0 export."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = os.path.join(os.path.dirname(__file__), "fixtures", "golden")
        cls.combined_path = os.path.join(cls.fixture_dir, "combined_realistic.conf")
        with open(cls.combined_path, "r", encoding="utf-8") as f:
            cls.combined_text = f.read()

        cls.scratch_dir = os.path.join(os.path.dirname(__file__), "..", "scratch")
        os.makedirs(cls.scratch_dir, exist_ok=True)

        cls.empty_path = os.path.join(cls.scratch_dir, "empty_cli_test.conf")
        with open(cls.empty_path, "w", encoding="utf-8") as f:
            f.write("   \n   \t  \n")

        cls.unrecognized_path = os.path.join(cls.scratch_dir, "unrecognized_cli_test.txt")
        with open(cls.unrecognized_path, "w", encoding="utf-8") as f:
            f.write("Plain text notes that do not represent any FortiGate configuration syntax.\nLine 2.\n")

        cls.partial_path = os.path.join(cls.scratch_dir, "partial_cli_test.conf")
        with open(cls.partial_path, "w", encoding="utf-8") as f:
            f.write("""config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
""")

        cls.no_findings_path = os.path.join(cls.scratch_dir, "no_findings_cli_test.conf")
        with open(cls.no_findings_path, "w", encoding="utf-8") as f:
            f.write("""config system global
    set hostname "SECURE_FW"
end
""")

        cls.malformed_path = os.path.join(cls.scratch_dir, "malformed_cli_test.conf")
        with open(cls.malformed_path, "w", encoding="utf-8") as f:
            f.write("""config firewall policy
    edit 1
        set srcintf
        set dstintf "port2"
    next
end
some arbitrary trailing garbage lines ###$$$
""")

    # 1. CLI module imports
    def test_01_cli_module_imports(self):
        """1. Package and CLI modules can be imported and expose key symbols."""
        self.assertEqual(fortigate_analyzer.__version__, "0.1.0")
        self.assertTrue(callable(run_static_analysis))
        self.assertTrue(callable(project_json_report))
        self.assertTrue(callable(main))

    # 2. --help
    def test_02_cli_help(self):
        """2. --help output includes program description and available subcommands."""
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn("fortigate-analyzer", help_text)
        self.assertIn("analyze", help_text)
        self.assertIn("export", help_text)
        self.assertIn("--version", help_text)

    # 3. --version
    def test_03_cli_version(self):
        """3. --version output outputs the correct application version."""
        parser = build_parser()
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm, patch("sys.stdout", out):
            parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("0.1.0", out.getvalue())

    # 4. analyze valid config
    def test_04_analyze_valid_config(self):
        """4. analyze command succeeds on valid configuration and outputs summary."""
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            code = main(["analyze", self.combined_path])
        self.assertEqual(code, EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("FortiGate Static Configuration Analysis", output)
        self.assertIn("Firewall Policies:", output)
        self.assertIn("Review Findings:", output)

    # 5. analyze partial config
    def test_05_analyze_partial_config(self):
        """5. analyze command preserves PARTIAL CONFIGURATION scope and succeeds."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = main(["analyze", self.partial_path])
        self.assertEqual(code, EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("PARTIAL CONFIGURATION", output)

    # 6. analyze no-findings config
    def test_06_analyze_no_findings_config(self):
        """6. analyze command with zero findings outputs neutral non-claim message."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = main(["analyze", self.no_findings_path])
        self.assertEqual(code, EXIT_SUCCESS)
        output = out.getvalue()
        self.assertIn("No review findings were generated by the supported static checks.", output)
        self.assertNotIn("Firewall is secure", output)

    # 7. analyze malformed recoverable config
    def test_07_analyze_malformed_recoverable_config(self):
        """7. analyze command tolerates recoverable malformed input without unhandled crash."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = main(["analyze", self.malformed_path])
        self.assertEqual(code, EXIT_SUCCESS)
        self.assertIn("FortiGate Static Configuration Analysis", out.getvalue())

    # 8. missing input file exit code
    def test_08_missing_input_file_exit_code(self):
        """8. Non-existent file returns exit code 2 and helpful stderr diagnostic."""
        err = io.StringIO()
        with patch("sys.stderr", err):
            code = main(["analyze", "non_existent_file_path_12345.conf"])
        self.assertEqual(code, EXIT_FILE_READ_ERROR)
        self.assertIn("not found", err.getvalue().lower())

    # 9. empty input behavior
    def test_09_empty_input_behavior(self):
        """9. Empty input file returns exit code 3 and stderr message."""
        err = io.StringIO()
        with patch("sys.stderr", err):
            code = main(["analyze", self.empty_path])
        self.assertEqual(code, EXIT_PROCESSING_ERROR)
        self.assertIn("empty", err.getvalue().lower())

    # 10. unrecognized input behavior
    def test_10_unrecognized_input_behavior(self):
        """10. Unrecognized non-FortiGate input returns exit code 3."""
        err = io.StringIO()
        with patch("sys.stderr", err):
            code = main(["analyze", self.unrecognized_path])
        self.assertEqual(code, EXIT_PROCESSING_ERROR)
        self.assertIn("not recognized", err.getvalue().lower())

    # 11. HTML export
    def test_11_html_export(self):
        """11. export --format html outputs self-contained HTML document."""
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            code = main(["export", self.combined_path, "--format", "html"])
        self.assertEqual(code, EXIT_SUCCESS)
        html_str = out.getvalue().strip()
        self.assertTrue(html_str.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", html_str)

    # 12. JSON export
    def test_12_json_export(self):
        """12. export --format json outputs valid JSON document to stdout."""
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            code = main(["export", self.combined_path, "--format", "json"])
        self.assertEqual(code, EXIT_SUCCESS)
        json_str = out.getvalue()
        self.assertTrue(len(json_str) > 100)

    # 13. JSON valid parsing
    def test_13_json_valid_parsing(self):
        """13. Output from JSON export successfully parses via standard json.loads."""
        out = io.StringIO()
        with patch("sys.stdout", out):
            code = main(["export", self.combined_path, "--format", "json"])
        self.assertEqual(code, EXIT_SUCCESS)
        data = json.loads(out.getvalue())
        self.assertIsInstance(data, dict)

    # 14. JSON schema_version
    def test_14_json_schema_version(self):
        """14. JSON document contains schema_version '1.0'."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        self.assertEqual(data.get("schema_version"), "1.0")

    # 15. application version separate from schema version
    def test_15_application_version_separate_from_schema_version(self):
        """15. metadata.analyzer_version is distinct from top-level schema_version."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["metadata"]["analyzer_version"], __version__)
        self.assertNotEqual(data["metadata"]["analyzer_version"], data["schema_version"])

    # 16. summary counts
    def test_16_summary_counts(self):
        """16. summary fields match computed policies and findings totals."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        summary = data["summary"]
        self.assertEqual(summary["total_policies"], len(data["policies"]))
        self.assertEqual(summary["enabled_policies"] + summary["disabled_policies"], summary["total_policies"])
        self.assertEqual(summary["total_findings"], len(data["findings"]))

    # 17. finding projection
    def test_17_finding_projection(self):
        """17. Finding objects expose required normalized safe fields."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        for f in data["findings"]:
            self.assertIn("severity", f)
            self.assertIn(f["severity"], ("HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertIn("category", f)
            self.assertIn("title", f)
            self.assertIn("description", f)
            self.assertIn("recommendation", f)
            self.assertIn("vdom", f)
            self.assertIn("evidence", f)
            self.assertIsInstance(f["evidence"], list)

    # 18. policy projection
    def test_18_policy_projection(self):
        """18. Policy objects expose sequence_index, selectors, interfaces, flow_type."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        self.assertTrue(len(data["policies"]) > 0)
        p0 = data["policies"][0]
        self.assertIn("sequence_index", p0)
        self.assertIn("policy_id", p0)
        self.assertIn("source_interfaces", p0)
        self.assertIn("destination_interfaces", p0)
        self.assertIn("action", p0)
        self.assertIn("technical_purpose", p0)

    # 19. IPv6 policy projection
    def test_19_ipv6_policy_projection(self):
        """19. IPv6 policies project address_family 'IPv6' and v6 selectors."""
        v6_config = """
config firewall policy
    edit 100
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        static_result = run_static_analysis(v6_config)
        data = project_json_report(static_result)
        self.assertEqual(len(data["policies"]), 1)
        pol = data["policies"][0]
        self.assertEqual(pol["address_family"], "IPv6")
        self.assertEqual(pol["source_selectors"], ["all"])
        self.assertEqual(pol["destination_selectors"], ["all"])

    # 20. VDOM preservation
    def test_20_vdom_preservation(self):
        """20. Multi-VDOM configuration preserves VDOM names in summary and items."""
        vdom_config = """
config vdom
    edit "CORP"
        config firewall policy
            edit 1
                set srcintf "p1"
                set dstintf "p2"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
            next
        end
    next
    edit "GUEST"
        config firewall policy
            edit 2
                set srcintf "p3"
                set dstintf "p4"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
            next
        end
    next
end
"""
        static_result = run_static_analysis(vdom_config)
        data = project_json_report(static_result)
        self.assertIn("CORP", data["summary"]["vdoms"])
        self.assertIn("GUEST", data["summary"]["vdoms"])
        self.assertEqual(data["summary"]["vdom_count"], 2)

    # 21. SSL-VPN projection
    def test_21_ssl_vpn_projection(self):
        """21. SSL-VPN settings and portals are projected accurately."""
        ssl_config = """
config vpn ssl settings
    set status enable
    set port 10443
    set source-interface "port1"
end
config vpn ssl web portal
    edit "full-tunnel"
        set tunnel-mode enable
        set web-mode disable
    next
end
"""
        static_result = run_static_analysis(ssl_config)
        data = project_json_report(static_result)
        ssl = data["ssl_vpn"]
        self.assertEqual(ssl["status"], "ENABLED")
        self.assertIn(10443, ssl["listening_ports"])
        self.assertEqual(len(ssl["portals"]), 1)
        self.assertTrue(ssl["portals"][0]["tunnel_mode"])
        self.assertFalse(ssl["portals"][0]["web_mode"])

    # 22. IPsec projection
    def test_22_ipsec_projection(self):
        """22. IPsec Phase 1 definitions are projected without secrets."""
        ipsec_config = """
config vpn ipsec phase1-interface
    edit "site-a"
        set interface "wan1"
        set remote-gw 198.51.100.2
        set proposal aes256-sha256
        set dhgrp 14
    next
end
"""
        static_result = run_static_analysis(ipsec_config)
        data = project_json_report(static_result)
        tunnels = data["vpn"]["ipsec_phase1"]
        self.assertEqual(len(tunnels), 1)
        self.assertEqual(tunnels[0]["name"], "site-a")
        self.assertEqual(tunnels[0]["remote_gw"], "198.51.100.2")

    # 23. local-in projection
    def test_23_local_in_projection(self):
        """23. Local-in policies are projected in local_in_policies list."""
        local_config = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "SSH"
        set action deny
    next
end
"""
        static_result = run_static_analysis(local_config)
        data = project_json_report(static_result)
        self.assertEqual(len(data["local_in_policies"]), 1)
        lip = data["local_in_policies"][0]
        self.assertEqual(lip["interface"], "port1")
        self.assertEqual(lip["action"], "deny")

    # 24. interface-policy projection
    def test_24_interface_policy_projection(self):
        """24. Interface policies are projected in interface_policies list."""
        intf_config = """
config firewall interface-policy
    edit 1
        set srcintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
"""
        static_result = run_static_analysis(intf_config)
        data = project_json_report(static_result)
        self.assertEqual(len(data["interface_policies"]), 1)
        self.assertEqual(data["interface_policies"][0]["interface"], "port1")

    # 25. documented defaults projection
    def test_25_documented_defaults_projection(self):
        """25. Documented defaults appear with effective values and citations."""
        defaults_path = os.path.join(self.fixture_dir, "version_default_applied.conf")
        with open(defaults_path, "r", encoding="utf-8") as f:
            text = f.read()
        static_result = run_static_analysis(text)
        data = project_json_report(static_result)
        defaults = data["documented_defaults"]
        self.assertTrue(len(defaults) > 0)
        self.assertEqual(defaults[0]["source"], "DOCUMENTED_DEFAULT")

    # 26. input scope projection
    def test_26_input_scope_projection(self):
        """26. input_assessment.analysis_scope contains coverage and limitation states."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        scope = data["input_assessment"]["analysis_scope"]
        self.assertIn("firewall_policies", scope)
        self.assertEqual(scope["firewall_policies"]["status"], "COVERED")

    # 27. raw config absent
    def test_27_raw_config_absent(self):
        """27. Raw configuration blocks and tokens are absent from JSON output."""
        static_result = run_static_analysis(self.combined_text)
        data = project_json_report(static_result)
        json_str = json.dumps(data)
        self.assertNotIn("config firewall policy\n", json_str)
        self.assertNotIn("set action accept\n", json_str)

    # 28. passwords absent
    def test_28_passwords_absent(self):
        """28. Injected administrator passwords never appear in JSON output."""
        secret_config = """
config system admin
    edit "admin_test"
        set password "SuperSecretPassword123!"
    next
end
"""
        static_result = run_static_analysis(secret_config)
        data = project_json_report(static_result)
        json_str = json.dumps(data)
        self.assertNotIn("SuperSecretPassword123!", json_str)

    # 29. PSKs absent
    def test_29_psks_absent(self):
        """29. Injected IPsec PSKs never appear in JSON output."""
        secret_config = """
config vpn ipsec phase1-interface
    edit "psk_tunnel"
        set psksecret "VerySecretPreSharedKey999!"
        set interface "port1"
    next
end
"""
        static_result = run_static_analysis(secret_config)
        data = project_json_report(static_result)
        json_str = json.dumps(data)
        self.assertNotIn("VerySecretPreSharedKey999!", json_str)

    # 30. ENC hashes absent
    def test_30_enc_hashes_absent(self):
        """30. ENC password hashes are strictly excluded from JSON output."""
        enc_config = """
config system admin
    edit "admin_enc"
        set password ENC AK1bM9f3XyZZ8891==
    next
end
"""
        static_result = run_static_analysis(enc_config)
        data = project_json_report(static_result)
        json_str = json.dumps(data)
        self.assertNotIn("AK1bM9f3XyZZ8891==", json_str)

    # 31. private key absent
    def test_31_private_key_absent(self):
        """31. Private keys are never parsed or present in JSON output."""
        priv_config = """
config vpn certificate local
    edit "testcert"
        set private-key "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    next
end
"""
        static_result = run_static_analysis(priv_config)
        data = project_json_report(static_result)
        json_str = json.dumps(data)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", json_str)

    # 32. deterministic JSON with fixed metadata
    def test_32_deterministic_json_with_fixed_metadata(self):
        """32. Repeated JSON projections with fixed metadata are byte-for-byte identical."""
        fixed_meta = {"filename": "test.conf", "generated_at": "2026-09-26 12:00:00 UTC"}
        static_result = run_static_analysis(self.combined_text, metadata=fixed_meta)
        json1 = json.dumps(project_json_report(static_result, metadata=fixed_meta), sort_keys=True)
        json2 = json.dumps(project_json_report(static_result, metadata=fixed_meta), sort_keys=True)
        self.assertEqual(json1, json2)

    # 33. stdout JSON contains no log contamination
    def test_33_stdout_json_contains_no_log_contamination(self):
        """33. export --format json writes strictly valid JSON to stdout without log noise."""
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            code = main(["export", self.combined_path, "--format", "json"])
        self.assertEqual(code, EXIT_SUCCESS)
        # Raw stdout must parse directly without string trimming of log banners
        parsed = json.loads(out.getvalue())
        self.assertIn("schema_version", parsed)
        self.assertNotIn("Analyzing...", out.getvalue())
        self.assertNotIn("Done!", out.getvalue())

    # 34. HTML uses reporting.py
    def test_34_html_uses_reporting_py(self):
        """34. HTML export reuses generate_static_report from reporting.py."""
        with patch("fortigate_analyzer.cli.generate_static_report") as mock_report:
            mock_report.return_value = "<!DOCTYPE html><html><body>Mock</body></html>"
            out = io.StringIO()
            with patch("sys.stdout", out):
                code = main(["export", self.combined_path, "--format", "html"])
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertTrue(mock_report.called)

    # 35. HTML does not reimplement analysis
    def test_35_html_does_not_reimplement_analysis(self):
        """35. HTML export relies on run_static_analysis rather than duplicating pipeline."""
        with patch("fortigate_analyzer.cli.run_static_analysis") as mock_run:
            mock_run.return_value = {
                "config": {"policies": [], "input_assessment": {"fortigate_detected": True}},
                "analysis": {"findings": []},
                "health": {"checks": []},
                "metadata": {},
            }
            out = io.StringIO()
            with patch("sys.stdout", out):
                code = main(["export", self.combined_path, "--format", "html"])
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertTrue(mock_run.called)

    # 36. CLI does not rerun analyzer unnecessarily
    def test_36_cli_does_not_rerun_analyzer_unnecessarily(self):
        """36. CLI invokes static analysis pipeline exactly once per command."""
        with patch("fortigate_analyzer.cli.run_static_analysis") as mock_run:
            mock_run.return_value = {
                "config": {"policies": [], "input_assessment": {"fortigate_detected": True}},
                "analysis": {"findings": []},
                "health": {"checks": []},
                "metadata": {},
            }
            out = io.StringIO()
            with patch("sys.stdout", out):
                main(["analyze", self.combined_path])
            self.assertEqual(mock_run.call_count, 1)

    # 37. all existing fixtures and golden landmark test
    def test_37_json_golden_landmarks(self):
        """37. Golden fixture combined_realistic.conf produces verified semantic landmarks."""
        static_result = run_static_analysis(
            self.combined_text,
            metadata={"filename": "combined_realistic.conf", "generated_at": "2026-09-26 12:00:00 UTC"},
        )
        data = project_json_report(static_result)

        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["metadata"]["filename"], "combined_realistic.conf")
        self.assertEqual(data["input_assessment"]["classification"], "FORTIGATE_CONFIGURATION_UNKNOWN_COMPLETENESS")
        self.assertEqual(data["summary"]["total_policies"], 6)
        self.assertEqual(data["summary"]["vdom_count"], 1)
        self.assertIn("root", data["summary"]["vdoms"])
        self.assertTrue(any("Disabled Firewall Policies" in f["title"] for f in data["findings"]))


if __name__ == "__main__":
    unittest.main()
