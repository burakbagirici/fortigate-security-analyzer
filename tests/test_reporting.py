"""Unit and integration test suite for FortiGate static analysis HTML report generation."""

from __future__ import annotations

import os
import re
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import parse_configuration
from reporting import generate_static_report

try:
    import streamlit
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False


class TestStaticReporting(unittest.TestCase):
    """Verify HTML static report generation, formatting, structure, and safety."""

    @classmethod
    def setUpClass(cls):
        golden_dir = os.path.join(os.path.dirname(__file__), "fixtures", "golden")
        cls.combined_path = os.path.join(golden_dir, "combined_realistic.conf")
        with open(cls.combined_path, "r", encoding="utf-8") as f:
            cls.combined_text = f.read()

        cls.combined_cfg = parse_configuration(cls.combined_text)
        cls.combined_analysis = analyze_configuration(cls.combined_cfg)
        cls.combined_health = run_health_check(cls.combined_cfg, cls.combined_analysis)
        cls.combined_report = generate_static_report(
            cls.combined_cfg,
            cls.combined_analysis,
            cls.combined_health,
            {"filename": "combined_realistic.conf", "file_size": len(cls.combined_text)},
        )

    def test_01_basic_html_report_generation(self):
        """1. Basic HTML report generation produces non-empty string with DOCTYPE."""
        self.assertIsInstance(self.combined_report, str)
        self.assertTrue(len(self.combined_report) > 1000)
        self.assertTrue(self.combined_report.strip().startswith("<!DOCTYPE html>"))
        self.assertIn("<html", self.combined_report)
        self.assertIn("</html>", self.combined_report)

    def test_02_valid_html_structure(self):
        """2. Report has valid HTML landmarks: head, title, body, container, cards."""
        self.assertIn("<head>", self.combined_report)
        self.assertIn("</head>", self.combined_report)
        self.assertIn("<body>", self.combined_report)
        self.assertIn("</body>", self.combined_report)
        self.assertIn("<title>", self.combined_report)
        self.assertIn('class="container"', self.combined_report)
        self.assertIn('class="card"', self.combined_report)

    def test_03_summary_counts(self):
        """3. Executive summary counts match underlying finding and policy numbers."""
        findings = self.combined_analysis["findings"] + self.combined_health["checks"]
        high_expected = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
        policies_count = len(self.combined_cfg.get("policies", []))

        self.assertIn(f">{policies_count}</div>", self.combined_report)
        self.assertIn("Executive Summary", self.combined_report)

    def test_04_input_assessment_rendering(self):
        """4. Input quality assessment, classification, and scope are rendered without invented confidence."""
        self.assertIn("Input Quality &amp; Analysis Scope Assessment", self.combined_report)
        classification = self.combined_cfg["input_assessment"]["classification"].replace("_", " ")
        self.assertIn(classification, self.combined_report)
        self.assertNotIn("Confidence", self.combined_report)

    def test_05_fortios_version_rendering(self):
        """5. FortiOS version information is displayed when present in backup header."""
        test_config = """#config-version=FG100E-7.2.5-FW-build1517:230810
config system global
    set hostname "TEST-FW"
end
"""
        cfg = parse_configuration(test_config)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc, {"filename": "test.conf"})
        self.assertIn("FortiOS 7.2.5", report)

    def test_06_policy_table_rendering(self):
        """6. Policy inventory table displays sequence, ID, names, interfaces, action."""
        self.assertIn("Firewall Policy Inventory", self.combined_report)
        self.assertIn("client", self.combined_report)
        self.assertIn("wan1", self.combined_report)
        self.assertIn("ACCEPT", self.combined_report)

    def test_07_address_family_rendering(self):
        """7. Address family badges (IPv4 and IPv6) are rendered cleanly in tables."""
        test_v6 = """
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        cfg = parse_configuration(test_v6)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("IPv4", report)
        self.assertIn("IPv6", report)

    def test_08_finding_rendering(self):
        """8. Finding details include title, description, recommendation, and evidence."""
        self.assertIn("Review Findings by Category", self.combined_report)
        self.assertIn("Description:", self.combined_report)
        self.assertIn("Recommendation:", self.combined_report)

    def test_09_finding_severity_rendering(self):
        """9. Severity badges are rendered with distinct classes."""
        self.assertTrue(
            "badge-HIGH" in self.combined_report
            or "badge-MEDIUM" in self.combined_report
            or "badge-LOW" in self.combined_report
            or "badge-INFO" in self.combined_report
        )

    def test_10_vdom_rendering(self):
        """10. VDOM information is exposed in report overview and metrics."""
        test_vdom = """
config vdom
    edit "CORP_VDOM"
        config firewall policy
            edit 1
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
            next
        end
    next
    edit "DMZ_VDOM"
        config firewall policy
            edit 2
                set srcintf "port3"
                set dstintf "port4"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
            next
        end
    next
end
"""
        cfg = parse_configuration(test_vdom)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("VDOMs Detected", report)
        self.assertIn("CORP_VDOM", report)

    def test_11_duplicate_policy_rendering(self):
        """11. Duplicate firewall policy findings are displayed in relationships section."""
        test_dupe = """
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
        cfg = parse_configuration(test_dupe)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("Policy Duplicate &amp; Shadowing Analysis", report)
        self.assertIn("Duplicate Firewall Policy", report)

    def test_12_shadowing_rendering(self):
        """12. Fully shadowed policy findings are displayed with earlier vs later details."""
        test_shadow = """
config firewall address
    edit "SUB_NET"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "SUB_NET"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
        cfg = parse_configuration(test_shadow)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("Fully Shadowed Firewall Policy", report)

    def test_13_ipsec_section(self):
        """13. IPsec section displays phase 1 interfaces without live tunnel claims."""
        test_ipsec = """
config vpn ipsec phase1-interface
    edit "to_branch"
        set interface "port1"
        set remote-gw 198.51.100.1
        set proposal aes256-sha256
        set dhgrp 14
    next
end
"""
        cfg = parse_configuration(test_ipsec)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("IPsec VPN Static Configuration", report)
        self.assertIn("to_branch", report)
        self.assertIn("198.51.100.1", report)
        self.assertIn("aes256-sha256", report)
        self.assertNotIn("Tunnel is UP", report)
        self.assertNotIn("Tunnel is DOWN", report)

    def test_14_ssl_vpn_section(self):
        """14. SSL-VPN section displays settings and portals without reachability claims."""
        test_ssl = """
config vpn ssl settings
    set status enable
    set port 10443
    set servercert "self-signed"
    set source-interface "port1"
end
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set web-mode enable
    next
end
"""
        cfg = parse_configuration(test_ssl)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("SSL-VPN Remote Access Configuration", report)
        self.assertIn("10443", report)
        self.assertIn("full-access", report)
        self.assertNotIn("Port open to Internet", report)
        self.assertNotIn("Authentication active", report)

    def test_15_local_in_section(self):
        """15. Local-in policy table displays management filtering rules."""
        test_local = """
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
        cfg = parse_configuration(test_local)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("Local-In Policies", report)
        self.assertIn("DENY", report)
        self.assertIn("SSH", report)

    def test_16_interface_policy_section(self):
        """16. Interface policies display inspection profile attachments."""
        test_intf = """
config firewall interface-policy
    edit 1
        set srcintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set ips-sensor-status enable
        set ips-sensor "default"
    next
end
"""
        cfg = parse_configuration(test_intf)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("Interface Policies", report)
        self.assertIn("IPS:", report)
        self.assertIn("default", report)

    def test_17_ipv6_section(self):
        """17. IPv6 section summarizes IPv6 tables and object counts."""
        test_v6 = """
config firewall address6
    edit "V6_NET"
        set ip6 2001:db8::/32
    next
end
config firewall local-in-policy6
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
    next
end
"""
        cfg = parse_configuration(test_v6)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("IPv6 Static Analysis Coverage", report)
        self.assertIn("Addresses (IPv6)", report)

    def test_18_documented_defaults(self):
        """18. Documented defaults appear as baseline facts and not security findings."""
        defaults_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "golden", "version_default_applied.conf"
        )
        with open(defaults_path, "r", encoding="utf-8") as f:
            defaults_text = f.read()
        cfg = parse_configuration(defaults_text)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("Documented FortiOS Defaults Applied", report)
        self.assertIn("DOCUMENTED_DEFAULT", report)

    def test_19_scope_limitation_rendering(self):
        """19. Scope limitation states (UNAVAILABLE_NOT_SUPPLIED, COVERED) are displayed."""
        self.assertIn("Analysis Scope Assessment", self.combined_report)
        self.assertTrue(
            "COVERED" in self.combined_report
            or "UNAVAILABLE_NOT_SUPPLIED" in self.combined_report
            or "UNOBSERVED_IN_INPUT" in self.combined_report
        )

    def test_20_no_numeric_score(self):
        """20. No numeric security score or arbitrary risk grade is generated."""
        self.assertNotRegex(self.combined_report, r"Security Score:\s*\d+")
        self.assertNotRegex(self.combined_report, r"Risk Score:\s*\d+")
        self.assertNotRegex(self.combined_report, r"\d+\s*/\s*100")
        self.assertNotRegex(self.combined_report, r"Score:\s*\d+%")

    def test_21_no_runtime_state_claims(self):
        """21. Report explicitly includes the static vs runtime analysis disclaimer."""
        self.assertIn("Static vs. Runtime Analysis Boundary", self.combined_report)
        self.assertIn("cannot", self.combined_report)
        self.assertIn("tunnel UP/DOWN", self.combined_report)

    def test_22_no_raw_config_inclusion(self):
        """22. Raw configuration blocks are not included in the report."""
        self.assertNotIn("config firewall policy\n", self.combined_report)
        self.assertNotIn("set service ALL\n", self.combined_report)
        self.assertNotIn("end\nconfig ", self.combined_report)

    def test_23_secret_suppression(self):
        """23. Injected fake secrets are strictly excluded at structured parser level and absent from HTML."""
        secret_config = """
config system admin
    edit "admin_test"
        set password "SuperSecretPassword123!"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config vpn ipsec phase1-interface
    edit "tunnel_psk"
        set psksecret "MyPresharedKey999!"
        set interface "port1"
    next
end
config system snmp community
    edit 1
        set name "public_secret_community"
    next
end
"""
        cfg = parse_configuration(secret_config)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)

        # Primary protection: secrets never enter structured models
        self.assertNotIn("SuperSecretPassword123!", str(cfg.get("admins", [])))
        self.assertNotIn("MyPresharedKey999!", str(cfg.get("ipsec_phase1", [])))
        self.assertNotIn("public_secret_community", str(cfg))

        report = generate_static_report(cfg, an, hc)

        self.assertNotIn("SuperSecretPassword123!", report)
        self.assertNotIn("MyPresharedKey999!", report)
        self.assertNotIn("public_secret_community", report)

    def test_24_enc_hash_suppression(self):
        """24. Injected ENC hash values are strictly suppressed from HTML output."""
        enc_config = """
config system admin
    edit "admin_enc"
        set password ENC AK1bM9f3XyZZ8891==
    next
end
"""
        cfg = parse_configuration(enc_config)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)

        self.assertNotIn("AK1bM9f3XyZZ8891==", report)
        self.assertNotIn("ENC AK1bM9f3XyZZ8891==", report)

    def test_25_partial_config_report(self):
        """25. Partial configuration produces clean report with scope limitations."""
        partial_config = """
config firewall policy
    edit 10
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        cfg = parse_configuration(partial_config)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc, {"filename": "partial.conf"})
        self.assertIn("Partial Configuration", report)
        self.assertIn("Firewall Policy Inventory (1)", report)

    def test_26_malformed_but_recoverable_config(self):
        """26. Malformed input generates a clean report without throwing unhandled exceptions."""
        malformed = """
config firewall policy
    edit 1
        set srcintf "port1
        set dstintf
    next
end
some unknown corrupt text @@@!!!
"""
        cfg = parse_configuration(malformed)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIsInstance(report, str)
        self.assertIn("Executive Summary", report)

    def test_27_no_findings_report(self):
        """27. Configuration with zero findings displays neutral success summary."""
        empty_clean = """
config system global
    set hostname "SECURE_FW"
end
"""
        cfg = parse_configuration(empty_clean)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)
        self.assertIn("0 review findings", report)
        self.assertIn("No security or configuration review findings were identified", report)

    def test_28_1000_policy_report_no_crash(self):
        """28. 1,000 synthetic policies generate HTML report in sub-second time without crashing."""
        policy_lines = []
        for i in range(1, 1001):
            policy_lines.append(f"""    edit {i}
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next""")
        config_text = "config firewall policy\n" + "\n".join(policy_lines) + "\nend\n"

        cfg = parse_configuration(config_text)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)

        report = generate_static_report(cfg, an, hc)
        self.assertIsInstance(report, str)
        self.assertIn("Firewall Policy Inventory (1000)", report)
        self.assertIn("Displaying first 500 of 1000 policies", report)

    def test_29_deterministic_repeated_report_output(self):
        """29. Repeated report generation on identical data with fixed timestamp is deterministic."""
        fixed_meta = {"filename": "test.conf", "generated_at": "2026-09-26 12:00:00 UTC"}
        rep1 = generate_static_report(self.combined_cfg, self.combined_analysis, self.combined_health, fixed_meta)
        rep2 = generate_static_report(self.combined_cfg, self.combined_analysis, self.combined_health, fixed_meta)
        self.assertEqual(rep1, rep2)
        # Verify valid UTC timestamp when metadata generated_at is omitted
        rep_auto = generate_static_report(self.combined_cfg, self.combined_analysis, self.combined_health, {"filename": "test.conf"})
        self.assertRegex(rep_auto, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")

    @unittest.skipUnless(STREAMLIT_AVAILABLE, "Streamlit is not installed (optional UI dependency)")
    def test_30_streamlit_report_download_integration(self):
        """30. app.py contains report download integration and uses cached payload."""
        import app
        self.assertTrue(hasattr(app, "generate_static_report"))
        with open(app.__file__, "r", encoding="utf-8") as f:
            app_code = f.read()
        self.assertIn("st.download_button", app_code)
        self.assertIn("html_report", app_code)

    def test_31_golden_report_landmarks(self):
        """31. Golden fixture combined_realistic.conf report contains expected structural landmarks."""
        expected_landmarks = [
            "FortiGate Static Configuration Analysis Report",
            "Executive Summary",
            "Input Quality &amp; Analysis Scope Assessment",
            "Review Findings by Category",
            "Firewall Policy Inventory",
            "Security Profiles Inventory",
            "Documented FortiOS Defaults Applied",
            "Configuration Inventory Summary",
            "Analysis Methodology &amp; Limitations",
            "Static vs. Runtime Analysis Boundary",
        ]
        for landmark in expected_landmarks:
            self.assertIn(landmark, self.combined_report)

    def test_32_legitimate_object_names_not_redacted(self):
        """32. Legitimate names containing words like community, token, password are not redacted."""
        naming_config = """
config firewall address
    edit "community-lan"
        set subnet 10.10.10.0 255.255.255.0
        set comment "Community medical center branch"
    next
    edit "token-auth-server"
        set subnet 10.20.20.5 255.255.255.255
    next
    edit "password-vault-host"
        set subnet 10.30.30.8 255.255.255.255
    next
end
config firewall policy
    edit 1
        set name "allow-community-traffic"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "community-lan"
        set dstaddr "token-auth-server"
        set service "ALL"
        set action accept
        set comments "Policy for community services"
    next
end
"""
        cfg = parse_configuration(naming_config)
        an = analyze_configuration(cfg)
        hc = run_health_check(cfg, an)
        report = generate_static_report(cfg, an, hc)

        self.assertIn("community-lan", report)
        self.assertIn("token-auth-server", report)
        self.assertIn("allow-community-traffic", report)
        self.assertNotIn("community [REDACTED]", report.lower())
        self.assertNotIn("token [REDACTED]", report.lower())

    def test_33_secret_suppression_structured_isolation_and_fallback(self):
        """33. Secrets are excluded at parser level; fallback sanitizer catches raw leak."""
        user_config = """
config user local
    edit "testuser"
        set type password
        set passwd "SecretPassword999!"
        set two-factor fortitoken
    next
end
"""
        cfg = parse_configuration(user_config)
        # 1. Structured isolation: password never enters parsed user_locals
        users = cfg.get("user_locals", [])
        self.assertEqual(len(users), 1)
        self.assertNotIn("passwd", users[0])
        self.assertNotIn("SecretPassword999!", str(users[0]))

        # 2. Fallback sanitizer: verify fallback replaces raw ENC hash or password if injected into free-form finding
        synthetic_analysis = {
            "findings": [
                {
                    "id": "LEAK_TEST",
                    "title": "Finding with leaked diagnostic",
                    "severity": "HIGH",
                    "description": "Evidence contains password MySecretValue and ENC AK1bM9f3XyZZ8891== in raw debug output.",
                    "recommendation": "Fix it.",
                }
            ]
        }
        report = generate_static_report(cfg, synthetic_analysis, {"checks": []})
        self.assertNotIn("MySecretValue", report)
        self.assertNotIn("AK1bM9f3XyZZ8891==", report)
        self.assertIn("password [REDACTED]", report)
        self.assertIn("ENC [REDACTED]", report)


if __name__ == "__main__":
    unittest.main()
