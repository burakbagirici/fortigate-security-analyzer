"""Unit tests for FortiOS Version-Aware Defaults Engine."""

import unittest
from fortios_defaults import (
    VERIFIED_RULES,
    RULE_INDEX,
    DefaultRule,
    get_rule,
    infer_field_default,
)
from parser import parse_configuration
from health_check import run_health_check
from analyzer import analyze_configuration


class TestFortiOSDefaultsEngine(unittest.TestCase):
    def setUp(self):
        self.base_full_header = (
            "#config-version=FG100F-7.2.11-FW-build1740-241015:opmode=0:vdom=0:user=admin\n"
        )

    def test_registered_rules_have_explicit_branches_and_citations(self):
        """Ensure all registered rules explicitly define branches and doc citations."""
        self.assertGreaterEqual(len(VERIFIED_RULES), 5)
        for rule in VERIFIED_RULES:
            self.assertIsInstance(rule, DefaultRule)
            self.assertTrue(rule.rule_id)
            self.assertTrue(rule.section_key)
            self.assertTrue(rule.field_name)
            self.assertIsNotNone(rule.default_value)
            # Ensure branches are explicit tuples of (major, minor)
            self.assertIsInstance(rule.verified_branches, frozenset)
            for branch in rule.verified_branches:
                self.assertIsInstance(branch, tuple)
                self.assertEqual(len(branch), 2)
                # Each branch must have an explicit doc citation
                self.assertIn(branch, rule.branch_docs)
                self.assertIn("CLI Reference", rule.branch_docs[branch])

    def test_explicit_value_always_takes_precedence(self):
        """Rule 1: Explicit value always wins, returning EXPLICIT_VALUE status."""
        config_text = (
            self.base_full_header
            + """
config system global
    set admintimeout 30
    set admin-sport 8443
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        )
        parsed = parse_configuration(config_text)
        result = infer_field_default(
            parsed, "system_global", "admintimeout", parsed["system_global"].get("admintimeout")
        )
        self.assertFalse(result["applicable"])
        self.assertEqual(result["status"], "EXPLICIT_VALUE")
        self.assertEqual(result["effective_value"], "30")
        self.assertEqual(result["explicit_value"], "30")
        self.assertEqual(result["value_source"], "EXPLICIT_CONFIG")
        self.assertTrue(result["explicitly_configured"])
        self.assertEqual(result["rule_id"], "system_global.admintimeout")

    def test_known_version_verified_rule_likely_full_backup_applies_default(self):
        """Rule 2: Known version + verified rule + LIKELY_FULL_BACKUP applies documented default."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-01"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        )
        parsed = parse_configuration(config_text)
        # Raw parsed config fact is preserved as None
        self.assertIsNone(parsed["ntp"].get("type"))

        # Infer default for ntp.type
        ntp_res = infer_field_default(parsed, "ntp", "type", parsed["ntp"].get("type"))
        self.assertTrue(ntp_res["applicable"])
        self.assertEqual(ntp_res["status"], "DOCUMENTED_DEFAULT_APPLIED")
        self.assertEqual(ntp_res["effective_value"], "fortiguard")
        self.assertEqual(ntp_res["value_source"], "DOCUMENTED_DEFAULT")
        self.assertEqual(ntp_res["rule_id"], "system_ntp.type")
        self.assertEqual(ntp_res["fortios_version"], "7.2.11")
        self.assertIn("FortiOS 7.2 CLI Reference", ntp_res["documentation"])
        self.assertFalse(ntp_res["explicitly_configured"])

        # Infer default for system_global.admintimeout
        timeout_res = infer_field_default(
            parsed, "system_global", "admintimeout", parsed["system_global"].get("admintimeout")
        )
        self.assertTrue(timeout_res["applicable"])
        self.assertEqual(timeout_res["status"], "DOCUMENTED_DEFAULT_APPLIED")
        self.assertEqual(timeout_res["effective_value"], "5")
        self.assertEqual(timeout_res["value_source"], "DOCUMENTED_DEFAULT")

        # Infer default for system_global.admin-sport
        sport_res = infer_field_default(
            parsed, "system_global", "admin-sport", parsed["system_global"].get("admin-sport")
        )
        self.assertTrue(sport_res["applicable"])
        self.assertEqual(sport_res["effective_value"], "443")

        # Infer default for system_global.admin-port
        port_res = infer_field_default(
            parsed, "system_global", "admin-port", parsed["system_global"].get("admin-port")
        )
        self.assertTrue(port_res["applicable"])
        self.assertEqual(port_res["effective_value"], "80")

        # Infer default for system_global.admin-ssh-port
        ssh_res = infer_field_default(
            parsed, "system_global", "admin-ssh-port", parsed["system_global"].get("admin-ssh-port")
        )
        self.assertTrue(ssh_res["applicable"])
        self.assertEqual(ssh_res["effective_value"], "22")

    def test_unknown_version_does_not_infer_defaults(self):
        """Rule 3: Unknown FortiOS version results in VERSION_UNKNOWN."""
        config_text = """
config system global
    set hostname "FGT-UNKNOWN"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        parsed = parse_configuration(config_text)
        result = infer_field_default(parsed, "ntp", "type", parsed["ntp"].get("type"))
        self.assertFalse(result["applicable"])
        # In partial or unknown version, scope is insufficient or version unknown
        self.assertIn(result["status"], ("VERSION_UNKNOWN", "INPUT_SCOPE_INSUFFICIENT"))
        self.assertIsNone(result["effective_value"])

    def test_partial_configuration_does_not_infer_defaults_from_absence(self):
        """Rule 4: Partial configuration snippet does not assume defaults for absent fields."""
        partial_text = """
config system ntp
    set ntpsync enable
end
"""
        parsed = parse_configuration(partial_text)
        self.assertEqual(parsed["input_assessment"]["classification"], "PARTIAL_CONFIGURATION")
        result = infer_field_default(parsed, "ntp", "type", parsed["ntp"].get("type"))
        self.assertFalse(result["applicable"])
        self.assertEqual(result["status"], "INPUT_SCOPE_INSUFFICIENT")
        self.assertIsNone(result["effective_value"])
        self.assertIn("PARTIAL_CONFIGURATION", result["reason"])

    def test_missing_section_results_in_section_not_supplied(self):
        """Rule 5: Entire configuration section missing results in SECTION_NOT_SUPPLIED."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-01"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        )
        parsed = parse_configuration(config_text)
        # config system ntp is completely absent
        result = infer_field_default(parsed, "ntp", "type", None)
        self.assertFalse(result["applicable"])
        self.assertEqual(result["status"], "SECTION_NOT_SUPPLIED")
        self.assertIsNone(result["effective_value"])
        self.assertIn("was not observed", result["reason"])

    def test_unsupported_version_branch_does_not_infer_default(self):
        """Rule 6: Unverified FortiOS branch results in UNSUPPORTED_VERSION."""
        header_7_6 = (
            "#config-version=FG100F-7.6.0-FW-build0000-241015:opmode=0:vdom=0:user=admin\n"
        )
        config_text = (
            header_7_6
            + """
config system global
    set hostname "FGT-76"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        )
        parsed = parse_configuration(config_text)
        result = infer_field_default(parsed, "ntp", "type", parsed["ntp"].get("type"))
        self.assertFalse(result["applicable"])
        self.assertEqual(result["status"], "UNSUPPORTED_VERSION")
        self.assertIsNone(result["effective_value"])
        self.assertIn("7.6 has not been individually verified", result["reason"])

    def test_verified_branches_coverage(self):
        """Ensure all explicitly verified branches (7.0, 7.2, 7.4) apply defaults."""
        for version_str, expected_branch in [
            ("7.0.14-FW-build0590", (7, 0)),
            ("7.2.8-FW-build1639", (7, 2)),
            ("7.4.4-FW-build2662", (7, 4)),
        ]:
            header = f"#config-version=FG100F-{version_str}-241015:opmode=0:vdom=0:user=admin\n"
            config_text = (
                header
                + """
config system global
    set hostname "FGT-TEST"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
            )
            parsed = parse_configuration(config_text)
            res = infer_field_default(parsed, "ntp", "type", None)
            self.assertTrue(res["applicable"])
            self.assertEqual(res["status"], "DOCUMENTED_DEFAULT_APPLIED")
            self.assertEqual(res["effective_value"], "fortiguard")
            self.assertIn(f"FortiOS {expected_branch[0]}.{expected_branch[1]} CLI Reference", res["documentation"])

    def test_unregistered_rule_returns_default_not_applicable(self):
        """Unregistered rule queries return DEFAULT_NOT_APPLICABLE."""
        parsed = parse_configuration(self.base_full_header + "config system global\nend\n")
        result = infer_field_default(parsed, "firewall_policy", "schedule", None)
        self.assertFalse(result["applicable"])
        self.assertEqual(result["status"], "DEFAULT_NOT_APPLICABLE")
        self.assertIsNone(result["effective_value"])

    def test_health_check_surfaces_ntp_documented_default(self):
        """Health check surfaces documented default finding when type is omitted in full backup."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-NTP"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        )
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # Scenario D: Documented default applies -> NO security finding created solely because default exists
        default_ntp_checks = [
            c for c in health["checks"]
            if "NTP" in c["title"]
        ]
        self.assertEqual(len(default_ntp_checks), 0)

        # Documented default is exposed in structured interpretation metadata
        applied_defaults = health.get("documented_defaults", [])
        ntp_default = next((d for d in applied_defaults if d["rule_id"] == "system_ntp.type"), None)
        self.assertIsNotNone(ntp_default)
        self.assertEqual(ntp_default["effective_value"], "fortiguard")
        self.assertEqual(ntp_default["value_source"], "DOCUMENTED_DEFAULT")
        self.assertIn("FortiOS 7.2 CLI Reference", ntp_default["documentation"])
        self.assertFalse(ntp_default["explicitly_configured"])

    def test_scenario_a_partial_firewall_policy_only_config(self):
        """Scenario A: Partial firewall-policy-only config -> no NTP finding, NTP scope unavailable."""
        partial_policy_text = """
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set action accept
    next
end
"""
        parsed = parse_configuration(partial_policy_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # No NTP security finding
        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 0)

        # NTP scope marked unavailable
        ntp_scope = parsed["input_assessment"]["analysis_scope"]["ntp"]
        self.assertEqual(ntp_scope["status"], "UNAVAILABLE_NOT_SUPPLIED")

    def test_scenario_b_full_looking_config_with_ntp_section_absent(self):
        """Scenario B: Full config with NTP section absent -> no NTP finding, scope UNOBSERVED_IN_INPUT."""
        full_no_ntp = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-NO-NTP"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        )
        parsed = parse_configuration(full_no_ntp)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # No NTP finding
        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 0)

        # Scope is UNOBSERVED_IN_INPUT
        ntp_scope = parsed["input_assessment"]["analysis_scope"]["ntp"]
        self.assertEqual(ntp_scope["status"], "UNOBSERVED_IN_INPUT")

    def test_scenario_c_partial_config_with_ntp_section_absent(self):
        """Scenario C: Partial config with NTP section absent -> no NTP finding."""
        partial_text = """
config system interface
    edit "port1"
        set role wan
    next
end
"""
        parsed = parse_configuration(partial_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 0)

    def test_scenario_e_ntp_section_supplied_with_explicit_type(self):
        """Scenario E: NTP section supplied + explicit type custom with server -> explicit value wins."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-EXPLICIT-NTP"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.0.0.123"
        next
    end
end
"""
        )
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # No default inference for ntp.type
        applied_defaults = health.get("documented_defaults", [])
        self.assertFalse(any(d["rule_id"] == "system_ntp.type" for d in applied_defaults))

        # No NTP findings (custom server properly configured)
        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 0)

    def test_scenario_f_genuine_ntp_ambiguity_with_sufficient_source_context(self):
        """Scenario F: Genuine NTP ambiguity (full backup, type custom, no servers) -> review finding."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-AMBIGUOUS-NTP"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
    set type custom
end
"""
        )
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # Cautious review finding produced because type is explicitly custom, but no servers exist
        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 1)
        self.assertEqual(ntp_checks[0]["title"], "NTP Server Configuration Could Not Be Confirmed")
        self.assertEqual(ntp_checks[0]["severity"], "LOW")
        evidence = " ".join(ntp_checks[0]["evidence"])
        self.assertIn("NTP type: custom", evidence)
        self.assertIn("Configured NTP servers: none", evidence)

    def test_scenario_g_unknown_fortios_version_alone_does_not_create_finding(self):
        """Scenario G: Unknown FortiOS version alone must not create an NTP finding."""
        no_header_config = """
config system global
    set hostname "FGT-NO-VERSION"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        parsed = parse_configuration(no_header_config)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # Must NOT create an NTP finding merely because FortiOS version is unknown
        ntp_checks = [c for c in health["checks"] if "NTP" in c.get("title", "")]
        self.assertEqual(len(ntp_checks), 0)

    def test_negative_assertions(self):
        """Verify negative assertions and non-claims."""
        config_text = (
            self.base_full_header
            + """
config system global
    set hostname "FGT-NEG"
end
config system interface
    edit "port1"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config system ntp
    set ntpsync enable
end
"""
        )
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        import json
        serialized = json.dumps({"config": parsed, "analysis": analysis, "health": health}).lower()

        # 1. No live reachability or session claims
        self.assertNotIn("live session", serialized)
        self.assertNotIn("confirmed reachable", serialized)
        self.assertNotIn("tunnel is up", serialized)
        self.assertNotIn("tunnel is down", serialized)

        # 2. No CVE lookup claims
        self.assertNotIn("cve-", serialized)
        self.assertNotIn("vulnerability database", serialized)

        # 3. No live FortiGuard queries
        self.assertNotIn("live fortiguard query", serialized)


if __name__ == "__main__":
    unittest.main()
