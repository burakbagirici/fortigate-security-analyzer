"""Unit test suite for FortiGate Input Quality & FortiOS Version Detection."""

from __future__ import annotations

import json
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import (
    assess_input_quality,
    detect_section_presence,
    parse_configuration,
    parse_fortios_version,
)
from runtime_health import analyze_runtime_health, parse_runtime_output


class TestInputQuality(unittest.TestCase):
    """Test suite covering input classification, metadata parsing, scope assessment, and user clarifications."""

    def test_01_empty_input(self):
        assessment = assess_input_quality("")
        self.assertEqual(assessment["classification"], "EMPTY_INPUT")
        self.assertFalse(assessment["fortigate_detected"])
        self.assertEqual(assessment["fortios"]["version"], "unknown")

    def test_02_whitespace_only_input(self):
        assessment = assess_input_quality("   \n\t  \n")
        self.assertEqual(assessment["classification"], "EMPTY_INPUT")
        self.assertFalse(assessment["fortigate_detected"])

    def test_03_random_non_fortigate_text(self):
        assessment = assess_input_quality("This is a random text file describing networking concepts.")
        self.assertEqual(assessment["classification"], "UNRECOGNIZED_INPUT")
        self.assertFalse(assessment["fortigate_detected"])

    def test_04_text_containing_only_fortigate(self):
        assessment = assess_input_quality("FortiGate")
        self.assertEqual(assessment["classification"], "UNRECOGNIZED_INPUT")
        self.assertFalse(assessment["fortigate_detected"])

    def test_05_valid_partial_firewall_policy(self):
        text = """config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end"""
        assessment = assess_input_quality(text)
        self.assertEqual(assessment["classification"], "PARTIAL_CONFIGURATION")
        self.assertTrue(assessment["fortigate_detected"])
        self.assertIn("firewall_policies", assessment["recognized_sections"])

    def test_06_valid_partial_system_interface_config(self):
        text = """config system interface
    edit "port1"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping https
    next
end"""
        assessment = assess_input_quality(text)
        self.assertEqual(assessment["classification"], "PARTIAL_CONFIGURATION")
        self.assertTrue(assessment["fortigate_detected"])
        self.assertIn("interfaces", assessment["recognized_sections"])

    def test_07_headerless_structurally_valid_partial_config(self):
        text = """config system interface
    edit "port1"
    next
end
config firewall address
    edit "NET1"
    next
end"""
        assessment = assess_input_quality(text)
        self.assertIn(
            assessment["classification"],
            {"PARTIAL_CONFIGURATION", "FORTIGATE_CONFIGURATION_UNKNOWN_COMPLETENESS"},
        )
        self.assertTrue(assessment["fortigate_detected"])
        self.assertEqual(assessment["fortios"]["version"], "unknown")

    def test_08_likely_full_backup_with_version_header(self):
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015:opmode=0:vdom=0:user=admin
config system global
    set hostname "FGT100F"
end
config system admin
    edit "admin"
    next
end
config system interface
    edit "port1"
    next
end
config firewall policy
    edit 1
    next
end"""
        assessment = assess_input_quality(text)
        self.assertEqual(assessment["classification"], "LIKELY_FULL_BACKUP")
        self.assertTrue(assessment["fortigate_detected"])
        self.assertEqual(assessment["fortios"]["version"], "7.2.11")

    def test_09_fortios_6x_header(self):
        text = "#config-version=FGT60E-6.2.3-FW-build1066-200115:opmode=0:vdom=0:user=admin"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "6.2.3")
        self.assertEqual(meta["major"], 6)
        self.assertEqual(meta["minor"], 2)
        self.assertEqual(meta["patch"], 3)
        self.assertEqual(meta["build"], 1066)
        self.assertEqual(meta["platform"], "FGT60E")

    def test_10_fortios_70_header(self):
        text = "#config-version=FGT_60E-7.0.5-FW-build0304-220412"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "7.0.5")
        self.assertEqual(meta["major"], 7)
        self.assertEqual(meta["minor"], 0)
        self.assertEqual(meta["patch"], 5)
        self.assertEqual(meta["build"], 304)
        self.assertEqual(meta["platform"], "FGT_60E")

    def test_11_fortios_72_header(self):
        text = "#config-version=FG100F-7.2.11-FW-build1740-241015"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "7.2.11")
        self.assertEqual(meta["major"], 7)
        self.assertEqual(meta["minor"], 2)
        self.assertEqual(meta["patch"], 11)
        self.assertEqual(meta["build"], 1740)
        self.assertEqual(meta["platform"], "FG100F")

    def test_12_fortios_74_header(self):
        text = "#config-version=FortiGate-600E-7.4.1-FW-build2464-230913"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "7.4.1")
        self.assertEqual(meta["major"], 7)
        self.assertEqual(meta["minor"], 4)
        self.assertEqual(meta["patch"], 1)
        self.assertEqual(meta["build"], 2464)
        self.assertEqual(meta["platform"], "FortiGate-600E")

    def test_13_fortios_76_header(self):
        text = "#config-version=FGT-7.6.0-build0100"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "7.6.0")
        self.assertEqual(meta["major"], 7)
        self.assertEqual(meta["minor"], 6)
        self.assertEqual(meta["patch"], 0)
        self.assertEqual(meta["build"], 100)

    def test_14_fortios_8x_header(self):
        text = "#config-version=v8.0.0-build0050"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "8.0.0")
        self.assertEqual(meta["major"], 8)
        self.assertEqual(meta["minor"], 0)
        self.assertEqual(meta["patch"], 0)
        self.assertEqual(meta["build"], 50)

    def test_15_version_header_with_platform_prefix(self):
        text = "#config-version=FGT100F-7.2.4-build1000"
        meta = parse_fortios_version(text)
        self.assertEqual(meta["platform"], "FGT100F")

    def test_16_version_header_with_build(self):
        text = "#config-version=7.2.4-build1234"
        meta = parse_fortios_version(text)
        self.assertEqual(meta["build"], 1234)

    def test_17_version_header_without_build(self):
        text = "#config-version=FGT60E-7.2.4"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "7.2.4")
        self.assertIsNone(meta["build"])

    def test_18_malformed_version_header(self):
        text = "#config-version=invalid_garbage_header_without_numbers"
        meta = parse_fortios_version(text)
        self.assertFalse(meta["detected"])
        self.assertEqual(meta["version"], "unknown")
        self.assertEqual(meta["source"], "malformed_header")

    def test_19_unknown_future_version_does_not_crash(self):
        text = "#config-version=FGT-9.1.2-build9999"
        meta = parse_fortios_version(text)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["version"], "9.1.2")
        self.assertEqual(meta["major"], 9)

    def test_20_truncated_config_section(self):
        text = """config system interface
    edit "port1"
        set ip "10.0.0.1"""
        assessment = assess_input_quality(text)
        self.assertTrue(len(assessment["structural_warnings"]) > 0)
        self.assertIn("Truncated or unclosed", assessment["structural_warnings"][0])

    def test_21_completed_next_object_missing_final_end(self):
        text = """config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["policies"]), 1)
        assessment = parsed["input_assessment"]
        self.assertTrue(len(assessment["structural_warnings"]) > 0)

    def test_22_unterminated_edit(self):
        text = """config system interface
    edit "port1"
        set mode static"""
        assessment = assess_input_quality(text)
        self.assertTrue(len(assessment["structural_warnings"]) > 0)

    def test_23_truncated_quoted_set_value(self):
        text = 'set ip "192.168.'
        assessment = assess_input_quality(text)
        self.assertTrue(len(assessment["structural_warnings"]) > 0)

    def test_24_multiple_recognized_sections(self):
        text = """config system interface
end
config firewall policy
end
config system global
end"""
        assessment = assess_input_quality(text)
        self.assertIn("interfaces", assessment["recognized_sections"])
        self.assertIn("firewall_policies", assessment["recognized_sections"])
        self.assertIn("system_global", assessment["recognized_sections"])

    def test_25_firewall_policies_present_interfaces_missing(self):
        text = "config firewall policy\nend"
        presence = detect_section_presence(text)
        self.assertTrue(presence["firewall_policies"])
        self.assertFalse(presence["interfaces"])

    def test_26_interfaces_present_firewall_policies_missing(self):
        text = "config system interface\nend"
        presence = detect_section_presence(text)
        self.assertTrue(presence["interfaces"])
        self.assertFalse(presence["firewall_policies"])

    def test_27_admin_section_absent(self):
        text = "config firewall policy\nend"
        assessment = assess_input_quality(text)
        self.assertEqual(
            assessment["analysis_scope"]["administrators"]["status"],
            "UNAVAILABLE_NOT_SUPPLIED",
        )

    def test_28_ipsec_section_absent(self):
        text = "config firewall policy\nend"
        assessment = assess_input_quality(text)
        self.assertEqual(
            assessment["analysis_scope"]["ipsec_vpn"]["status"],
            "UNAVAILABLE_NOT_SUPPLIED",
        )

    def test_29_security_profiles_absent(self):
        text = "config firewall policy\nend"
        assessment = assess_input_quality(text)
        self.assertEqual(
            assessment["analysis_scope"]["security_profiles"]["status"],
            "UNAVAILABLE_NOT_SUPPLIED",
        )

    def test_30_valid_config_no_ipsec_not_malformed(self):
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015
config system global
end
config system admin
end
config system interface
end
config firewall policy
end"""
        assessment = assess_input_quality(text)
        self.assertNotEqual(assessment["classification"], "MALFORMED_OR_TRUNCATED_CONFIGURATION")
        self.assertEqual(assessment["classification"], "LIKELY_FULL_BACKUP")

    def test_31_valid_config_no_sdwan_not_malformed(self):
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015
config system global
end
config system admin
end
config system interface
end
config firewall policy
end"""
        assessment = assess_input_quality(text)
        self.assertNotEqual(assessment["classification"], "MALFORMED_OR_TRUNCATED_CONFIGURATION")
        self.assertEqual(assessment["classification"], "LIKELY_FULL_BACKUP")

    def test_32_partial_input_does_not_turn_missing_setting_into_disabled(self):
        text = """config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end"""
        parsed = parse_configuration(text)
        health = run_health_check(parsed)
        # Should not generate false-positive disabled admin setting findings when admin block is missing
        admin_findings = [
            c for c in health["checks"] if c["category"] == "Administrative Security"
        ]
        self.assertEqual(admin_findings, [])

    def test_33_partial_input_unresolved_reference_wording_cautious(self):
        text = """config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "CUSTOM_ADDR"
        set dstaddr "all"
        set action accept
    next
end"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        serialized = json.dumps(analysis)
        self.assertNotIn("confirmed broken configuration", serialized.lower())

    def test_34_full_looking_config_unresolved_reference_identifiable(self):
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015
config system global
end
config system admin
end
config system interface
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "MISSING_OBJECT"
        set dstaddr "all"
        set action accept
    next
end"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        policy_asm = analysis["policy_assessments"][0]
        self.assertEqual(policy_asm["resolved_sources"][0]["name"], "MISSING_OBJECT")
        self.assertEqual(policy_asm["resolved_sources"][0]["type"], "unknown")

    def test_35_no_secret_leakage_in_metadata_warnings(self):
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015:user=admin
config system admin
    edit "admin"
        set password ENC secret_hash_value_12345
    next
end"""
        parsed = parse_configuration(text)
        meta_json = json.dumps(parsed["input_assessment"])
        self.assertNotIn("secret_hash_value_12345", meta_json)

    def test_36_existing_analysis_executes_on_partial_input(self):
        text = """config firewall policy
    edit 10
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)
        self.assertEqual(analysis["policy_assessments"][0]["policy_id"], 10)

    def test_37_runtime_analysis_remains_unaffected(self):
        runtime_text = "diagnose sys top 1 10"
        data = parse_runtime_output(runtime_text)
        result = analyze_runtime_health(data)
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_38_section_presence_vs_parsed_object_count(self):
        """User Clarification 1: Distinguish SECTION PRESENCE from PARSED OBJECT COUNT."""
        text = """config firewall local-in-policy
end"""
        parsed = parse_configuration(text)
        assessment = parsed["input_assessment"]
        # Section presence is True because header 'config firewall local-in-policy' was present
        self.assertTrue(assessment["section_presence"]["local_in_policies"])
        # Parsed object count is 0 because no edit blocks exist
        self.assertEqual(assessment["object_counts"]["local_in_policies"], 0)

    def test_39_likely_full_backup_optional_feature_absence(self):
        """User Clarification 2: Missing optional feature in full backup is UNOBSERVED_IN_INPUT."""
        text = """#config-version=FG100F-7.2.11-FW-build1740-241015:opmode=0:vdom=0:user=admin
config system global
end
config system admin
end
config system interface
end
config firewall policy
end"""
        assessment = assess_input_quality(text)
        self.assertEqual(assessment["classification"], "LIKELY_FULL_BACKUP")
        # Missing IPsec should be UNOBSERVED_IN_INPUT, not UNAVAILABLE_NOT_SUPPLIED
        self.assertEqual(
            assessment["analysis_scope"]["ipsec_vpn"]["status"],
            "UNOBSERVED_IN_INPUT",
        )

    def test_40_input_assessment_separate_from_security_findings(self):
        """User Clarification 3: Input assessment metadata is not overload as security findings."""
        text = """config firewall policy
    edit 1
    next
end"""
        parsed = parse_configuration(text)
        health = run_health_check(parsed)
        # Input assessment is present as dedicated dictionary key
        self.assertIn("input_assessment", health)
        # Missing sections do not populate security findings list checks
        for check in health["checks"]:
            self.assertNotIn("partial input detected", check.get("title", "").lower())
            self.assertNotIn("unknown fortios version", check.get("title", "").lower())


if __name__ == "__main__":
    unittest.main()
