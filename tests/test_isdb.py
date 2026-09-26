"""Synthetic regression coverage for Internet Service Database awareness."""

import os
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import parse_configuration


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "isdb.conf")


class TestISDBAwareness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as handle:
            cls.config = parse_configuration(handle.read())
        cls.analysis = analyze_configuration(cls.config)

    def assessment(self, policy_id):
        return next(
            item
            for item in self.analysis["policy_assessments"]
            if item["policy_id"] == policy_id
        )

    def test_01_traditional_policy_shape_is_unchanged(self):
        parsed = parse_configuration(
            'config firewall policy\nedit 1\nset srcaddr "all"\n'
            'set dstaddr "all"\nset service "ALL"\nnext\nend'
        )["policies"][0]
        self.assertEqual(parsed["srcaddr"], ["all"])
        self.assertEqual(parsed["service"], ["ALL"])

    def test_02_destination_id_is_list_valued(self):
        policy = self.config["policies"][0]
        self.assertEqual(policy["internet-service-id"], ["65646"])

    def test_03_predefined_name_metadata_is_parsed(self):
        item = self.config["internet_service_names"][0]
        self.assertEqual(item["name"], "Google-Gmail")
        self.assertEqual(item["internet-service-id"], "65646")

    def test_04_predefined_group_members_are_parsed(self):
        group = self.config["internet_service_groups"][0]
        self.assertEqual(group["member"], ["Google-Gmail", "Microsoft-Office365"])

    def test_05_custom_object_safe_metadata_is_parsed(self):
        custom = self.config["internet_service_customs"][0]
        self.assertEqual(custom["comment"], "Local application endpoints")
        self.assertNotIn("password", custom)
        self.assertNotIn("protocol", custom)

    def test_06_custom_group_members_are_parsed(self):
        group = self.config["internet_service_custom_groups"][0]
        self.assertEqual(group["member"], ["Local-SaaS"])
        self.assertNotIn("private-key", group)

    def test_07_destination_id_known_in_backup(self):
        selector = self.assessment(1)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "known_in_backup")
        self.assertTrue(selector["resolved"])

    def test_08_destination_name_known_in_backup(self):
        selector = self.assessment(2)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["type"], "name")
        self.assertEqual(selector["resolution"], "known_in_backup")

    def test_09_destination_group_resolves_locally(self):
        selector = self.assessment(3)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "local")
        self.assertEqual(selector["object"]["name"], "Cloud-Apps")

    def test_10_source_isdb_replaces_traditional_source(self):
        assessment = self.assessment(4)
        self.assertTrue(assessment["internet_service_matching"]["source"]["enabled"])
        self.assertEqual(assessment["resolved_sources"], [])

    def test_11_custom_object_resolves_locally(self):
        selector = self.assessment(5)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "local")

    def test_12_custom_group_resolves_locally(self):
        selector = self.assessment(6)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "local")

    def test_13_predefined_fortiguard_selector_is_valid_offline(self):
        selector = self.assessment(7)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "predefined_offline")
        self.assertIsNone(selector["resolved"])

    def test_14_lan_wan_isdb_policy_infers_internet_access(self):
        assessment = self.assessment(1)
        self.assertEqual(assessment["purpose"], "Internet Access")
        self.assertIn("Internet Service destination", assessment["assessment"])

    def test_15_sdwan_isdb_policy_infers_internet_access(self):
        assessment = self.assessment(6)
        self.assertEqual(assessment["flow_type"], "OUTBOUND_INTERNET")
        self.assertEqual(assessment["purpose"], "Internet Access")

    def test_16_security_profile_remains_attached(self):
        profile = self.assessment(7)["security_profiles"]["antivirus"]
        self.assertTrue(profile["attached"])
        self.assertTrue(profile["resolved"])

    def test_17_missing_profiles_still_generate_outbound_review(self):
        checks = run_health_check(self.config, self.analysis)["checks"]
        self.assertTrue(any(c["title"] == "No Security Profiles Detected on Outbound Internet Policy" for c in checks))

    def test_18_missing_traditional_destination_and_service_are_not_unresolved(self):
        checks = run_health_check(self.config, self.analysis)["checks"]
        integrity = [c for c in checks if c["category"] == "Configuration Integrity"]
        evidence = " ".join(item for check in integrity for item in check["evidence"])
        self.assertNotIn("Policy 1", evidence)
        self.assertNotIn("unresolved service", evidence)

    def test_19_unknown_local_custom_reference_is_conservative(self):
        text = '''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set internet-service enable
set internet-service-custom "Missing-Custom"
set action accept
next
end'''
        config = parse_configuration(text)
        analysis = analyze_configuration(config)
        selector = analysis["policy_assessments"][0]["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "unresolved")
        checks = run_health_check(config, analysis)["checks"]
        self.assertTrue(any("Missing-Custom" in " ".join(c["evidence"]) for c in checks))

    def test_20_unknown_predefined_name_is_not_reported_broken(self):
        text = '''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set internet-service enable
set internet-service-name "Valid-External-Name"
set action accept
next
end'''
        config = parse_configuration(text)
        analysis = analyze_configuration(config)
        selector = analysis["policy_assessments"][0]["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "predefined_offline")
        checks = run_health_check(config, analysis)["checks"]
        self.assertFalse(any("Valid-External-Name" in " ".join(c["evidence"]) for c in checks))

    def test_21_negated_isdb_skips_relationship_analysis(self):
        config = parse_configuration('''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set internet-service enable
set internet-service-name "A"
set internet-service-negate enable
set action accept
next
edit 2
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set internet-service enable
set internet-service-name "A"
set internet-service-negate enable
set action accept
next
end''')
        titles = {f["title"] for f in analyze_configuration(config)["findings"]}
        self.assertNotIn("Duplicate Firewall Policy", titles)
        self.assertNotIn("Fully Shadowed Firewall Policy", titles)

    def test_22_traditional_and_isdb_policies_do_not_shadow(self):
        config = parse_configuration('''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action accept
next
edit 2
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set internet-service enable
set internet-service-id 1
set action accept
next
end''')
        titles = {f["title"] for f in analyze_configuration(config)["findings"]}
        self.assertFalse(titles & {"Duplicate Firewall Policy", "Fully Shadowed Firewall Policy"})

    def test_23_multi_vdom_custom_resolution_is_isolated(self):
        config = parse_configuration('''config vdom
edit "A"
config firewall internet-service-custom
edit "Local"
set comment "A object"
next
end
config firewall policy
edit 1
set internet-service enable
set internet-service-custom "Local"
next
end
next
edit "B"
config firewall policy
edit 1
set internet-service enable
set internet-service-custom "Local"
next
end
next
end''')
        analysis = analyze_configuration(config)["policy_assessments"]
        first = analysis[0]["internet_service_matching"]["destination"]["selectors"][0]
        second = analysis[1]["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(first["resolution"], "local")
        self.assertEqual(second["resolution"], "unresolved")

    def test_24_malformed_isdb_line_does_not_abort_parsing(self):
        config = parse_configuration('''config firewall policy
edit 1
set internet-service-name "unterminated
set internet-service enable
next
end''')
        self.assertEqual(len(config["policies"]), 1)
        self.assertEqual(config["policies"][0]["internet-service"], "enable")

    def test_25_destination_isdb_suppresses_broad_service_finding(self):
        titles = {
            f["title"]
            for f in self.analysis["findings"]
            if f.get("policy_id") == 1
        }
        self.assertNotIn("Broad Inbound Service Access", titles)


if __name__ == "__main__":
    unittest.main()
