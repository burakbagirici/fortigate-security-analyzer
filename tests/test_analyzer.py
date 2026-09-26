"""Unit tests for analyzer.py baseline behavior."""

import os
import unittest
from parser import parse_configuration
from analyzer import _schedule_compatible, analyze_configuration


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> str:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.basic_config = parse_configuration(read_fixture("basic.conf"))
        self.basic_analysis = analyze_configuration(self.basic_config)
        self.shadow_config = parse_configuration(read_fixture("shadowing.conf"))
        self.shadow_analysis = analyze_configuration(self.shadow_config)
        self.profile_config = parse_configuration(read_fixture("profiles.conf"))
        self.profile_analysis = analyze_configuration(self.profile_config)

    def test_lan_to_wan_internet_access_purpose(self):
        assessments = self.basic_analysis["policy_assessments"]
        p10 = next(a for a in assessments if a["policy_id"] == 10)
        self.assertEqual(p10["purpose"], "Internet Access")
        self.assertEqual(p10["flow_type"], "OUTBOUND_INTERNET")

    def test_public_https_vip_publishing_purpose(self):
        assessments = self.basic_analysis["policy_assessments"]
        p20 = next(a for a in assessments if a["policy_id"] == 20)
        self.assertEqual(p20["purpose"], "Public Server Publishing")
        self.assertEqual(p20["flow_type"], "INBOUND_PUBLIC")

    def test_wan_to_lan_unrestricted_rdp_finding(self):
        findings = self.basic_analysis["findings"]
        p30_findings = [f for f in findings if f.get("policy_id") == 30]
        titles = {f["title"] for f in p30_findings}
        self.assertIn("Internet-Exposed Administrative Access", titles)
        finding = next(f for f in p30_findings if f["title"] == "Internet-Exposed Administrative Access")
        self.assertEqual(finding["severity"], "HIGH")

    def test_broad_internal_rule_finding(self):
        findings = self.basic_analysis["findings"]
        p40_findings = [f for f in findings if f.get("policy_id") == 40]
        titles = {f["title"] for f in p40_findings}
        self.assertIn("Broad Internal Network Access", titles)
        finding = next(f for f in p40_findings if f["title"] == "Broad Internal Network Access")
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_disabled_policy_behavior(self):
        assessments = self.basic_analysis["policy_assessments"]
        p50 = next(a for a in assessments if a["policy_id"] == 50)
        self.assertEqual(p50["purpose"], "Disabled Policy")
        findings = self.basic_analysis["findings"]
        p50_findings = [f for f in findings if f.get("policy_id") == 50]
        self.assertEqual(len(p50_findings), 1)
        self.assertEqual(p50_findings[0]["title"], "Disabled Policy")
        self.assertEqual(p50_findings[0]["severity"], "LOW")

    def test_security_profile_inventory_mapping(self):
        assessments = self.profile_analysis["policy_assessments"]
        p1 = next(a for a in assessments if a["policy_id"] == 1)
        profiles = p1["security_profiles"]
        self.assertTrue(profiles["ips"]["attached"])
        self.assertTrue(profiles["ips"]["resolved"])
        self.assertEqual(profiles["ips"]["source"], "custom")

    def test_builtin_ssl_profile_recognition(self):
        assessments = self.profile_analysis["policy_assessments"]
        p1 = next(a for a in assessments if a["policy_id"] == 1)
        profiles = p1["security_profiles"]
        self.assertTrue(profiles["ssl_inspection"]["attached"])
        self.assertTrue(profiles["ssl_inspection"]["resolved"])
        self.assertEqual(profiles["ssl_inspection"]["source"], "built-in")
        self.assertEqual(profiles["ssl_inspection"]["name"], "deep-inspection")

    def test_unresolved_custom_security_profile_behavior(self):
        assessments = self.profile_analysis["policy_assessments"]
        p2 = next(a for a in assessments if a["policy_id"] == 2)
        profiles = p2["security_profiles"]
        self.assertTrue(profiles["antivirus"]["attached"])
        self.assertFalse(profiles["antivirus"]["resolved"])
        self.assertIsNone(profiles["antivirus"]["source"])

    def test_exact_duplicate_policy_detection(self):
        findings = self.shadow_analysis["findings"]
        dup_findings = [f for f in findings if f.get("policy_id") == 102 and f.get("title") == "Duplicate Firewall Policy"]
        self.assertEqual(len(dup_findings), 1)
        self.assertEqual(dup_findings[0]["severity"], "LOW")
        self.assertEqual(dup_findings[0]["shadowed_by_policy_id"], 101)

    def test_fully_shadowed_policy_detection(self):
        findings = self.shadow_analysis["findings"]
        shadow_findings = [f for f in findings if f.get("policy_id") == 103 and f.get("title") == "Fully Shadowed Firewall Policy"]
        self.assertEqual(len(shadow_findings), 1)
        self.assertEqual(shadow_findings[0]["severity"], "MEDIUM")
        self.assertEqual(shadow_findings[0]["shadowed_by_policy_id"], 101)

    def test_conflicting_shadowing_detection(self):
        findings = self.shadow_analysis["findings"]
        conflict_findings = [f for f in findings if f.get("policy_id") == 104 and f.get("title") == "Conflicting Policy Shadowing"]
        self.assertEqual(len(conflict_findings), 1)
        self.assertEqual(conflict_findings[0]["severity"], "HIGH")
        self.assertEqual(conflict_findings[0]["shadowed_by_policy_id"], 101)

    def test_policy_order_uses_sequence_index_not_numeric_id(self):
        # In shadowing.conf, policy 101 (sequence_index 0) shadows policy 103 (sequence_index 2).
        # Even though 101 < 103 numerically here, if order was reversed sequence_index would determine shadowing.
        findings = self.shadow_analysis["findings"]
        p103 = next(f for f in findings if f.get("policy_id") == 103 and "Shadowed" in f.get("title", ""))
        self.assertEqual(p103["earlier_sequence"], 0)
        self.assertEqual(p103["later_sequence"], 2)

    def test_slash_8_contains_slash_24(self):
        # Policy 101 has 10.0.0.0/8, Policy 103 has 10.0.1.0/24 -> 101 covers 103
        findings = self.shadow_analysis["findings"]
        p103 = [f for f in findings if f.get("policy_id") == 103 and f.get("title") == "Fully Shadowed Firewall Policy"]
        self.assertEqual(len(p103), 1)

    def test_all_contains_https(self):
        # Policy 101 service ALL, Policy 103 service HTTPS -> 101 covers 103
        findings = self.shadow_analysis["findings"]
        p103 = [f for f in findings if f.get("policy_id") == 103 and f.get("title") == "Fully Shadowed Firewall Policy"]
        self.assertEqual(len(p103), 1)

    def test_unsupported_match_conditions_cause_conservative_skip(self):
        # Policy 105 has set users "john_doe" -> skipped from shadowing checks
        findings = self.shadow_analysis["findings"]
        p105_shadowed = [f for f in findings if f.get("policy_id") == 105 and "Shadow" in f.get("title", "")]
        self.assertEqual(len(p105_shadowed), 0)

    def test_different_schedules_not_safely_comparable(self):
        # Policy 106 has schedule "work-hours", earlier policy 101 has schedule "always"
        findings = self.shadow_analysis["findings"]
        p106_shadowed = [f for f in findings if f.get("policy_id") == 106 and "Shadow" in f.get("title", "")]
        self.assertEqual(len(p106_shadowed), 0)

    def test_disabled_earlier_rule_does_not_shadow_later_rule(self):
        # Policy 108 is disabled "all -> all", Policy 109 is enabled "NET_10_0_1_0_24 -> all"
        findings = self.shadow_analysis["findings"]
        p109_shadowed = [f for f in findings if f.get("policy_id") == 109 and f.get("shadowed_by_policy_id") == 108]
        self.assertEqual(len(p109_shadowed), 0)

    def test_schedule_default_omitted_vs_explicit_always_behavior(self):
        """An omitted later schedule uses the FortiGate default ``always``."""
        findings = self.shadow_analysis["findings"]
        # Policy 107 omits schedule, while Policy 101 has schedule "always".
        p107_shadowed = [
            finding
            for finding in findings
            if finding.get("policy_id") == 107
            and finding.get("title") == "Fully Shadowed Firewall Policy"
        ]
        self.assertEqual(len(p107_shadowed), 1)
        self.assertEqual(p107_shadowed[0]["severity"], "MEDIUM")
        self.assertEqual(p107_shadowed[0]["shadowed_by_policy_id"], 101)

    def test_omitted_schedule_matches_explicit_always(self):
        self.assertTrue(_schedule_compatible({}, {"schedule": "always"}))

    def test_explicit_always_matches_omitted_schedule(self):
        self.assertTrue(_schedule_compatible({"schedule": "always"}, {}))

    def test_omitted_schedules_match_each_other(self):
        self.assertTrue(_schedule_compatible({}, {}))
        self.assertTrue(
            _schedule_compatible(
                {"schedule": "always"}, {"schedule": "always"}
            )
        )

    def test_named_schedule_does_not_match_omitted_schedule(self):
        self.assertFalse(
            _schedule_compatible({"schedule": "work-hours"}, {})
        )
        self.assertFalse(_schedule_compatible({"schedule": "night"}, {}))

    def test_duplicate_policy_with_omitted_and_explicit_always_schedule(self):
        shared_fields = {
            "srcintf": ["LAN"],
            "dstintf": ["WAN"],
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["HTTPS"],
            "action": "accept",
        }
        earlier = {"id": 201, "sequence_index": 0, **shared_fields}
        later = {
            "id": 202,
            "sequence_index": 1,
            **shared_fields,
            "schedule": "always",
        }

        findings = analyze_configuration(
            {"policies": [earlier, later]}
        )["findings"]
        duplicate_findings = [
            finding
            for finding in findings
            if finding.get("policy_id") == 202
            and finding.get("title") == "Duplicate Firewall Policy"
        ]

        self.assertEqual(len(duplicate_findings), 1)
        self.assertEqual(duplicate_findings[0]["severity"], "LOW")
        self.assertEqual(duplicate_findings[0]["shadowed_by_policy_id"], 201)

    def test_multivdom_same_named_addresses_resolve_within_scope(self):
        config = parse_configuration(read_fixture("multivdom.conf"))
        analysis = analyze_configuration(config)
        root = next(
            item
            for item in analysis["policy_assessments"]
            if item["policy_id"] == 12 and item["vdom"] == "root"
        )
        branch = next(
            item
            for item in analysis["policy_assessments"]
            if item["policy_id"] == 12 and item["vdom"] == "VDOM-B"
        )

        self.assertEqual(root["resolved_sources"][0]["subnet"], "10.10.10.10/32")
        self.assertEqual(
            branch["resolved_sources"][0]["subnet"], "172.16.10.10/32"
        )

    def test_multivdom_service_groups_and_vips_resolve_within_scope(self):
        config = parse_configuration(read_fixture("multivdom.conf"))
        assessments = analyze_configuration(config)["policy_assessments"]
        root = next(
            item
            for item in assessments
            if item["policy_id"] == 12 and item["vdom"] == "root"
        )
        branch = next(
            item
            for item in assessments
            if item["policy_id"] == 12 and item["vdom"] == "VDOM-B"
        )

        self.assertEqual(
            root["resolved_services"][0]["members"][0]["name"],
            "ROOT_HTTPS",
        )
        self.assertEqual(
            branch["resolved_services"][0]["members"][0]["name"],
            "BRANCH_SSH",
        )
        self.assertEqual(root["vip_references"][0]["mapped_ip"], "10.10.10.10")
        self.assertEqual(
            branch["vip_references"][0]["mapped_ip"], "172.16.10.10"
        )

    def test_multivdom_security_profiles_resolve_within_scope(self):
        config = parse_configuration(read_fixture("multivdom.conf"))
        assessments = analyze_configuration(config)["policy_assessments"]

        for vdom in ("root", "VDOM-B"):
            assessment = next(
                item
                for item in assessments
                if item["policy_id"] == 12 and item["vdom"] == vdom
            )
            ips = assessment["security_profiles"]["ips"]
            self.assertTrue(ips["resolved"])
            self.assertEqual(ips["source"], "custom")
            self.assertEqual(ips["vdom"], vdom)

    def test_identical_policies_in_different_vdoms_are_not_duplicates(self):
        config = parse_configuration(read_fixture("multivdom.conf"))
        findings = analyze_configuration(config)["findings"]
        cross_vdom_duplicates = [
            finding
            for finding in findings
            if finding.get("title") == "Duplicate Firewall Policy"
            and finding.get("policy_id") == 10
        ]

        self.assertEqual(cross_vdom_duplicates, [])

    def test_shadowing_is_isolated_by_vdom_and_preserved_within_vdom(self):
        config = parse_configuration(read_fixture("multivdom.conf"))
        findings = analyze_configuration(config)["findings"]
        root_shadowing = [
            finding
            for finding in findings
            if finding.get("title") == "Fully Shadowed Firewall Policy"
            and finding.get("policy_id") == 11
            and finding.get("vdom") == "root"
        ]
        branch_cross_shadowing = [
            finding
            for finding in findings
            if finding.get("shadowed_by_policy_id") == 10
            and finding.get("vdom") == "VDOM-B"
        ]

        self.assertEqual(len(root_shadowing), 1)
        self.assertEqual(root_shadowing[0]["shadowed_by_policy_id"], 10)
        self.assertEqual(branch_cross_shadowing, [])

    def test_object_from_another_vdom_remains_unresolved(self):
        config_text = """
config vdom
    edit "root"
        config firewall policy
            edit 1
                set srcintf "lan"
                set dstintf "wan"
                set srcaddr "BRANCH_ONLY"
                set dstaddr "all"
                set action accept
                set service "ALL"
                set ips-sensor "BRANCH_IPS"
            next
        end
    next
    edit "VDOM-B"
        config firewall address
            edit "BRANCH_ONLY"
                set subnet 172.16.0.0 255.255.0.0
            next
        end
        config ips sensor
            edit "BRANCH_IPS"
            next
        end
    next
end
"""
        assessment = analyze_configuration(parse_configuration(config_text))[
            "policy_assessments"
        ][0]

        self.assertEqual(assessment["resolved_sources"][0]["type"], "unknown")
        self.assertFalse(assessment["security_profiles"]["ips"]["resolved"])

    def test_policy_operational_fields_are_exposed_as_inventory(self):
        config = parse_configuration(read_fixture("health_v4.conf"))
        assessment = next(
            item
            for item in analyze_configuration(config)["policy_assessments"]
            if item["policy_id"] == 100
        )

        self.assertEqual(
            assessment["operational_settings"],
            {
                "inspection-mode": "flow",
                "logtraffic-start": "enable",
                "capture-packet": "enable",
                "auto-asic-offload": "disable",
            },
        )

    def test_single_vdom_interface_with_set_vdom_root_resolves(self):
        config_text = """
config system interface
    edit "lan1"
        set vdom "root"
        set role lan
    next
    edit "wan1"
        set vdom "root"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "lan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_intf = assessment["source_interfaces"][0]
        dst_intf = assessment["destination_interfaces"][0]

        self.assertTrue(src_intf["resolved"])
        self.assertEqual(src_intf["role"], "LAN")
        self.assertFalse(src_intf["role_inferred"])
        self.assertEqual(src_intf["configured_role"], "lan")

        self.assertTrue(dst_intf["resolved"])
        self.assertEqual(dst_intf["role"], "WAN")
        self.assertFalse(dst_intf["role_inferred"])
        self.assertEqual(dst_intf["configured_role"], "wan")

    def test_explicit_role_overrides_misleading_name(self):
        config_text = """
config system interface
    edit "VLAN50-DMZ"
        set role lan
    next
end
config firewall policy
    edit 1
        set srcintf "VLAN50-DMZ"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        src_intf = analysis["policy_assessments"][0]["source_interfaces"][0]
        self.assertTrue(src_intf["resolved"])
        self.assertEqual(src_intf["role"], "LAN")
        self.assertFalse(src_intf["role_inferred"])

    def test_alias_wan_inference_when_role_absent(self):
        config_text = """
config system interface
    edit "port4"
        set alias "WAN-ISP"
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "port4"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        dst_intf = analysis["policy_assessments"][0]["destination_interfaces"][0]
        self.assertTrue(dst_intf["resolved"])
        self.assertEqual(dst_intf["role"], "WAN")
        self.assertTrue(dst_intf["role_inferred"])

    def test_system_zone_member_resolution_and_lan_role(self):
        config_text = """
config system interface
    edit "port2"
        set role lan
    next
end
config system zone
    edit "emir_LOCAL"
        set intrazone allow
        set interface "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "emir_LOCAL"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        src_zone = analysis["policy_assessments"][0]["source_interfaces"][0]
        self.assertTrue(src_zone["resolved"])
        self.assertEqual(src_zone["type"], "zone")
        self.assertEqual(src_zone["role"], "LAN")
        self.assertTrue(src_zone["role_inferred"])

    def test_mixed_role_zone_remains_unknown(self):
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
    edit "port2"
        set role lan
    next
end
config system zone
    edit "MIXED_ZONE"
        set interface "port1" "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "MIXED_ZONE"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        src_zone = analysis["policy_assessments"][0]["source_interfaces"][0]
        self.assertTrue(src_zone["resolved"])
        self.assertEqual(src_zone["role"], "UNKNOWN")

    def test_sdwan_zone_resolution_and_wan_role(self):
        config_text = """
config system interface
    edit "port3"
        set role wan
    next
    edit "port5"
        set role wan
    next
end
config system sdwan
    set status enable
    config zone
        edit "SD-WAN"
        next
    end
    config members
        edit 1
            set interface "port5"
            set zone "SD-WAN"
        next
        edit 2
            set interface "port3"
            set zone "SD-WAN"
        next
    end
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "SD-WAN"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        dst_zone = analysis["policy_assessments"][0]["destination_interfaces"][0]
        self.assertTrue(dst_zone["resolved"])
        self.assertEqual(dst_zone["type"], "sdwan_zone")
        self.assertEqual(dst_zone["role"], "WAN")
        self.assertTrue(dst_zone["role_inferred"])

    def test_builtin_any_interface_recognition(self):
        config_text = """
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        src_intf = analysis["policy_assessments"][0]["source_interfaces"][0]
        self.assertTrue(src_intf["resolved"])
        self.assertEqual(src_intf["role"], "UNKNOWN")
        self.assertFalse(src_intf["role_inferred"])
        self.assertEqual(src_intf["type"], "builtin")

    def test_unknown_interface_remains_unresolved(self):
        config_text = """
config firewall policy
    edit 1
        set srcintf "MISSING_INTERFACE"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        src_intf = analysis["policy_assessments"][0]["source_interfaces"][0]
        self.assertFalse(src_intf["resolved"])
        self.assertEqual(src_intf["type"], "unknown")

    def test_multivdom_interface_isolation_and_no_cross_borrowing(self):
        config_text = """
config system interface
    edit "wan_root"
        set vdom "root"
        set role wan
    next
    edit "wan_b"
        set vdom "VDOM-B"
        set role wan
    next
end
config vdom
    edit "root"
        config firewall policy
            edit 1
                set srcintf "any"
                set dstintf "wan_root"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
            next
        end
    next
    edit "VDOM-B"
        config firewall policy
            edit 2
                set srcintf "any"
                set dstintf "wan_root"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        p1_dst = analysis["policy_assessments"][0]["destination_interfaces"][0]
        p2_dst = analysis["policy_assessments"][1]["destination_interfaces"][0]

        # In root, wan_root resolves
        self.assertTrue(p1_dst["resolved"])
        self.assertEqual(p1_dst["role"], "WAN")

        # In VDOM-B, wan_root is NOT borrowed from root and remains unresolved
        self.assertFalse(p2_dst["resolved"])

    def test_real_world_case_a_lan_to_wan_internet_access(self):
        config_text = """
config system interface
    edit "VLAN10-IT"
        set vdom "root"
        set role lan
    next
    edit "port4"
        set vdom "root"
        set alias "WAN-ISP"
    next
end
config firewall policy
    edit 1
        set srcintf "VLAN10-IT"
        set dstintf "port4"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "OUTBOUND_INTERNET")
        self.assertEqual(assessment["purpose"], "Internet Access")
        self.assertEqual(assessment["traffic_direction"], "LAN -> WAN")

    def test_real_world_case_b_wan_to_vip_publishing(self):
        config_text = """
config system interface
    edit "port4"
        set vdom "root"
        set alias "WAN-ISP"
    next
    edit "VLAN50-DMZ"
        set vdom "root"
        set role dmz
    next
end
config firewall vip
    edit "PUB_HTTPS"
        set extip 203.0.113.10
        set mappedip 192.168.50.10
        set extintf "port4"
    next
end
config firewall policy
    edit 2
        set srcintf "port4"
        set dstintf "VLAN50-DMZ"
        set srcaddr "all"
        set dstaddr "PUB_HTTPS"
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "INBOUND_PUBLIC")
        self.assertEqual(assessment["purpose"], "Public Server Publishing")
        self.assertEqual(assessment["traffic_direction"], "WAN -> DMZ")

    def test_real_world_case_c_system_zone_to_sdwan_internet_access(self):
        config_text = """
config system interface
    edit "port2"
        set vdom "root"
        set role lan
    next
    edit "port3"
        set vdom "root"
        set role wan
    next
    edit "port5"
        set vdom "root"
        set role wan
    next
end
config system zone
    edit "emir_LOCAL"
        set interface "port2"
    next
end
config system sdwan
    set status enable
    config zone
        edit "SD-WAN"
        next
    end
    config members
        edit 1
            set interface "port3"
            set zone "SD-WAN"
        next
        edit 2
            set interface "port5"
            set zone "SD-WAN"
        next
    end
end
config firewall policy
    edit 3
        set srcintf "emir_LOCAL"
        set dstintf "SD-WAN"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["traffic_direction"], "LAN -> WAN")
        self.assertEqual(assessment["flow_type"], "OUTBOUND_INTERNET")
        self.assertEqual(assessment["purpose"], "Internet Access")

    def test_real_world_case_d_system_zone_to_dmz_web_access(self):
        config_text = """
config system interface
    edit "port2"
        set vdom "root"
        set role lan
    next
    edit "port1"
        set vdom "root"
        set role dmz
    next
end
config system zone
    edit "emir_LOCAL"
        set interface "port2"
    next
end
config firewall policy
    edit 4
        set srcintf "emir_LOCAL"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTP"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["traffic_direction"], "LAN -> DMZ")
        self.assertEqual(assessment["flow_type"], "INTERNAL_ACCESS")
        self.assertEqual(assessment["purpose"], "Web Access")


if __name__ == "__main__":
    unittest.main()

