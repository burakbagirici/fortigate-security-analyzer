"""Unit tests for FortiGate IPv6 Static Configuration Analysis."""

from __future__ import annotations

import json
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import (
    assess_input_quality,
    parse_configuration,
    parse_firewall_policies,
    parse_addresses6,
    parse_address_groups6,
    parse_vips6,
    parse_local_in_policies6,
    parse_interface_policies6,
)


class TestIPv6StaticAnalysis(unittest.TestCase):
    """Verify safe static analysis and family isolation of FortiGate IPv6 configurations."""

    def test_01_address_family_detection_ipv4(self):
        """1. Standard IPv4 policy has address_family='IPv4'."""
        text = """
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(parsed["policies"][0]["address_family"], "IPv4")
        analysis = analyze_configuration(parsed)
        self.assertEqual(analysis["policy_assessments"][0]["address_family"], "IPv4")

    def test_02_address_family_detection_ipv6(self):
        """2. Policy with srcaddr6/dstaddr6 has address_family='IPv6'."""
        text = """
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "CORP_NET6"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(parsed["policies"][0]["address_family"], "IPv6")
        analysis = analyze_configuration(parsed)
        self.assertEqual(analysis["policy_assessments"][0]["address_family"], "IPv6")

    def test_03_address_family_detection_mixed_or_ambiguous(self):
        """3. Policy configuring both IPv4 and IPv6 selectors is marked MIXED_OR_AMBIGUOUS."""
        text = """
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "CORP_NET4"
        set srcaddr6 "CORP_NET6"
        set dstaddr "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(parsed["policies"][0]["address_family"], "MIXED_OR_AMBIGUOUS")
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["address_family"], "MIXED_OR_AMBIGUOUS")
        self.assertEqual(assessment["purpose"], "Custom / Unknown Access")
        self.assertEqual(assessment["purpose_confidence"], "LOW")

    def test_04_address_family_detection_unknown(self):
        """4. Policy without any address selectors is marked UNKNOWN."""
        text = """
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(parsed["policies"][0]["address_family"], "UNKNOWN")

    def test_05_address6_parsing_and_resolution(self):
        """5. config firewall address6 parsing and subnet resolution."""
        text = """
config firewall address6
    edit "CORP_NET6"
        set ip6 2001:db8:1::/48
        set comment "Corporate IPv6 Subnet"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "CORP_NET6"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["addresses6"]), 1)
        addr = parsed["addresses6"][0]
        self.assertEqual(addr["name"], "CORP_NET6")
        self.assertEqual(addr["ip6"], "2001:db8:1::/48")

        analysis = analyze_configuration(parsed)
        resolved_src = analysis["policy_assessments"][0]["resolved_sources"][0]
        self.assertEqual(resolved_src["name"], "CORP_NET6")
        self.assertEqual(resolved_src["type"], "address")
        self.assertEqual(resolved_src["address_family"], "IPv6")
        self.assertEqual(resolved_src["subnet"], "2001:db8:1::/48")

    def test_06_address_group6_parsing_and_resolution(self):
        """6. config firewall addrgrp6 parsing and member expansion."""
        text = """
config firewall address6
    edit "NET_A6"
        set ip6 2001:db8:1::/64
    next
    edit "NET_B6"
        set ip6 2001:db8:2::/64
    next
end
config firewall addrgrp6
    edit "GRP_ALL6"
        set member "NET_A6" "NET_B6"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "GRP_ALL6"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["address_groups6"]), 1)
        analysis = analyze_configuration(parsed)
        resolved_src = analysis["policy_assessments"][0]["resolved_sources"][0]
        self.assertEqual(resolved_src["name"], "GRP_ALL6")
        self.assertEqual(resolved_src["type"], "address_group")
        self.assertEqual(resolved_src["address_family"], "IPv6")
        self.assertEqual(len(resolved_src["members"]), 2)
        member_names = [m["name"] for m in resolved_src["members"]]
        self.assertIn("NET_A6", member_names)
        self.assertIn("NET_B6", member_names)

    def test_07_vip6_parsing_and_resolution(self):
        """7. config firewall vip6 parsing and resolution."""
        text = """
config firewall vip6
    edit "VIP_EXT6"
        set extip 2001:db8:cafe::1
        set mappedip 2001:db8:feed::1
    next
end
config firewall policy
    edit 1
        set srcintf "wan"
        set dstintf "dmz"
        set srcaddr6 "all"
        set dstaddr6 "VIP_EXT6"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["vips6"]), 1)
        vip = parsed["vips6"][0]
        self.assertEqual(vip["name"], "VIP_EXT6")
        self.assertEqual(vip["extip"], "2001:db8:cafe::1")
        self.assertEqual(vip["mappedip"], "2001:db8:feed::1")

        analysis = analyze_configuration(parsed)
        resolved_dst = analysis["policy_assessments"][0]["resolved_destinations"][0]
        self.assertEqual(resolved_dst["name"], "VIP_EXT6")
        self.assertEqual(resolved_dst["type"], "vip")
        self.assertEqual(resolved_dst["address_family"], "IPv6")

    def test_08_strict_isolation_no_cross_family_borrowing(self):
        """8. IPv4 objects are NOT resolved in IPv6 policies, and vice versa."""
        text = """
config firewall address
    edit "ADDR_IPV4"
        set subnet 10.10.10.0 255.255.255.0
    next
end
config firewall address6
    edit "ADDR_IPV6"
        set ip6 2001:db8:a::/64
    next
end
config firewall policy
    edit 1
        set name "IPv4-Trying-To-Use-IPv6"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "ADDR_IPV6"
        set dstaddr "all"
        set action accept
    next
    edit 2
        set name "IPv6-Trying-To-Use-IPv4"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "ADDR_IPV4"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)

        # Policy 1 is IPv4: ADDR_IPV6 must remain unknown
        p1 = analysis["policy_assessments"][0]
        self.assertEqual(p1["address_family"], "IPv4")
        self.assertEqual(p1["resolved_sources"][0]["type"], "unknown")

        # Policy 2 is IPv6: ADDR_IPV4 must remain unknown
        p2 = analysis["policy_assessments"][1]
        self.assertEqual(p2["address_family"], "IPv6")
        self.assertEqual(p2["resolved_sources"][0]["type"], "unknown")

    def test_09_local_in_policy6_parsing_and_assessment(self):
        """9. config firewall local-in-policy6 parsing and assessment."""
        text = """
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall local-in-policy6
    edit 1
        set intf "wan1"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set action deny
        set service "SSH"
        set status enable
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["local_in_policies6"]), 1)
        lip = parsed["local_in_policies6"][0]
        self.assertEqual(lip["address_family"], "IPv6")
        self.assertEqual(lip["action"], "deny")

        analysis = analyze_configuration(parsed)
        self.assertIn("local_in_policy6_assessments", analysis)
        lip_ass = analysis["local_in_policy6_assessments"][0]
        self.assertEqual(lip_ass["address_family"], "IPv6")
        self.assertEqual(lip_ass["action"], "deny")
        self.assertEqual(lip_ass["resolved_sources"][0]["type"], "builtin")
        self.assertEqual(lip_ass["resolved_sources"][0]["address_family"], "IPv6")

        # Negative assertion: not present in forwarding policy_assessments
        self.assertEqual(len(analysis["policy_assessments"]), 0)

    def test_10_interface_policy6_parsing_and_assessment(self):
        """10. config firewall interface-policy6 parsing and assessment."""
        text = """
config ips sensor
    edit "ips-sensor1"
    next
end
config firewall interface-policy6
    edit 1
        set interface "wan1"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set service6 "ALL"
        set ips-sensor-status enable
        set ips-sensor "ips-sensor1"
        set status enable
    next
end
"""
        parsed = parse_configuration(text)
        self.assertEqual(len(parsed["interface_policies6"]), 1)
        ip = parsed["interface_policies6"][0]
        self.assertEqual(ip["address_family"], "IPv6")
        self.assertEqual(ip["service6"], ["ALL"])

        analysis = analyze_configuration(parsed)
        self.assertIn("interface_policy6_assessments", analysis)
        ip_ass = analysis["interface_policy6_assessments"][0]
        self.assertEqual(ip_ass["address_family"], "IPv6")
        ips_profile = ip_ass["inspection_profiles"]["ips"]
        self.assertEqual(ips_profile["active"], True)
        self.assertEqual(ips_profile["resolved"], True)

        # Negative assertion: no forwarding authorization or reachability claims
        dumped = json.dumps(ip_ass).casefold()
        self.assertNotIn("action", ip_ass)
        self.assertNotIn("traffic allowed", dumped)
        self.assertNotIn("forwarding authorization", dumped)

    def test_11_ssl_vpn_ipv6_settings_and_auth_rules(self):
        """11. SSL-VPN source-address6 and tunnel-ipv6-pools."""
        text = """
config firewall address6
    edit "CORP_VPN_SRC6"
        set ip6 2001:db8:55::/64
    next
end
config user group
    edit "VPN_GROUP"
    next
end
config vpn ssl settings
    set status enable
    set source-interface "wan1"
    set source-address6 "CORP_VPN_SRC6"
    set tunnel-ipv6-pools "IPV6_POOL1"
    set default-portal "full-access"
    config authentication-rule
        edit 1
            set groups "VPN_GROUP"
            set portal "full-access"
            set source-interface "wan1"
            set source-address6 "CORP_VPN_SRC6"
        next
    end
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        ssl = analysis["ssl_vpn_assessments"][0]

        # Settings level source-address6
        self.assertEqual(len(ssl["resolved_sources6"]), 1)
        self.assertEqual(ssl["resolved_sources6"][0]["name"], "CORP_VPN_SRC6")
        self.assertEqual(ssl["resolved_sources6"][0]["type"], "address")
        self.assertEqual(ssl["resolved_sources6"][0]["address_family"], "IPv6")
        self.assertEqual(ssl["tunnel_ipv6_pools"], ["IPV6_POOL1"])
        self.assertEqual(ssl["configured_facts"]["tunnel-ipv6-pools"], ["IPV6_POOL1"])

        # Auth rule level source-address6
        rule = ssl["authentication_rules"][0]
        self.assertEqual(len(rule["resolved_addresses6"]), 1)
        self.assertEqual(rule["resolved_addresses6"][0]["name"], "CORP_VPN_SRC6")
        self.assertEqual(rule["resolved_addresses6"][0]["type"], "address")
        self.assertEqual(rule["resolved_addresses6"][0]["address_family"], "IPv6")

    def test_12_shadowing_isolation_across_families(self):
        """12. IPv4 policy never shadows IPv6 policy and vice versa."""
        text = """
config firewall address
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall address6
    edit "all"
        set ip6 ::/0
    next
    edit "SERVER6"
        set ip6 2001:db8:1::10/128
    next
end
config firewall policy
    edit 1
        set name "Broad-IPv4-Policy"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 2
        set name "Narrow-IPv6-Policy"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "SERVER6"
        set dstaddr6 "all"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        # Policy 2 must NOT be reported as shadowed by Policy 1
        shadow_findings = [
            f for f in analysis["findings"]
            if "Shadowed" in f.get("title", "")
        ]
        self.assertEqual(len(shadow_findings), 0)

    def test_13_shadowing_within_ipv6_family(self):
        """13. Broad IPv6 policy shadows narrow later IPv6 policy."""
        text = """
config firewall address6
    edit "CORP_NET6"
        set ip6 2001:db8:1::/48
    next
    edit "SERVER6"
        set ip6 2001:db8:1::10/128
    next
    edit "all"
        set ip6 ::/0
    next
end
config firewall policy
    edit 1
        set name "Broad-IPv6"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "CORP_NET6"
        set dstaddr6 "all"
        set action accept
        set service "HTTPS"
    next
    edit 2
        set name "Narrow-IPv6"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "SERVER6"
        set dstaddr6 "all"
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        shadow_findings = [
            f for f in analysis["findings"]
            if f.get("title") == "Fully Shadowed Firewall Policy"
        ]
        self.assertEqual(len(shadow_findings), 1)
        self.assertEqual(shadow_findings[0]["policy_id"], 2)
        self.assertEqual(shadow_findings[0]["shadowed_by_policy_id"], 1)

    def test_14_vdom_isolation_for_ipv6(self):
        """14. IPv6 objects and policies in one VDOM do not leak into another."""
        text = """
config vdom
    edit "VDOM_A"
        config firewall address6
            edit "NET_A6"
                set ip6 2001:db8:a::/64
            next
        end
        config firewall policy
            edit 1
                set srcintf "lan"
                set dstintf "wan"
                set srcaddr6 "NET_A6"
                set dstaddr6 "all"
                set action accept
            next
        end
    next
    edit "VDOM_B"
        config firewall policy
            edit 2
                set srcintf "lan"
                set dstintf "wan"
                set srcaddr6 "NET_A6"
                set dstaddr6 "all"
                set action accept
            next
        end
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        assessments = analysis["policy_assessments"]

        # VDOM_A policy 1 resolves NET_A6
        p1 = next(a for a in assessments if a["vdom"] == "VDOM_A")
        self.assertEqual(p1["resolved_sources"][0]["type"], "address")
        self.assertEqual(p1["resolved_sources"][0]["address_family"], "IPv6")

        # VDOM_B policy 2 cannot resolve NET_A6
        p2 = next(a for a in assessments if a["vdom"] == "VDOM_B")
        self.assertEqual(p2["resolved_sources"][0]["type"], "unknown")

    def test_15_health_check_unresolved_ipv6_reference(self):
        """15. Unresolved IPv6 address reference generates integrity check finding."""
        text = """
config system interface
    edit "lan"
        set role lan
    next
    edit "wan"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "NON_EXISTENT_IPV6"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)
        integrity = [
            c for c in health["checks"]
            if c.get("title") == "Configuration References Could Not Be Fully Resolved"
        ]
        self.assertEqual(len(integrity), 1)
        self.assertTrue(any("NON_EXISTENT_IPV6" in e for e in integrity[0]["evidence"]))

    def test_16_health_check_all_ipv6_builtin_tolerance(self):
        """16. Builtin 'all' or 'all_ipv6' in IPv6 policy does not trigger unresolved finding."""
        text = """
config system interface
    edit "lan"
        set role lan
    next
    edit "wan"
        set role wan
    next
end
config firewall address6
    edit "all"
        set ip6 ::/0
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)
        integrity = [
            c for c in health["checks"]
            if c.get("title") == "Configuration References Could Not Be Fully Resolved"
        ]
        self.assertEqual(len(integrity), 0)

    def test_17_input_quality_ipv6_domain_coverage(self):
        """17. Input quality assessment accurately reflects IPv6 domain."""
        text = """
config firewall address6
    edit "NET6"
        set ip6 2001:db8::/32
    next
end
config firewall vip6
    edit "VIP6"
        set extip 2001:db8::1
        set mappedip 2001:db8::2
    next
end
config firewall local-in-policy6
    edit 1
        set intf "wan1"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set action deny
    next
end
config firewall interface-policy6
    edit 1
        set interface "wan1"
        set srcaddr6 "all"
        set dstaddr6 "all"
    next
end
"""
        parsed = parse_configuration(text)
        quality = assess_input_quality(text, parsed)
        self.assertEqual(quality["analysis_scope"]["ipv6"]["status"], "COVERED")
        self.assertEqual(quality["object_counts"]["addresses6"], 1)
        self.assertEqual(quality["object_counts"]["vips6"], 1)
        self.assertEqual(quality["object_counts"]["local_in_policies6"], 1)
        self.assertEqual(quality["object_counts"]["interface_policies6"], 1)

    def test_18_golden_fixture_ipv6_conf(self):
        """18. Verify the ipv6.conf golden fixture parses and analyzes cleanly."""
        with open("tests/fixtures/golden/ipv6.conf", "r", encoding="utf-8") as f:
            content = f.read()

        parsed = parse_configuration(content)
        self.assertEqual(len(parsed["policies"]), 5)
        self.assertEqual(len(parsed["addresses6"]), 4)
        self.assertEqual(len(parsed["address_groups6"]), 1)
        self.assertEqual(len(parsed["vips6"]), 1)
        self.assertEqual(len(parsed["local_in_policies6"]), 2)
        self.assertEqual(len(parsed["interface_policies6"]), 1)

        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        # Policy 3 (IPv6 SERVER6) is shadowed by Policy 2 (IPv6 CORP_NET6)
        shadow_findings = [
            f for f in analysis["findings"]
            if f.get("title") == "Fully Shadowed Firewall Policy"
        ]
        self.assertEqual(len(shadow_findings), 1)
        self.assertEqual(shadow_findings[0]["policy_id"], 3)
        self.assertEqual(shadow_findings[0]["shadowed_by_policy_id"], 2)

        # Interface policy 1 has active resolved IPS sensor
        ip_ass = analysis["interface_policy6_assessments"][0]
        self.assertTrue(ip_ass["inspection_profiles"]["ips"]["active"])
        self.assertTrue(ip_ass["inspection_profiles"]["ips"]["resolved"])


if __name__ == "__main__":
    unittest.main()
