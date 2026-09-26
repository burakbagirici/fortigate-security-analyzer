"""Comprehensive Robustness, Property-Style Invariant, and Corpus Hardening Tests.

Validates resilience against real-world malformations, extreme nesting,
Unicode characters, cycles, fuzz mutations, and secret leakage.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from analyzer import analyze_configuration
from health_check import run_health_check
import parser
from parser import (
    assess_input_quality,
    parse_configuration,
    parse_fortios_version,
)


class TestRobustnessAndCorpusInvariants(unittest.TestCase):
    """Test suite covering the 25 required robustness and property-style invariants."""

    BASE_CONFIG = """
#config-version=FG100F-7.2.5-build1517:00000000
config system global
    set hostname "FortiGate-Invariant-Test"
end
config system interface
    edit "port1"
        set role lan
        set allowaccess ping
    next
    edit "port2"
        set role wan
        set allowaccess ping
    next
end
config firewall address
    edit "LAN_SUBNET"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall policy
    edit 1
        set name "LAN_TO_WAN_OUTBOUND"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN_SUBNET"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS" "DNS"
        set logtraffic all
    next
end
"""

    def test_01_crlf_vs_lf(self):
        """1. CRLF line endings produce identical parsed, analyzed, and health output to LF."""
        lf_config = self.BASE_CONFIG.strip().replace("\r\n", "\n")
        crlf_config = lf_config.replace("\n", "\r\n")

        p_lf = parse_configuration(lf_config)
        p_crlf = parse_configuration(crlf_config)
        self.assertEqual(p_lf, p_crlf)

        a_lf = analyze_configuration(p_lf)
        a_crlf = analyze_configuration(p_crlf)
        self.assertEqual(a_lf, a_crlf)

        h_lf = run_health_check(p_lf, a_lf)
        h_crlf = run_health_check(p_crlf, a_crlf)
        self.assertEqual(h_lf, h_crlf)

    def test_02_whitespace_invariance(self):
        """2. Irregular indentation, excessive spaces, and blank lines do not alter semantic results."""
        messy_config = """

  #config-version=FG100F-7.2.5-build1517:00000000   
   
   config    system    global   
       set   hostname    "FortiGate-Invariant-Test"   
   end   

    config    system    interface   
        edit   "port1"   
            set    role   lan   
            set    allowaccess    ping   
        next   
        edit   "port2"   
            set    role   wan   
            set    allowaccess    ping   
        next   
    end   

    config    firewall    address   
        edit   "LAN_SUBNET"   
            set   subnet   10.0.0.0   255.255.255.0   
        next   
        edit   "all"   
            set   subnet   0.0.0.0   0.0.0.0   
        next   
    end   

    config    firewall    policy   
        edit   1   
            set   name   "LAN_TO_WAN_OUTBOUND"   
            set   srcintf   "port1"   
            set   dstintf   "port2"   
            set   srcaddr   "LAN_SUBNET"   
            set   dstaddr   "all"   
            set   action   accept   
            set   schedule   "always"   
            set   service   "HTTPS"   "DNS"   
            set   logtraffic   all   
        next   
    end   
"""
        clean_parsed = parse_configuration(self.BASE_CONFIG)
        messy_parsed = parse_configuration(messy_config)
        self.assertEqual(clean_parsed, messy_parsed)

    def test_03_unrelated_unknown_section_invariance(self):
        """3. Injecting unsupported/unknown FortiOS config blocks does not alter supported analysis."""
        injected_config = (
            self.BASE_CONFIG
            + """
config router ospf
    set router-id 1.1.1.1
    config area
        edit 0.0.0.0
        next
    end
end
config switch-controller managed-switch
    edit "FS108E3X14000123"
        set fsw-wan1-admin enable
    next
end
config system custom-hardware-sensor
    set mode turbo
end
"""
        )
        base_p = parse_configuration(self.BASE_CONFIG)
        base_a = analyze_configuration(base_p)
        base_h = run_health_check(base_p, base_a)

        inj_p = parse_configuration(injected_config)
        inj_a = analyze_configuration(inj_p)
        inj_h = run_health_check(inj_p, inj_a)

        self.assertEqual(base_a["policy_assessments"], inj_a["policy_assessments"])
        self.assertEqual(base_a["findings"], inj_a["findings"])
        self.assertEqual(base_h["checks"], inj_h["checks"])

    def test_04_section_reorder_invariance(self):
        """4. Reordering top-level sections does not alter object resolution or policy analysis."""
        reordered_config = """
#config-version=FG100F-7.2.5-build1517:00000000
config firewall policy
    edit 1
        set name "LAN_TO_WAN_OUTBOUND"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN_SUBNET"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS" "DNS"
        set logtraffic all
    next
end
config firewall address
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
    edit "LAN_SUBNET"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config system interface
    edit "port2"
        set role wan
        set allowaccess ping
    next
    edit "port1"
        set role lan
        set allowaccess ping
    next
end
config system global
    set hostname "FortiGate-Invariant-Test"
end
"""
        base_p = parse_configuration(self.BASE_CONFIG)
        base_a = analyze_configuration(base_p)

        reord_p = parse_configuration(reordered_config)
        reord_a = analyze_configuration(reord_p)

        # Assessments must match completely
        self.assertEqual(
            base_a["policy_assessments"][0]["purpose"],
            reord_a["policy_assessments"][0]["purpose"],
        )
        self.assertEqual(
            base_a["policy_assessments"][0]["resolved_sources"],
            reord_a["policy_assessments"][0]["resolved_sources"],
        )
        self.assertEqual(
            base_a["policy_assessments"][0]["source_interfaces"],
            reord_a["policy_assessments"][0]["source_interfaces"],
        )

    def test_05_deterministic_repeated_analysis(self):
        """5. Repeated analysis of identical input produces bit-for-bit identical outputs."""
        p = parse_configuration(self.BASE_CONFIG)
        first_a = analyze_configuration(p)
        first_h = run_health_check(p, first_a)

        for _ in range(5):
            loop_a = analyze_configuration(p)
            loop_h = run_health_check(p, loop_a)
            self.assertEqual(first_a, loop_a)
            self.assertEqual(first_h, loop_h)

    def test_06_unicode_object_names(self):
        """6. Unicode object names, comments, and values do not crash parser or analyzer."""
        unicode_config = """
config system interface
    edit "port1"
        set role lan
    next
    edit "port2"
        set role wan
    next
end
config firewall address
    edit "ADDR_Şirket_Ağı"
        set subnet 10.20.30.0 255.255.255.0
        set comment "İntranet güvenli bölge 🚀"
    next
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall policy
    edit 1
        set name "POL_Özel_Erişim"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "ADDR_Şirket_Ağı"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set comments "Türkçe karakter ve Emoji testi"
    next
end
"""
        parsed = parse_configuration(unicode_config)
        analysis = analyze_configuration(parsed)
        p_ass = analysis["policy_assessments"][0]
        self.assertEqual(p_ass["resolved_sources"][0]["name"], "ADDR_Şirket_Ağı")
        self.assertEqual(p_ass["resolved_sources"][0]["type"], "address")

    def test_07_escaped_quote_handling(self):
        """7. Escaped quotes in comments and values are parsed cleanly without breaking tokens."""
        config_text = r"""
config system interface
    edit "port1"
        set description "Interface with \"nested escaped\" quotes"
    next
end
config firewall policy
    edit 1
        set name "Policy_Quote_Test"
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set comments "He said: \"Allow traffic\", and it was allowed."
    next
end
"""
        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["interfaces"]), 1)
        self.assertEqual(len(parsed["policies"]), 1)
        self.assertIn('"nested escaped"', parsed["interfaces"][0]["description"])
        self.assertIn('"Allow traffic"', parsed["policies"][0]["comments"])

    def test_08_long_comments(self):
        """8. Extremely long comments (10,000 chars) are processed safely without catastrophic backtracking."""
        long_comment = "SAFE_TEXT_" * 1000  # 10,000 characters
        config_text = f"""
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set comments "{long_comment}"
    next
end
"""
        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["policies"]), 1)
        self.assertEqual(parsed["policies"][0]["comments"], long_comment)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)

    def test_09_missing_next(self):
        """9. Missing 'next' keyword between edits is tolerated without crashing."""
        config_text = """
config firewall address
    edit "ADDR_1"
        set subnet 10.1.1.0 255.255.255.0
    edit "ADDR_2"
        set subnet 10.2.2.0 255.255.255.0
    next
end
"""
        parsed = parse_configuration(config_text)
        self.assertTrue(len(parsed["addresses"]) >= 1)

    def test_10_missing_end(self):
        """10. Unclosed config section abruptly hitting EOF does not raise an unhandled exception."""
        config_text = """
config system global
    set hostname "TruncatedDevice"
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
"""
        parsed = parse_configuration(config_text)
        self.assertIsInstance(parsed, dict)
        quality = assess_input_quality(config_text, parsed)
        self.assertIn(quality["classification"], {
            "FORTIGATE_CONFIGURATION_UNKNOWN_COMPLETENESS",
            "MALFORMED_OR_TRUNCATED_CONFIGURATION",
            "PARTIAL_CONFIGURATION",
        })

    def test_11_duplicate_section(self):
        """11. Duplicated top-level configuration sections are aggregated safely."""
        config_text = """
config firewall address
    edit "ADDR_1"
        set subnet 10.1.0.0 255.255.0.0
    next
end
config firewall address
    edit "ADDR_2"
        set subnet 10.2.0.0 255.255.0.0
    next
end
"""
        parsed = parse_configuration(config_text)
        addr_names = {a["name"] for a in parsed["addresses"]}
        self.assertEqual(addr_names, {"ADDR_1", "ADDR_2"})

    def test_12_unknown_set_field(self):
        """12. Unknown or proprietary 'set' fields are tolerated and ignored without error."""
        config_text = """
config system interface
    edit "port1"
        set role lan
        set proprietary-experimental-acceleration enable
        set vendor-specific-offload 4096
    next
end
"""
        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["interfaces"]), 1)
        self.assertEqual(parsed["interfaces"][0]["role"], "lan")

    def test_13_vdom_same_name_isolation(self):
        """13. Objects with identical names in different VDOMs are strictly isolated."""
        config_text = """
config vdom
    edit "CORP_VDOM"
        config firewall address
            edit "SHARED_NAME"
                set subnet 10.10.10.0 255.255.255.0
            next
        end
        config firewall policy
            edit 1
                set srcintf "any"
                set dstintf "any"
                set srcaddr "SHARED_NAME"
                set dstaddr "all"
                set action accept
            next
        end
    next
    edit "GUEST_VDOM"
        config firewall address
            edit "SHARED_NAME"
                set subnet 192.168.99.0 255.255.255.0
            next
        end
        config firewall policy
            edit 2
                set srcintf "any"
                set dstintf "any"
                set srcaddr "SHARED_NAME"
                set dstaddr "all"
                set action accept
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        corp_p = next(a for a in analysis["policy_assessments"] if a["vdom"] == "CORP_VDOM")
        guest_p = next(a for a in analysis["policy_assessments"] if a["vdom"] == "GUEST_VDOM")

        self.assertEqual(corp_p["resolved_sources"][0]["subnet"], "10.10.10.0/24")
        self.assertEqual(guest_p["resolved_sources"][0]["subnet"], "192.168.99.0/24")

    def test_14_ipv4_ipv6_same_name_isolation(self):
        """14. Objects sharing the same name in firewall address and address6 do not cross-pollute."""
        config_text = """
config firewall address
    edit "SAME_NAME_OBJ"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall address6
    edit "SAME_NAME_OBJ"
        set ip6 2001:db8:beef::/48
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "SAME_NAME_OBJ"
        set dstaddr "all"
        set action accept
    next
    edit 2
        set srcintf "any"
        set dstintf "any"
        set srcaddr6 "SAME_NAME_OBJ"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        p1 = analysis["policy_assessments"][0]
        p2 = analysis["policy_assessments"][1]

        self.assertEqual(p1["address_family"], "IPv4")
        self.assertEqual(p1["resolved_sources"][0]["address_family"], "IPv4")
        self.assertEqual(p1["resolved_sources"][0]["subnet"], "10.0.0.0/24")

        self.assertEqual(p2["address_family"], "IPv6")
        self.assertEqual(p2["resolved_sources"][0]["address_family"], "IPv6")
        self.assertEqual(p2["resolved_sources"][0]["subnet"], "2001:db8:beef::/48")

    def test_15_address_group_self_cycle(self):
        """15. Address group with direct self-reference terminates with loop_detected and no crash."""
        config_text = """
config firewall addrgrp
    edit "SELF_LOOP_GRP"
        set member "SELF_LOOP_GRP"
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "SELF_LOOP_GRP"
        set dstaddr "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        res_src = analysis["policy_assessments"][0]["resolved_sources"][0]
        self.assertEqual(res_src["name"], "SELF_LOOP_GRP")
        # Direct self reference is either loop_detected or empty members without RecursionError
        self.assertIsInstance(res_src.get("members"), list)

    def test_16_address_group_mutual_cycle(self):
        """16. Mutual cyclical address groups (A -> B -> A) do not cause infinite recursion."""
        config_text = """
config firewall address
    edit "HOST_1"
        set subnet 10.1.1.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "CYCLE_A"
        set member "CYCLE_B" "HOST_1"
    next
    edit "CYCLE_B"
        set member "CYCLE_A"
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "CYCLE_A"
        set dstaddr "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)
        res_src = analysis["policy_assessments"][0]["resolved_sources"][0]
        self.assertEqual(res_src["name"], "CYCLE_A")

    def test_17_deep_group_chain(self):
        """17. Deeply nested group hierarchy (20 levels) resolves without recursion limit errors."""
        lines = [
            "config firewall address",
            '    edit "TARGET_HOST"',
            "        set subnet 10.9.9.9 255.255.255.255",
            "    next",
            "end",
            "config firewall addrgrp",
            '    edit "GRP_LEVEL_1"',
            '        set member "TARGET_HOST"',
            "    next",
        ]
        for lvl in range(2, 21):
            lines.extend([
                f'    edit "GRP_LEVEL_{lvl}"',
                f'        set member "GRP_LEVEL_{lvl - 1}"',
                "    next",
            ])
        lines.extend([
            "end",
            "config firewall policy",
            "    edit 1",
            '        set srcintf "any"',
            '        set dstintf "any"',
            '        set srcaddr "GRP_LEVEL_20"',
            '        set dstaddr "all"',
            "        set action accept",
            "    next",
            "end",
        ])
        config_text = "\n".join(lines)
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)

    def test_18_service_group_cycle(self):
        """18. Mutual cyclical service groups (SVC_A -> SVC_B -> SVC_A) do not cause infinite recursion."""
        config_text = """
config firewall service group
    edit "SVC_GRP_A"
        set member "SVC_GRP_B"
    next
    edit "SVC_GRP_B"
        set member "SVC_GRP_A"
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SVC_GRP_A"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)

    def test_19_1000_policy_no_crash_and_scaling(self):
        """19. Scaling test: 1,000 forwarding policies with 100 addresses completes cleanly without crash."""
        lines = [
            "#config-version=FG1000D-7.2.5-build1517:00000000",
            "config system interface",
            '    edit "port1"',
            "        set role lan",
            "    next",
            '    edit "port2"',
            "        set role wan",
            "    next",
            "end",
            "config firewall address",
        ]
        for i in range(1, 101):
            lines.extend([
                f'    edit "ADDR_{i}"',
                f"        set subnet 10.0.{i}.0 255.255.255.0",
                "    next",
            ])
        lines.extend([
            '    edit "all"',
            "        set subnet 0.0.0.0 0.0.0.0",
            "    next",
            "end",
            "config firewall policy",
        ])
        for i in range(1, 1001):
            addr_idx = ((i - 1) % 100) + 1
            lines.extend([
                f"    edit {i}",
                f'        set name "POLICY_{i}"',
                '        set srcintf "port1"',
                '        set dstintf "port2"',
                f'        set srcaddr "ADDR_{addr_idx}"',
                '        set dstaddr "all"',
                "        set action accept",
                '        set schedule "always"',
                '        set service "HTTPS"',
                "    next",
            ])
        lines.append("end\n")
        config_text = "\n".join(lines)

        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["policies"]), 1000)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1000)
        health = run_health_check(parsed, analysis)
        self.assertIsInstance(health["checks"], list)

    def test_20_secret_injection_suppression(self):
        """20. Test fake credentials and private keys injected across all fields are never emitted in results."""
        config_text = """
config system admin
    edit "admin_test"
        set password "SUPER_SECRET_ADMIN_PASSWORD_123"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config user local
    edit "user_vpn_test"
        set passwd "SUPER_SECRET_USER_PASSWORD_456"
        set two-factor email
    next
end
config vpn ipsec phase1-interface
    edit "IPSEC_SECRET_TEST"
        set interface "port1"
        set psksecret "SUPER_SECRET_PSK_789"
        set remote-gw 198.51.100.1
    next
end
config system snmp community
    edit 1
        set name "SUPER_SECRET_COMMUNITY_ABC"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        health = run_health_check(parsed, analysis)

        serialized = json.dumps({"config": parsed, "analysis": analysis, "health": health})
        for canary in (
            "SUPER_SECRET_ADMIN_PASSWORD_123",
            "SUPER_SECRET_USER_PASSWORD_456",
            "SUPER_SECRET_PSK_789",
            "SUPER_SECRET_COMMUNITY_ABC",
        ):
            self.assertNotIn(canary, serialized)

    def test_21_malformed_ipv6_input(self):
        """21. Malformed IPv6 addresses, invalid prefixes, and truncated addresses are handled safely."""
        config_text = """
config firewall address6
    edit "MALFORMED_1"
        set ip6 2001:db8:::1/64
    next
    edit "MALFORMED_2"
        set ip6 2001:xyz::1/128
    next
    edit "MALFORMED_3"
        set ip6 2001:db8::1/150
    next
end
config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr6 "MALFORMED_1"
        set dstaddr6 "all"
        set action accept
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(len(analysis["policy_assessments"]), 1)

    def test_22_malformed_ssl_vpn_input(self):
        """22. Truncated and corrupt SSL-VPN settings are handled conservatively without crash."""
        config_text = """
config vpn ssl settings
    set status enable
    set source-interface
    set default-portal
    config authentication-rule
        edit
            set groups
        next
    end
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertIn("ssl_vpn_assessments", analysis)

    def test_23_malformed_interface_policy_input(self):
        """23. Malformed config firewall interface-policy syntax is tolerated safely."""
        config_text = """
config firewall interface-policy
    edit
        set interface
        set ips-sensor-status
        set ips-sensor
    next
    edit "invalid_id"
        set status corrupt_status
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertIn("interface_policy_assessments", analysis)

    def test_24_malformed_local_in_input(self):
        """24. Malformed config firewall local-in-policy syntax is tolerated safely."""
        config_text = """
config firewall local-in-policy
    edit
        set action
        set service
    next
    edit 99
        set action unknown_action_xyz
        set status
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertIn("local_in_assessments", analysis)

    def test_25_parser_single_index_guarantee_remains_intact(self):
        """25. parse_configuration strictly performs exactly one structural scan pass."""
        sample_config = self.BASE_CONFIG
        with patch.object(
            parser, "_annotated_config_lines", wraps=parser._annotated_config_lines
        ) as mock_scan:
            parsed = parse_configuration(sample_config)
            self.assertEqual(
                mock_scan.call_count,
                1,
                f"Single-index guarantee violated: called {mock_scan.call_count} times.",
            )
            self.assertEqual(len(parsed["policies"]), 1)


if __name__ == "__main__":
    unittest.main()
