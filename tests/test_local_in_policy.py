"""Unit tests for FortiGate Local-In Policy Analysis."""

from __future__ import annotations

import json
import unittest

from analyzer import analyze_configuration, classify_interface
from health_check import run_health_check
from parser import parse_configuration


class TestLocalInPolicy(unittest.TestCase):
    """Verify safe static analysis and resolution of FortiGate local-in policies."""

    def test_01_basic_local_in_accept(self):
        """1. Basic local-in ACCEPT policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set status enable
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["action"], "accept")
        self.assertEqual(
            local_in["assessment"],
            "This local-in policy is configured to accept matching local-in traffic bound for the FortiGate.",
        )
        self.assertNotIn("confirmed reachable", local_in["assessment"])

    def test_02_basic_local_in_deny(self):
        """2. Basic local-in DENY policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "PING"
        set status enable
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["action"], "deny")
        self.assertEqual(
            local_in["assessment"],
            "This local-in policy is configured to deny matching local-in traffic bound for the FortiGate.",
        )
        self.assertNotIn("proven effective non-exposure", local_in["assessment"])

    def test_03_disabled_local_in_policy(self):
        """3. Disabled local-in policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
        set status disable
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["purpose"], "Disabled Local-In Policy")
        self.assertIn("disabled", local_in["assessment"])

    def test_04_wan_ssh(self):
        """4. WAN + SSH local-in policy."""
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "WAN")
        self.assertEqual(local_in["purpose"], "Administrative Service Access to FortiGate")

    def test_05_wan_https(self):
        """5. WAN + HTTPS local-in policy."""
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "WAN")
        self.assertEqual(local_in["purpose"], "Administrative Service Access to FortiGate")

    def test_06_management_ssh(self):
        """6. MANAGEMENT + SSH local-in policy."""
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
    next
end
config firewall local-in-policy
    edit 1
        set intf "mgmt1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "MANAGEMENT")
        self.assertEqual(local_in["purpose"], "Management Interface Access to FortiGate")

    def test_07_lan_ssh(self):
        """7. LAN + SSH local-in policy."""
        config_text = """
config system interface
    edit "port2"
        set role lan
    next
end
config firewall local-in-policy
    edit 1
        set intf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "LAN")
        self.assertEqual(local_in["purpose"], "Local Service Access to FortiGate")

    def test_08_vpn_interface_local_in(self):
        """8. VPN interface local-in policy."""
        config_text = """
config vpn ipsec phase1-interface
    edit "ipsec1"
        set interface "port1"
    next
end
config firewall local-in-policy
    edit 1
        set intf "ipsec1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "IKE"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "VPN")
        self.assertEqual(local_in["purpose"], "VPN Service Access to FortiGate")

    def test_09_ping_local_in(self):
        """9. PING local-in policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "PING"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["purpose"], "Diagnostic Access to FortiGate")

    def test_10_custom_service(self):
        """10. Custom service local-in policy."""
        config_text = """
config firewall service custom
    edit "CUSTOM_APP"
        set tcp-portrange 8443
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "CUSTOM_APP"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["purpose"], "Local Service Access to FortiGate")
        self.assertEqual(local_in["resolved_services"][0]["type"], "custom_service")

    def test_11_address_resolution(self):
        """11. Address resolution for local-in policy."""
        config_text = """
config firewall address
    edit "ADMIN_NET"
        set subnet 192.168.1.0 255.255.255.0
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "ADMIN_NET"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_sources"][0]["subnet"], "192.168.1.0/24")

    def test_12_address_group_resolution(self):
        """12. Address group resolution."""
        config_text = """
config firewall address
    edit "HOST_A"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "ADMIN_GRP"
        set member "HOST_A"
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "ADMIN_GRP"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_sources"][0]["type"], "address_group")

    def test_13_service_group_resolution(self):
        """13. Service group resolution."""
        config_text = """
config firewall service group
    edit "ADMIN_SERVICES"
        set member "SSH" "HTTPS"
    next
end
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ADMIN_SERVICES"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_services"][0]["type"], "service_group")

    def test_14_builtin_all_and_ipv4_ipv6(self):
        """14. Built-in all / ALL / all_ipv4 / all_ipv6."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all_ipv4"
        set dstaddr "all_ipv6"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_sources"][0]["type"], "builtin")
        self.assertEqual(local_in["resolved_destinations"][0]["type"], "builtin")
        self.assertEqual(local_in["resolved_services"][0]["type"], "builtin_service")

    def test_15_unresolved_address(self):
        """15. Unresolved address in local-in policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "UNKNOWN_SRC"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_sources"][0]["type"], "unknown")

    def test_16_unresolved_service(self):
        """16. Unresolved service in local-in policy."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "UNKNOWN_SVC"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["resolved_services"][0]["type"], "unknown")

    def test_17_source_negation(self):
        """17. Source negation (srcaddr-negate)."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "ADMIN_NET"
        set srcaddr-negate enable
        set action deny
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertTrue(local_in["srcaddr_negate"])
        self.assertTrue(any("negated" in obs for obs in local_in["security_observations"]))

    def test_18_destination_negation(self):
        """18. Destination negation (dstaddr-negate)."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set dstaddr "INTERNAL_IP"
        set dstaddr-negate enable
        set action deny
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertTrue(local_in["dstaddr_negate"])

    def test_19_service_negation(self):
        """19. Service negation (service-negate)."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set service "SSH"
        set service-negate enable
        set action deny
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertTrue(local_in["service_negate"])

    def test_20_isdb_source_behavior(self):
        """20. ISDB source ID / name / group / custom behavior."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set internet-service-src enable
        set internet-service-src-name "Google-Web"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertTrue(local_in["internet_service_source"]["enabled"])

    def test_21_predefined_offline_isdb_source(self):
        """21. Predefined-offline ISDB source."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set internet-service-src enable
        set internet-service-src-name "Custom-Offline-ISDB"
        set action accept
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        selector = local_in["internet_service_source"]["selectors"][0]
        self.assertEqual(selector["resolution"], "predefined_offline")

    def test_22_ha_mgmt_intf_only(self):
        """22. ha-mgmt-intf-only metadata."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set ha-mgmt-intf-only enable
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["ha_mgmt_intf_only"], "enable")
        self.assertTrue(any("HA management" in obs for obs in local_in["security_observations"]))

    def test_23_virtual_patch_metadata(self):
        """23. virtual-patch metadata."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set virtual-patch enable
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["virtual_patch"], "enable")
        self.assertTrue(any("Virtual patch" in obs for obs in local_in["security_observations"]))

    def test_24_configuration_order_and_sequence_index(self):
        """24. Configuration order / sequence_index."""
        config_text = """
config firewall local-in-policy
    edit 10
        set intf "port1"
        set action accept
    next
    edit 5
        set intf "port1"
        set action deny
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        items = analysis["local_in_assessments"]
        self.assertEqual([i["policy_id"] for i in items], [10, 5])
        self.assertEqual([i["sequence_index"] for i in items], [0, 1])

    def test_25_disabled_policy_is_not_active_exposure(self):
        """25. Disabled policy is not active exposure."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set status disable
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["purpose"], "Disabled Local-In Policy")
        self.assertTrue(any("disabled" in obs for obs in local_in["security_observations"]))

    def test_26_deny_policy_is_not_exposure(self):
        """26. DENY policy is not exposure."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set action deny
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["action"], "deny")
        self.assertIn("deny", local_in["assessment"])

    def test_27_management_does_not_become_wan(self):
        """27. MANAGEMENT does not become WAN."""
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
    next
end
config firewall local-in-policy
    edit 1
        set intf "mgmt1"
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "MANAGEMENT")

    def test_28_lan_does_not_become_wan(self):
        """28. LAN does not become WAN."""
        config_text = """
config system interface
    edit "port2"
        set role lan
    next
end
config firewall local-in-policy
    edit 1
        set intf "port2"
        set action accept
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "LAN")

    def test_29_vpn_does_not_become_wan(self):
        """29. VPN does not become WAN."""
        config_text = """
config vpn ipsec phase1-interface
    edit "ipsec1"
        set interface "port1"
    next
end
config firewall local-in-policy
    edit 1
        set intf "ipsec1"
        set action accept
        set service "IKE"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        local_in = analysis["local_in_assessments"][0]
        self.assertEqual(local_in["interface_context"], "VPN")

    def test_30_vdom_isolation(self):
        """30. VDOM isolation for local-in policies."""
        config_text = """
config vdom
    edit "VDOM-A"
        config firewall local-in-policy
            edit 1
                set intf "port1"
                set action accept
            next
        end
    next
    edit "VDOM-B"
        config firewall local-in-policy
            edit 1
                set intf "port2"
                set action deny
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        item_a = next(i for i in analysis["local_in_assessments"] if i["vdom"] == "VDOM-A")
        item_b = next(i for i in analysis["local_in_assessments"] if i["vdom"] == "VDOM-B")
        self.assertEqual(item_a["action"], "accept")
        self.assertEqual(item_b["action"], "deny")

    def test_31_same_name_object_isolation_between_vdoms(self):
        """31. Same-name object resolution isolation between VDOMs."""
        config_text = """
config vdom
    edit "VDOM-A"
        config firewall address
            edit "ADDR1"
                set subnet 10.1.0.0 255.255.255.0
            next
        end
        config firewall local-in-policy
            edit 1
                set intf "port1"
                set srcaddr "ADDR1"
                set action accept
            next
        end
    next
    edit "VDOM-B"
        config firewall address
            edit "ADDR1"
                set subnet 10.2.0.0 255.255.255.0
            next
        end
        config firewall local-in-policy
            edit 1
                set intf "port1"
                set srcaddr "ADDR1"
                set action accept
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        item_a = next(i for i in analysis["local_in_assessments"] if i["vdom"] == "VDOM-A")
        item_b = next(i for i in analysis["local_in_assessments"] if i["vdom"] == "VDOM-B")
        self.assertEqual(item_a["resolved_sources"][0]["subnet"], "10.1.0.0/24")
        self.assertEqual(item_b["resolved_sources"][0]["subnet"], "10.2.0.0/24")

    def test_32_malformed_truncated_local_in_block(self):
        """32. Malformed / truncated local-in block handling."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        self.assertEqual(parsed["local_in_policies"], [])
        self.assertEqual(analysis["local_in_assessments"], [])

    def test_33_secret_suppression(self):
        """33. Secret suppression in local-in policies."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set comments "User password should not be here"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        serialized = json.dumps(analysis)
        self.assertNotIn("SuperSecretPassword", serialized)

    def test_34_no_live_reachability_claims(self):
        """34. No live-reachability claims in local-in policy assessment."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["local_in_assessments"][0]
        text = assessment["assessment"]
        self.assertNotIn("live session", text.lower())
        self.assertNotIn("confirmed reachable", text.lower())
        self.assertNotIn("login succeeds", text.lower())
        self.assertNotIn("compromised", text.lower())

    def test_35_accept_followed_by_deny_no_effective_claim(self):
        """35. ACCEPT followed by DENY preserves sequence & facts without claiming final effective reachability state."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
    edit 2
        set intf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        p1 = analysis["local_in_assessments"][0]
        p2 = analysis["local_in_assessments"][1]
        self.assertEqual(p1["action"], "accept")
        self.assertEqual(p1["sequence_index"], 0)
        self.assertEqual(p2["action"], "deny")
        self.assertEqual(p2["sequence_index"], 1)

        self.assertNotIn("effective exposure", p1["assessment"].lower())
        self.assertNotIn("effective non-exposure", p2["assessment"].lower())
        self.assertNotIn("confirmed reachable", p1["assessment"].lower())

    def test_36_deny_followed_by_accept_no_effective_claim(self):
        """36. DENY followed by ACCEPT preserves sequence & facts without claiming final effective reachability state."""
        config_text = """
config firewall local-in-policy
    edit 1
        set intf "port1"
        set srcaddr "ADMIN_NET"
        set action deny
        set service "SSH"
    next
    edit 2
        set intf "port1"
        set srcaddr "all"
        set action accept
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        p1 = analysis["local_in_assessments"][0]
        p2 = analysis["local_in_assessments"][1]
        self.assertEqual(p1["action"], "deny")
        self.assertEqual(p1["sequence_index"], 0)
        self.assertEqual(p2["action"], "accept")
        self.assertEqual(p2["sequence_index"], 1)

        self.assertNotIn("proven effective non-exposure", p1["assessment"].lower())
        self.assertNotIn("confirmed reachable", p2["assessment"].lower())


if __name__ == "__main__":
    unittest.main()
