"""Regression tests for static route-based IPsec policy context."""

import json
import os
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import parse_configuration


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

BASE_CONFIG = '''
config system interface
 edit "lan"
  set role lan
 next
 edit "internal"
  set role internal
 next
 edit "dmz"
  set role dmz
 next
 edit "wan1"
  set role wan
 next
 edit "tunnel-a"
  set type tunnel
 next
 edit "tunnel-b"
  set type tunnel
 next
 edit "orphan-tunnel"
  set type tunnel
 next
end
config firewall address
 edit "LOCAL-NET"
  set subnet 10.0.0.0 255.255.255.0
 next
 edit "REMOTE-NET"
  set subnet 10.50.0.0 255.255.255.0
 next
end
config firewall service custom
 edit "APP-8443"
  set tcp-portrange 8443
 next
end
config antivirus profile
 edit "VPN-AV"
 next
end
config vpn ipsec phase1-interface
 edit "tunnel-a"
  set interface "wan1"
  set remote-gw 192.0.2.10
  set ike-version 2
  set proposal aes256-sha256
 next
 edit "tunnel-b"
  set interface "wan1"
  set remote-gw 192.0.2.20
  set ike-version 2
  set proposal aes256-sha256
 next
end
config vpn ipsec phase2-interface
 edit "tunnel-a-p2"
  set phase1name "tunnel-a"
  set src-subnet 10.0.0.0 255.255.255.0
  set dst-subnet 10.50.0.0 255.255.255.0
 next
end
config firewall policy
 edit 1
  set name "LAN to VPN"
  set srcintf "lan"
  set dstintf "tunnel-a"
  set srcaddr "LOCAL-NET"
  set dstaddr "REMOTE-NET"
  set service "APP-8443"
  set action accept
  set utm-status enable
  set av-profile "VPN-AV"
 next
 edit 2
  set name "VPN to LAN"
  set srcintf "tunnel-a"
  set dstintf "lan"
  set srcaddr "REMOTE-NET"
  set dstaddr "LOCAL-NET"
  set service "APP-8443"
  set action accept
 next
 edit 3
  set name "Internal to VPN"
  set srcintf "internal"
  set dstintf "tunnel-a"
  set srcaddr "LOCAL-NET"
  set dstaddr "REMOTE-NET"
  set service "HTTPS"
  set action accept
 next
 edit 4
  set name "VPN to DMZ"
  set srcintf "tunnel-a"
  set dstintf "dmz"
  set srcaddr "REMOTE-NET"
  set dstaddr "LOCAL-NET"
  set service "HTTPS"
  set action accept
 next
 edit 5
  set name "VPN Transit"
  set srcintf "tunnel-a"
  set dstintf "tunnel-b"
  set srcaddr "REMOTE-NET"
  set dstaddr "LOCAL-NET"
  set service "HTTPS"
  set action accept
 next
 edit 6
  set name "Missing Phase1"
  set srcintf "lan"
  set dstintf "orphan-tunnel"
  set srcaddr "LOCAL-NET"
  set dstaddr "REMOTE-NET"
  set service "HTTPS"
  set action accept
 next
 edit 7
  set name "Disabled VPN"
  set status disable
  set srcintf "lan"
  set dstintf "tunnel-a"
  set srcaddr "all"
  set dstaddr "all"
  set service "ALL"
  set action accept
 next
end
'''


class TestVPNContext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = parse_configuration(BASE_CONFIG)
        cls.analysis = analyze_configuration(cls.config)

    def policy(self, policy_id):
        return next(a for a in self.analysis["policy_assessments"] if a["policy_id"] == policy_id)

    def test_01_lan_to_route_based_ipsec(self):
        item = self.policy(1)
        self.assertEqual(item["traffic_direction"], "LAN -> VPN")
        self.assertEqual(item["flow_type"], "TO_VPN")
        self.assertEqual(item["purpose"], "Site-to-Site VPN Access")

    def test_02_ipsec_to_lan(self):
        item = self.policy(2)
        self.assertEqual(item["traffic_direction"], "VPN -> LAN")
        self.assertEqual(item["flow_type"], "FROM_VPN_INTERNAL")
        self.assertEqual(item["purpose"], "VPN-to-Internal Access")

    def test_03_internal_to_ipsec(self):
        item = self.policy(3)
        self.assertEqual(item["traffic_direction"], "INTERNAL -> VPN")
        self.assertEqual(item["purpose"], "Site-to-Site VPN Access")

    def test_04_ipsec_to_dmz(self):
        item = self.policy(4)
        self.assertEqual(item["traffic_direction"], "VPN -> DMZ")
        self.assertEqual(item["purpose"], "VPN-to-DMZ Access")

    def test_05_vpn_to_vpn(self):
        item = self.policy(5)
        self.assertEqual(item["traffic_direction"], "VPN -> VPN")
        self.assertEqual(item["flow_type"], "VPN_TRANSIT")
        self.assertEqual(item["purpose"], "VPN Transit Access")

    def test_06_phase1_object_resolution_metadata(self):
        context = self.policy(1)["destination_interfaces"][0]
        self.assertTrue(context["resolved"])
        self.assertEqual(context["type"], "vpn")
        self.assertEqual(context["source"], "ipsec_phase1")
        self.assertEqual(context["phase1_name"], "tunnel-a")
        self.assertEqual(context["parent_interface"], "wan1")
        self.assertEqual(context["remote_gateway"], "192.0.2.10")

    def test_07_missing_phase1_object_remains_unknown(self):
        context = self.policy(6)["destination_interfaces"][0]
        self.assertTrue(context["resolved"])
        self.assertEqual(context["role"], "UNKNOWN")
        self.assertEqual(context["type"], "interface")

    def test_08_physical_wan_under_ipsec_remains_wan(self):
        config = parse_configuration(BASE_CONFIG + '''
config firewall policy
 edit 100
  set srcintf "lan"
  set dstintf "wan1"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
end''')
        item = next(a for a in analyze_configuration(config)["policy_assessments"] if a["policy_id"] == 100)
        self.assertEqual(item["destination_interfaces"][0]["role"], "WAN")
        self.assertEqual(item["destination_interfaces"][0]["type"], "interface")

    def test_09_same_name_vpn_objects_are_vdom_isolated(self):
        text = '''config vdom
edit "A"
config system interface
 edit "shared-vpn"
  set type tunnel
 next
end
config vpn ipsec phase1-interface
 edit "shared-vpn"
  set interface "wan-a"
 next
end
config firewall policy
 edit 1
  set srcintf "shared-vpn"
  set dstintf "shared-vpn"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
end
next
edit "B"
config system interface
 edit "shared-vpn"
  set type tunnel
 next
 edit "a-only-vpn"
  set type tunnel
 next
end
config vpn ipsec phase1-interface
 edit "shared-vpn"
  set interface "wan-b"
 next
end
config firewall policy
 edit 1
  set srcintf "shared-vpn"
  set dstintf "a-only-vpn"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
end
next
end'''
        result = analyze_configuration(parse_configuration(text))["policy_assessments"]
        a, b = result
        self.assertEqual(a["source_interfaces"][0]["parent_interface"], "wan-a")
        self.assertEqual(b["source_interfaces"][0]["parent_interface"], "wan-b")
        self.assertEqual(b["destination_interfaces"][0]["role"], "UNKNOWN")

    def test_10_disabled_vpn_policy_behavior(self):
        item = self.policy(7)
        self.assertEqual(item["traffic_direction"], "LAN -> VPN")
        self.assertEqual(item["purpose"], "Disabled Policy")
        findings = [f for f in self.analysis["findings"] if f.get("policy_id") == 7]
        self.assertEqual([f["title"] for f in findings], ["Disabled Policy"])

    def test_11_vpn_policy_resolves_address_and_service_objects(self):
        item = self.policy(1)
        self.assertEqual(item["resolved_sources"][0]["subnet"], "10.0.0.0/24")
        self.assertEqual(item["resolved_destinations"][0]["subnet"], "10.50.0.0/24")
        self.assertEqual(item["resolved_services"][0]["type"], "custom_service")

    def test_12_vpn_policy_security_profile_resolution(self):
        profile = self.policy(1)["security_profiles"]["antivirus"]
        self.assertTrue(profile["attached"])
        self.assertTrue(profile["resolved"])

    def test_13_vpn_interface_does_not_trigger_wan_management(self):
        text = '''config system interface
edit "wan-vpn"
 set type tunnel
 set allowaccess http telnet https ssh
next
end
config vpn ipsec phase1-interface
edit "wan-vpn"
 set interface "wan1"
next
end'''
        config = parse_configuration(text)
        titles = {c["title"] for c in run_health_check(config)["checks"]}
        self.assertNotIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertNotIn("Telnet Management Exposed on WAN", titles)
        self.assertNotIn("Remote Management Accessible from WAN", titles)

    def test_14_existing_ipsec_health_findings_remain(self):
        with open(os.path.join(FIXTURES, "vpn.conf"), encoding="utf-8") as handle:
            checks = run_health_check(parse_configuration(handle.read()))["checks"]
        titles = {c["title"] for c in checks}
        self.assertTrue({
            "Legacy Cryptographic Algorithm Detected",
            "Legacy Diffie-Hellman Group Detected",
            "IKEv1 Configuration Detected",
            "Perfect Forward Secrecy Disabled",
            "Broad IPsec Traffic Selectors",
            "IPsec Phase 2 References Unknown Phase 1",
        } <= titles)

    def test_15_vpn_secret_suppression(self):
        text = BASE_CONFIG.replace(
            'set interface "wan1"\n  set remote-gw 192.0.2.10',
            'set interface "wan1"\n  set psksecret "FAKE-VPN-PSK"\n  set private-key "FAKE-VPN-KEY"\n  set remote-gw 192.0.2.10',
            1,
        )
        config = parse_configuration(text)
        public = json.dumps({
            "config": config,
            "analysis": analyze_configuration(config),
            "health": run_health_check(config),
        })
        self.assertNotIn("FAKE-VPN-PSK", public)
        self.assertNotIn("FAKE-VPN-KEY", public)

    def test_16_no_live_state_claims(self):
        public = json.dumps({
            "analysis": self.analysis,
            "health": run_health_check(self.config, self.analysis),
        }).casefold()
        for claim in (
            "tunnel is up",
            "tunnel is down",
            "peer is reachable",
            "remote subnet is reachable",
            "encryption is currently active",
            "traffic is currently passing",
            "vpn is healthy",
            "vpn is unhealthy",
        ):
            self.assertNotIn(claim, public)


if __name__ == "__main__":
    unittest.main()
