"""Golden regression coverage for VPN-aware system-zone resolution."""

import json
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import parse_configuration


ZONE_CONFIG = '''
config system interface
 edit "lan"
  set role lan
 next
 edit "dmz"
  set role dmz
 next
 edit "wan"
  set role wan
 next
 edit "vpn1"
  set type tunnel
 next
 edit "vpn2"
  set type tunnel
 next
 edit "orphan"
  set type tunnel
 next
end
config vpn ipsec phase1-interface
 edit "vpn1"
  set interface "wan"
  set ike-version 2
  set proposal aes256-sha256
 next
 edit "vpn2"
  set interface "wan"
  set ike-version 2
  set proposal 3des-sha1
 next
end
config system zone
 edit "TUNNEL-POOL"
  set interface "vpn1" "vpn2"
 next
 edit "TUNNEL-POOL-2"
  set interface "vpn2"
 next
 edit "VPN-WAN-MIX"
  set interface "vpn1" "wan"
 next
 edit "VPN-LAN-MIX"
  set interface "vpn1" "lan"
 next
 edit "VPN-UNKNOWN-MIX"
  set interface "vpn1" "orphan"
 next
 edit "VPN-NAME-ONLY"
  set interface "lan"
 next
end
config firewall policy
 edit 1
  set srcintf "lan"
  set dstintf "TUNNEL-POOL"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 2
  set srcintf "TUNNEL-POOL"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 3
  set srcintf "TUNNEL-POOL"
  set dstintf "dmz"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 4
  set srcintf "TUNNEL-POOL"
  set dstintf "TUNNEL-POOL-2"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 5
  set srcintf "VPN-WAN-MIX"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 6
  set srcintf "VPN-LAN-MIX"
  set dstintf "dmz"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 7
  set srcintf "VPN-UNKNOWN-MIX"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
 edit 8
  set srcintf "VPN-NAME-ONLY"
  set dstintf "dmz"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
end
'''


class TestVPNZones(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = parse_configuration(ZONE_CONFIG)
        cls.analysis = analyze_configuration(cls.config)

    def policy(self, policy_id):
        return next(
            item
            for item in self.analysis["policy_assessments"]
            if item["policy_id"] == policy_id
        )

    def test_01_zone_with_two_vpn_members_resolves_as_vpn(self):
        context = self.policy(1)["destination_interfaces"][0]
        self.assertEqual(context["type"], "zone")
        self.assertEqual(context["role"], "VPN")
        self.assertTrue(context["resolved"])
        self.assertEqual(
            [member["role"] for member in context["member_contexts"]],
            ["VPN", "VPN"],
        )

    def test_02_lan_to_vpn_zone(self):
        item = self.policy(1)
        self.assertEqual(item["traffic_direction"], "LAN -> VPN")
        self.assertEqual(item["flow_type"], "TO_VPN")
        self.assertEqual(item["purpose"], "Site-to-Site VPN Access")

    def test_03_vpn_zone_to_lan(self):
        item = self.policy(2)
        self.assertEqual(item["traffic_direction"], "VPN -> LAN")
        self.assertEqual(item["purpose"], "VPN-to-Internal Access")

    def test_04_vpn_zone_to_dmz(self):
        item = self.policy(3)
        self.assertEqual(item["traffic_direction"], "VPN -> DMZ")
        self.assertEqual(item["purpose"], "VPN-to-DMZ Access")

    def test_05_vpn_zone_to_vpn_zone(self):
        item = self.policy(4)
        self.assertEqual(item["traffic_direction"], "VPN -> VPN")
        self.assertEqual(item["flow_type"], "VPN_TRANSIT")
        self.assertEqual(item["purpose"], "VPN Transit Access")

    def test_06_vpn_and_wan_mixed_zone_remains_unknown(self):
        context = self.policy(5)["source_interfaces"][0]
        self.assertEqual(context["role"], "UNKNOWN")
        self.assertEqual(self.policy(5)["flow_type"], "UNKNOWN")

    def test_07_vpn_and_lan_mixed_zone_remains_unknown(self):
        context = self.policy(6)["source_interfaces"][0]
        self.assertEqual(context["role"], "UNKNOWN")
        self.assertEqual(self.policy(6)["purpose"], "Custom / Unknown Access")

    def test_08_vpn_and_unresolved_context_remains_unknown(self):
        context = self.policy(7)["source_interfaces"][0]
        self.assertEqual(context["role"], "UNKNOWN")
        self.assertTrue(any(member["role"] == "UNKNOWN" for member in context["member_contexts"]))

    def test_09_zone_name_does_not_create_vpn_role(self):
        context = self.policy(8)["source_interfaces"][0]
        self.assertEqual(context["name"], "VPN-NAME-ONLY")
        self.assertEqual(context["role"], "LAN")
        self.assertNotEqual(context["role"], "VPN")

    def test_10_vdom_isolation_for_vpn_zone_members(self):
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
config system zone
 edit "VPN-ZONE"
  set interface "shared-vpn"
 next
end
config firewall policy
 edit 1
  set srcintf "VPN-ZONE"
  set dstintf "VPN-ZONE"
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
end
config system zone
 edit "VPN-ZONE"
  set interface "shared-vpn"
 next
end
config firewall policy
 edit 1
  set srcintf "VPN-ZONE"
  set dstintf "VPN-ZONE"
  set srcaddr "all"
  set dstaddr "all"
  set service "HTTPS"
  set action accept
 next
end
next
end'''
        result = analyze_configuration(parse_configuration(text))["policy_assessments"]
        a = next(item for item in result if item["vdom"] == "A")
        b = next(item for item in result if item["vdom"] == "B")
        self.assertEqual(a["source_interfaces"][0]["role"], "VPN")
        self.assertEqual(b["source_interfaces"][0]["role"], "UNKNOWN")

    def test_11_vpn_zone_health_and_static_ipsec_checks(self):
        health = run_health_check(self.config, self.analysis)
        titles = {item["title"] for item in health["checks"]}
        self.assertIn("Legacy Cryptographic Algorithm Detected", titles)
        self.assertNotIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertNotIn("Telnet Management Exposed on WAN", titles)
        self.assertNotIn("Remote Management Accessible from WAN", titles)
        self.assertNotIn("IPS Not Detected on Internet-Facing Policy", titles)

    def test_12_no_live_state_or_routing_claims(self):
        public = json.dumps(
            {
                "analysis": self.analysis,
                "health": run_health_check(self.config, self.analysis),
            }
        ).casefold()
        for claim in (
            "tunnel is up",
            "peer is reachable",
            "routing exists",
            "remote network is reachable",
            "traffic is passing",
        ):
            self.assertNotIn(claim, public)


if __name__ == "__main__":
    unittest.main()
