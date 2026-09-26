"""Unit tests for FortiGate Management Context Awareness."""

from __future__ import annotations

import unittest

from analyzer import analyze_configuration, classify_interface
from health_check import run_health_check
from parser import parse_configuration


class TestManagementContext(unittest.TestCase):
    """Verify explicit configuration indicators and precedence for Management Context."""

    def test_01_set_dedicated_to_management(self):
        """1. set dedicated-to management -> MANAGEMENT context."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["role_inferred"])
        self.assertTrue(res["management_context"]["is_management"])
        self.assertEqual(
            res["management_context"]["source"], "interface_dedicated_to"
        )

    def test_02_enabled_system_dedicated_mgmt(self):
        """2. enabled system dedicated-mgmt -> MANAGEMENT context."""
        config_text = """
config system interface
    edit "mgmt1"
    next
end
config system dedicated-mgmt
    set status enable
    set interface "mgmt1"
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["role_inferred"])
        self.assertTrue(res["management_context"]["is_management"])
        self.assertEqual(
            res["management_context"]["source"], "system_dedicated_mgmt"
        )

    def test_03_disabled_system_dedicated_mgmt(self):
        """3. disabled system dedicated-mgmt -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "mgmt1"
    next
end
config system dedicated-mgmt
    set status disable
    set interface "mgmt1"
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["management_context"]["is_management"])
        self.assertIsNone(res["management_context"]["source"])

    def test_04_enabled_ha_management_interface(self):
        """4. enabled HA management interface -> MANAGEMENT context."""
        config_text = """
config system interface
    edit "port5"
    next
end
config system ha
    set ha-mgmt-status enable
    config ha-mgmt-interfaces
        edit 1
            set interface "port5"
        next
    end
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["role_inferred"])
        self.assertTrue(res["management_context"]["is_management"])
        self.assertEqual(res["management_context"]["source"], "ha_management")

    def test_05_disabled_ha_mgmt_status(self):
        """5. disabled ha-mgmt-status -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "port5"
    next
end
config system ha
    set ha-mgmt-status disable
    config ha-mgmt-interfaces
        edit 1
            set interface "port5"
        next
    end
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["management_context"]["is_management"])

    def test_06_heartbeat_interface(self):
        """6. heartbeat interface -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "port8"
        set alias "HA heartbeat link"
    next
end
config system ha
    set hbdev "port8" 50
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["management_context"]["is_management"])

    def test_07_interface_named_mgmt_only(self):
        """7. interface named 'mgmt' only -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "mgmt"
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertEqual(res["role"], "UNKNOWN")
        self.assertFalse(res["management_context"]["is_management"])

    def test_08_alias_containing_management_only(self):
        """8. alias containing 'management' only -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "port2"
        set alias "management network"
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["management_context"]["is_management"])

    def test_09_interface_named_admin_only(self):
        """9. interface named 'admin' only -> not MANAGEMENT."""
        config_text = """
config system interface
    edit "admin-port"
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertNotEqual(res["role"], "MANAGEMENT")
        self.assertFalse(res["management_context"]["is_management"])

    def test_10_allowaccess_https_ssh_only(self):
        """10. allowaccess HTTPS/SSH only -> existing role preserved."""
        config_text = """
config system interface
    edit "port1"
        set role lan
        set allowaccess ping https ssh
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "LAN")
        self.assertEqual(res["configured_role"], "lan")
        self.assertFalse(res["management_context"]["is_management"])

    def test_11_management_vdom_only(self):
        """11. management-vdom only -> role unchanged."""
        config_text = """
config system global
    set management-vdom "root"
end
config system interface
    edit "port1"
        set role lan
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "LAN")
        self.assertEqual(res["configured_role"], "lan")
        self.assertFalse(res["management_context"]["is_management"])

    def test_12_management_evidence_overrides_configured_role(self):
        """12. MANAGEMENT explicit evidence overrides normal role inference while preserving configured role."""
        config_text = """
config system interface
    edit "port1"
        set role wan
        set dedicated-to management
    next
end
"""
        parsed = parse_configuration(config_text)
        res = classify_interface(parsed["interfaces"][0], config=parsed)
        self.assertEqual(res["role"], "MANAGEMENT")
        self.assertEqual(res["configured_role"], "wan")
        self.assertFalse(res["role_inferred"])
        self.assertTrue(res["management_context"]["is_management"])
        self.assertEqual(
            res["management_context"]["source"], "interface_dedicated_to"
        )

    def test_13_homogeneous_management_system_zone(self):
        """13. homogeneous MANAGEMENT system zone -> MANAGEMENT."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
    edit "port2"
        set dedicated-to management
    next
end
config system zone
    edit "mgmt-zone"
        set interface "port1" "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "mgmt-zone"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_zone = assessment["source_interfaces"][0]
        self.assertEqual(src_zone["role"], "MANAGEMENT")
        self.assertTrue(src_zone["management_context"]["is_management"])
        self.assertEqual(
            src_zone["management_context"]["source"], "system_zone_derived"
        )

    def test_14_management_and_wan_zone(self):
        """14. MANAGEMENT + WAN zone -> UNKNOWN."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
    edit "port2"
        set role wan
    next
end
config system zone
    edit "mixed-zone"
        set interface "port1" "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "mixed-zone"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_zone = assessment["source_interfaces"][0]
        self.assertEqual(src_zone["role"], "UNKNOWN")
        self.assertFalse(src_zone["management_context"]["is_management"])

    def test_15_management_and_lan_zone(self):
        """15. MANAGEMENT + LAN zone -> UNKNOWN."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
    edit "port2"
        set role lan
    next
end
config system zone
    edit "mixed-zone"
        set interface "port1" "port2"
    next
end
config firewall policy
    edit 1
        set srcintf "mixed-zone"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_zone = assessment["source_interfaces"][0]
        self.assertEqual(src_zone["role"], "UNKNOWN")

    def test_16_management_and_vpn_zone(self):
        """16. MANAGEMENT + VPN zone -> UNKNOWN."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
end
config vpn ipsec phase1-interface
    edit "ipsec1"
        set interface "port1"
    next
end
config system zone
    edit "mixed-zone"
        set interface "port1" "ipsec1"
    next
end
config firewall policy
    edit 1
        set srcintf "mixed-zone"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_zone = assessment["source_interfaces"][0]
        self.assertEqual(src_zone["role"], "UNKNOWN")

    def test_17_management_and_unresolved_zone_member(self):
        """17. MANAGEMENT + unresolved zone member -> UNKNOWN."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
end
config system zone
    edit "mixed-zone"
        set interface "port1" "nonexistent"
    next
end
config firewall policy
    edit 1
        set srcintf "mixed-zone"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        src_zone = assessment["source_interfaces"][0]
        self.assertEqual(src_zone["role"], "UNKNOWN")

    def test_18_wan_to_management_policy(self):
        """18. WAN -> MANAGEMENT policy."""
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
    edit "port2"
        set dedicated-to management
    next
end
config firewall policy
    edit 10
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "SSH"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "TO_MANAGEMENT")
        self.assertEqual(assessment["purpose"], "Management Network Access")

    def test_19_lan_to_management_policy(self):
        """19. LAN -> MANAGEMENT policy."""
        config_text = """
config system interface
    edit "port1"
        set role lan
    next
    edit "port2"
        set dedicated-to management
    next
end
config firewall policy
    edit 11
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "TO_MANAGEMENT")
        self.assertEqual(assessment["purpose"], "Management Network Access")

    def test_20_management_to_wan_policy(self):
        """20. MANAGEMENT -> WAN policy."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
    edit "port2"
        set role wan
    next
end
config firewall policy
    edit 12
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "FROM_MANAGEMENT")
        self.assertEqual(assessment["purpose"], "Management-to-Network Access")

    def test_21_management_to_management_policy(self):
        """21. MANAGEMENT -> MANAGEMENT policy."""
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
    next
    edit "mgmt2"
        set dedicated-to management
    next
end
config firewall policy
    edit 13
        set srcintf "mgmt1"
        set dstintf "mgmt2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        self.assertEqual(assessment["flow_type"], "MANAGEMENT_TRANSIT")
        self.assertEqual(assessment["purpose"], "Management Transit Access")

    def test_22_vdom_isolation(self):
        """22. VDOM isolation for management evidence."""
        config_text = """
config vdom
    edit "VDOM-A"
        config system interface
            edit "port1"
                set dedicated-to management
            next
        end
    next
    edit "VDOM-B"
        config system interface
            edit "port1"
                set role lan
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)
        intf_a = next(i for i in parsed["interfaces"] if i.get("vdom") == "VDOM-A")
        intf_b = next(i for i in parsed["interfaces"] if i.get("vdom") == "VDOM-B")

        res_a = classify_interface(intf_a, config=parsed)
        res_b = classify_interface(intf_b, config=parsed)

        self.assertEqual(res_a["role"], "MANAGEMENT")
        self.assertTrue(res_a["management_context"]["is_management"])

        self.assertEqual(res_b["role"], "LAN")
        self.assertFalse(res_b["management_context"]["is_management"])

    def test_23_management_interface_does_not_trigger_wan_management_findings(self):
        """23. MANAGEMENT interface does not trigger WAN management findings."""
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
        set allowaccess http telnet https ssh
    next
end
"""
        parsed = parse_configuration(config_text)
        results = run_health_check(parsed)
        titles = [r["title"] for r in results["checks"]]
        self.assertNotIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertNotIn("Telnet Management Exposed on WAN", titles)
        self.assertNotIn("Remote Management Accessible from WAN", titles)

    def test_24_real_wan_interface_still_triggers_findings(self):
        """24. Real WAN interface still triggers existing findings."""
        config_text = """
config system interface
    edit "wan1"
        set role wan
        set allowaccess http telnet
    next
end
"""
        parsed = parse_configuration(config_text)
        results = run_health_check(parsed)
        titles = [r["title"] for r in results["checks"]]
        self.assertIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertIn("Telnet Management Exposed on WAN", titles)

    def test_25_trusted_host_wan_behavior_remains_unchanged(self):
        """25. trusted-host WAN behavior remains unchanged."""
        config_text = """
config system interface
    edit "wan1"
        set role wan
        set allowaccess https
    next
end
config system admin
    edit "admin"
        set trusthost1 0.0.0.0 0.0.0.0
    next
end
"""
        parsed = parse_configuration(config_text)
        results = run_health_check(parsed)
        titles = [r["title"] for r in results["checks"]]
        self.assertIn(
            "Administrative Access Lacks Trusted Host Restrictions", titles
        )

    def test_26_secret_suppression(self):
        """26. secret suppression in parsed HA management config."""
        config_text = """
config system ha
    set ha-mgmt-status enable
    set password "SuperSecretPassword123"
    set psksecret "SuperSecretPSK123"
    config ha-mgmt-interfaces
        edit 1
            set interface "port5"
        next
    end
end
"""
        parsed = parse_configuration(config_text)
        ha_info = parsed["ha_management"]
        self.assertTrue(ha_info["enabled"])
        self.assertIn("port5", ha_info["interfaces"])

        raw_str = str(parsed["ha_mgmt"])
        self.assertNotIn("SuperSecretPassword123", raw_str)
        self.assertNotIn("SuperSecretPSK123", raw_str)

    def test_27_no_live_state_reachability_claims(self):
        """27. static policy interpretation only; no live-state/reachability claims."""
        config_text = """
config system interface
    edit "port1"
        set dedicated-to management
    next
    edit "port2"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""
        parsed = parse_configuration(config_text)
        analysis = analyze_configuration(parsed)
        assessment = analysis["policy_assessments"][0]
        text = assessment["assessment"]

        self.assertNotIn("live session", text.lower())
        self.assertNotIn("reachable", text.lower())
        self.assertNotIn("proven access", text.lower())
        self.assertNotIn("authenticated", text.lower())


if __name__ == "__main__":
    unittest.main()
