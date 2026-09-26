"""Tests for FortiOS SSL-VPN static configuration analysis."""

import json
import unittest

from analyzer import analyze_configuration
from health_check import run_health_check
from parser import (
    parse_configuration,
    parse_ssl_vpn_portals,
    parse_ssl_vpn_settings,
    parse_user_groups,
    parse_user_locals,
)


class TestSSLVPNAnalysis(unittest.TestCase):
    def test_01_basic_ssl_vpn_enabled(self):
        config_text = """
config system interface
    edit "wan1"
        set role wan
    next
end
config vpn ssl settings
    set status enable
    set source-interface "wan1"
    set port 10443
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        self.assertEqual(len(config["ssl_vpn_settings"]), 1)
        self.assertEqual(len(analysis["ssl_vpn_assessments"]), 1)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["status"], "ENABLED")
        self.assertEqual(str(assessment["port"]), "10443")
        self.assertEqual(len(assessment["source_interfaces"]), 1)
        self.assertEqual(assessment["source_interfaces"][0]["name"], "wan1")
        self.assertEqual(assessment["source_interfaces"][0]["role"], "WAN")

    def test_02_disabled_ssl_vpn_settings(self):
        config_text = """
config vpn ssl settings
    set status disable
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["status"], "DISABLED")
        self.assertEqual(assessment["configured_facts"]["status"], "disable")

    def test_03_missing_status_is_not_observed(self):
        config_text = """
config vpn ssl settings
    set port 443
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["status"], "NOT_OBSERVED")
        self.assertIsNone(assessment["configured_facts"]["status"])

    def test_04_listening_interface_wan_resolved(self):
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
end
config vpn ssl settings
    set status enable
    set source-interface "port1"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        intf = assessment["source_interfaces"][0]
        self.assertEqual(intf["name"], "port1")
        self.assertEqual(intf["role"], "WAN")
        self.assertTrue(intf["resolved"])

    def test_05_listening_interface_management_resolved(self):
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
    next
end
config vpn ssl settings
    set status enable
    set source-interface "mgmt1"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        intf = assessment["source_interfaces"][0]
        self.assertEqual(intf["name"], "mgmt1")
        self.assertEqual(intf["role"], "MANAGEMENT")
        self.assertTrue(intf["resolved"])

    def test_06_listening_interface_unknown_unresolved(self):
        config_text = """
config vpn ssl settings
    set status enable
    set source-interface "ghost_wan"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        assessment = analysis["ssl_vpn_assessments"][0]
        intf = assessment["source_interfaces"][0]
        self.assertEqual(intf["name"], "ghost_wan")
        self.assertFalse(intf["resolved"])

        # Health check catches unresolved listening interface on enabled SSL-VPN
        integrity_checks = [c for c in health["checks"] if "Configuration References Could Not Be Fully Resolved" in c.get("title", "")]
        self.assertTrue(len(integrity_checks) >= 1)
        evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
        self.assertTrue(any("ghost_wan" in e for e in evidence))

    def test_07_multiple_listening_interfaces(self):
        config_text = """
config system interface
    edit "wan1"
        set role wan
    next
    edit "wan2"
        set role wan
    next
end
config vpn ssl settings
    set status enable
    set source-interface "wan1" "wan2"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(len(assessment["source_interfaces"]), 2)
        names = [i["name"] for i in assessment["source_interfaces"]]
        self.assertIn("wan1", names)
        self.assertIn("wan2", names)

    def test_08_source_address_resolved(self):
        config_text = """
config firewall address
    edit "Allowed_Remote_IPs"
        set subnet 203.0.113.0 255.255.255.0
    next
end
config vpn ssl settings
    set status enable
    set source-address "Allowed_Remote_IPs"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        srcs = assessment["source_addresses"]
        self.assertEqual(len(srcs), 1)
        self.assertEqual(srcs[0]["name"], "Allowed_Remote_IPs")
        self.assertEqual(srcs[0]["type"], "address")

    def test_09_broad_source_address_all_is_configuration_fact_no_finding(self):
        config_text = """
config firewall address
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config vpn ssl settings
    set status enable
    set source-address "all"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(len(assessment["source_addresses"]), 1)
        self.assertEqual(assessment["source_addresses"][0]["name"], "all")
        # Broad source address "all" is standard FortiGate SSL-VPN default, NOT a finding
        findings = [f for f in analysis["findings"] if "ssl" in f.get("title", "").lower()]
        self.assertEqual(len(findings), 0)
        ssl_health_warnings = [
            c for c in health["checks"]
            if "ssl" in c.get("title", "").lower() and c.get("severity") in {"HIGH", "CRITICAL"}
        ]
        self.assertEqual(len(ssl_health_warnings), 0)

    def test_10_unresolved_source_address(self):
        config_text = """
config vpn ssl settings
    set status enable
    set source-address "Missing_Address_Obj"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["source_addresses"][0]["type"], "unknown")

        integrity_checks = [c for c in health["checks"] if "Configuration References Could Not Be Fully Resolved" in c.get("title", "")]
        self.assertTrue(len(integrity_checks) >= 1)
        evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
        self.assertTrue(any("Missing_Address_Obj" in e for e in evidence))

    def test_11_port_parsing_and_preservation(self):
        config_text = """
config vpn ssl settings
    set port 8443
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(str(assessment["port"]), "8443")
        self.assertEqual(assessment["configured_facts"]["port"], "8443")

    def test_12_server_cert_reference(self):
        config_text = """
config vpn ssl settings
    set servercert "My_Company_Wildcard"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["servercert"], "My_Company_Wildcard")

    def test_13_minimum_tls_version(self):
        config_text = """
config vpn ssl settings
    set ssl-min-proto-ver tls1-3
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertEqual(assessment["ssl_min_proto_ver"], "tls1-3")
        self.assertEqual(assessment["min_tls_version"], "tls1-3")

    def test_14_tls_crypto_inventory(self):
        config_text = """
config vpn ssl settings
    set banned-cipher SHA1 3DES
    set ciphersuite TLS-AES-256-GCM-SHA384
    set dtls-tunnel enable
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        self.assertIn("SHA1", assessment["banned_cipher"])
        self.assertEqual(assessment["ciphersuite"], "TLS-AES-256-GCM-SHA384")
        self.assertEqual(assessment["dtls_tunnel"], "enable")

    def test_15_tunnel_mode_portal_split_tunnel_and_pools(self):
        config_text = """
config firewall address
    edit "Corporate_LAN"
        set subnet 10.10.0.0 255.255.0.0
    next
    edit "VPN_Pool_Range"
        set type iprange
        set start-ip 10.212.134.1
        set end-ip 10.212.134.100
    next
end
config vpn ssl web portal
    edit "tunnel-only"
        set tunnel-mode enable
        set web-mode disable
        set split-tunneling enable
        set split-tunneling-routing-address "Corporate_LAN"
        set ip-pools "VPN_Pool_Range"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        portals = parse_ssl_vpn_portals(config_text)
        self.assertEqual(len(portals), 1)
        p = portals[0]
        self.assertEqual(p["name"], "tunnel-only")
        self.assertEqual(p["tunnel-mode"], "enable")
        self.assertEqual(p["split-tunneling"], "enable")
        self.assertEqual(p["split-tunneling-routing-address"], ["Corporate_LAN"])
        self.assertEqual(p["ip-pools"], ["VPN_Pool_Range"])

    def test_16_tunnel_mode_portal_split_tunnel_disabled(self):
        config_text = """
config vpn ssl web portal
    edit "full-tunnel"
        set tunnel-mode enable
        set web-mode disable
        set split-tunneling disable
    next
end
"""
        config = parse_configuration(config_text)
        portals = parse_ssl_vpn_portals(config_text)
        p = portals[0]
        self.assertEqual(p["split-tunneling"], "disable")

    def test_17_web_mode_only_portal(self):
        config_text = """
config vpn ssl web portal
    edit "web-only"
        set tunnel-mode disable
        set web-mode enable
    next
end
config vpn ssl settings
    set status enable
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        portal = assessment["portals"][0]
        self.assertEqual(portal["tunnel_mode"], "DISABLED")
        self.assertEqual(portal["web_mode"], "ENABLED")
        self.assertEqual(portal["mode_summary"], "WEB")

    def test_18_dual_mode_portal(self):
        config_text = """
config vpn ssl web portal
    edit "dual"
        set tunnel-mode enable
        set web-mode enable
    next
end
config vpn ssl settings
    set status enable
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        portal = analysis["ssl_vpn_assessments"][0]["portals"][0]
        self.assertEqual(portal["mode_summary"], "DUAL_MODE")

    def test_19_disabled_portal(self):
        config_text = """
config vpn ssl web portal
    edit "dormant"
        set tunnel-mode disable
        set web-mode disable
    next
end
config vpn ssl settings
    set status enable
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        portal = analysis["ssl_vpn_assessments"][0]["portals"][0]
        self.assertEqual(portal["mode_summary"], "DISABLED")

    def test_20_builtin_portals_resolved_as_builtin(self):
        for builtin_name in ["full-access", "web-access", "tunnel-access", "FULL-ACCESS", "Web-Access"]:
            config_text = f"""
config vpn ssl settings
    set status enable
    set default-portal "{builtin_name}"
end
"""
            config = parse_configuration(config_text)
            analysis = analyze_configuration(config)
            health = run_health_check(config, analysis)
            assessment = analysis["ssl_vpn_assessments"][0]
            dp = assessment["default_portal_resolution"]
            self.assertTrue(dp["resolved"], f"Builtin {builtin_name} should resolve as True")
            self.assertEqual(dp["source"], "builtin")

            # Must NEVER be flagged as unresolved in health checks
            integrity_checks = [c for c in health["checks"] if "Configuration References Could Not Be Fully Resolved" in c.get("title", "")]
            evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
            self.assertFalse(any(builtin_name.lower() in e.lower() for e in evidence))

    def test_21_custom_portal_overrides_or_resolves_as_custom(self):
        config_text = """
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set web-mode enable
    next
end
config vpn ssl settings
    set status enable
    set default-portal "full-access"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessment = analysis["ssl_vpn_assessments"][0]
        dp = assessment["default_portal_resolution"]
        self.assertTrue(dp["resolved"])
        self.assertEqual(dp["source"], "custom")

    def test_22_missing_default_portal_unresolved(self):
        config_text = """
config vpn ssl settings
    set status enable
    set default-portal "completely-nonexistent-portal"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        assessment = analysis["ssl_vpn_assessments"][0]
        dp = assessment["default_portal_resolution"]
        self.assertFalse(dp["resolved"])
        self.assertEqual(dp["source"], "unresolved")

        integrity_checks = [c for c in health["checks"] if "Configuration References Could Not Be Fully Resolved" in c.get("title", "")]
        evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
        self.assertTrue(any("completely-nonexistent-portal" in e for e in evidence))

    def test_23_auth_rule_ordering_and_sequence_index(self):
        config_text = """
config vpn ssl settings
    set status enable
    config authentication-rule
        edit 10
            set portal "full-access"
        next
        edit 20
            set portal "web-access"
        next
    end
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        rules = analysis["ssl_vpn_assessments"][0]["authentication_rules"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["id"], 10)
        self.assertEqual(rules[0]["sequence_index"], 0)
        self.assertEqual(rules[1]["id"], 20)
        self.assertEqual(rules[1]["sequence_index"], 1)

    def test_24_auth_rule_group_resolution(self):
        config_text = """
config user group
    edit "Finance_Dept"
    next
end
config vpn ssl settings
    set status enable
    config authentication-rule
        edit 1
            set groups "Finance_Dept"
            set portal "full-access"
        next
    end
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        rule = analysis["ssl_vpn_assessments"][0]["authentication_rules"][0]
        self.assertTrue(rule["resolved_groups"][0]["resolved"])
        self.assertEqual(rule["resolved_groups"][0]["name"], "Finance_Dept")

    def test_25_auth_rule_user_resolution(self):
        config_text = """
config user local
    edit "alice"
        set type password
    next
end
config vpn ssl settings
    set status enable
    config authentication-rule
        edit 1
            set users "alice"
            set portal "full-access"
        next
    end
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        rule = analysis["ssl_vpn_assessments"][0]["authentication_rules"][0]
        self.assertTrue(rule["resolved_users"][0]["resolved"])
        self.assertEqual(rule["resolved_users"][0]["name"], "alice")

    def test_26_auth_rule_unresolved_group_and_portal(self):
        config_text = """
config vpn ssl settings
    set status enable
    config authentication-rule
        edit 1
            set groups "Ghost_Group"
            set portal "ghost-portal"
        next
    end
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        rule = analysis["ssl_vpn_assessments"][0]["authentication_rules"][0]
        self.assertFalse(rule["resolved_groups"][0]["resolved"])
        self.assertFalse(rule["portal_resolution"]["resolved"])

        integrity_checks = [c for c in health["checks"] if "Configuration References Could Not Be Fully Resolved" in c.get("title", "")]
        evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
        self.assertTrue(any("Ghost_Group" in e for e in evidence))
        self.assertTrue(any("ghost-portal" in e for e in evidence))

    def test_27_auth_rule_source_interface_and_address(self):
        config_text = """
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall address
    edit "Branch_Office"
        set subnet 198.51.100.0 255.255.255.0
    next
end
config vpn ssl settings
    set status enable
    config authentication-rule
        edit 1
            set source-interface "wan1"
            set source-address "Branch_Office"
            set portal "full-access"
        next
    end
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        rule = analysis["ssl_vpn_assessments"][0]["authentication_rules"][0]
        self.assertTrue(rule["source_interfaces"][0]["resolved"])
        self.assertEqual(rule["source_interfaces"][0]["name"], "wan1")
        self.assertEqual(rule["source_addresses"][0]["type"], "address")

    def test_28_multivdom_portal_and_group_isolation(self):
        config_text = """
config vdom
    edit "VDOM1"
        config user group
            edit "VPN_Users"
            next
        end
        config vpn ssl web portal
            edit "custom-portal"
                set tunnel-mode enable
            next
        end
        config vpn ssl settings
            set status enable
            config authentication-rule
                edit 1
                    set groups "VPN_Users"
                    set portal "custom-portal"
                next
            end
        end
    next
    edit "VDOM2"
        config vpn ssl settings
            set status enable
            config authentication-rule
                edit 1
                    set groups "VPN_Users"
                    set portal "custom-portal"
                next
            end
        end
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessments = analysis["ssl_vpn_assessments"]
        self.assertEqual(len(assessments), 2)

        vdom1_a = next(a for a in assessments if a["vdom"] == "VDOM1")
        vdom2_a = next(a for a in assessments if a["vdom"] == "VDOM2")

        # In VDOM1, both resolve
        rule1 = vdom1_a["authentication_rules"][0]
        self.assertTrue(rule1["resolved_groups"][0]["resolved"])
        self.assertTrue(rule1["portal_resolution"]["resolved"])
        self.assertEqual(rule1["portal_resolution"]["source"], "custom")

        # In VDOM2, both remain unresolved (no cross-VDOM leakage!)
        rule2 = vdom2_a["authentication_rules"][0]
        self.assertFalse(rule2["resolved_groups"][0]["resolved"])
        self.assertFalse(rule2["portal_resolution"]["resolved"])

    def test_29_partial_configuration_ssl_vpn_status(self):
        config_text = """
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set action accept
    next
end
"""
        config = parse_configuration(config_text)
        assessment = config["input_assessment"]
        self.assertEqual(assessment["classification"], "PARTIAL_CONFIGURATION")
        self.assertFalse(assessment["section_presence"]["ssl_vpn_settings"])
        self.assertEqual(assessment["analysis_scope"]["ssl_vpn"]["status"], "UNAVAILABLE_NOT_SUPPLIED")

    def test_30_likely_full_backup_without_ssl_vpn_is_unobserved_not_incomplete(self):
        config_text = """#config-version=FG100F-7.2.5-build1517:00000000
config system global
    set hostname "FullFW"
end
config system admin
    edit "admin"
    next
end
config system interface
    edit "wan1"
        set role wan
    next
    edit "lan1"
        set role lan
    next
end
config firewall policy
    edit 1
        set srcintf "lan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        config = parse_configuration(config_text)
        assessment = config["input_assessment"]
        self.assertEqual(assessment["classification"], "LIKELY_FULL_BACKUP")
        self.assertFalse(assessment["section_presence"]["ssl_vpn_settings"])
        # Unused SSL-VPN in full backup must be UNOBSERVED_IN_INPUT, NOT marked incomplete!
        self.assertEqual(assessment["analysis_scope"]["ssl_vpn"]["status"], "UNOBSERVED_IN_INPUT")

    def test_31_malformed_truncated_block_tolerance(self):
        config_text = """
config vpn ssl settings
    set status enable
    set port 10443
    config authentication-rule
        edit 1
            set portal "tunnel-access"
"""
        # Missing next, end, end - parser must not crash
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        self.assertIn("ssl_vpn_settings", config)
        self.assertEqual(len(config["ssl_vpn_settings"]), 1)
        self.assertEqual(len(analysis["ssl_vpn_assessments"]), 1)

    def test_32_user_local_password_and_secret_suppression(self):
        config_text = """
config user local
    edit "admin_bob"
        set type password
        set passwd ENC 3xAmPlEhAsH123456789
        set two-factor email
        set comments "Admin user"
    next
    edit "api_user"
        set type password
        set password "supersecret123"
    next
end
"""
        locals_parsed = parse_user_locals(config_text)
        self.assertEqual(len(locals_parsed), 2)
        for u in locals_parsed:
            self.assertNotIn("passwd", u)
            self.assertNotIn("password", u)
            self.assertNotIn("secret", u)
            self.assertNotIn("hash", u)
        # Ensure allowed non-secret fields are preserved
        bob = next(u for u in locals_parsed if u["name"] == "admin_bob")
        self.assertEqual(bob["type"], "password")
        self.assertEqual(bob["two-factor"], "email")
        self.assertEqual(bob["comments"], "Admin user")

    def test_33_forwarding_policy_referencing_ssl_root_is_separate(self):
        config_text = """
config system interface
    edit "lan1"
        set role lan
    next
end
config vpn ssl settings
    set status enable
    set default-portal "full-access"
end
config firewall policy
    edit 42
        set srcintf "ssl.root"
        set dstintf "lan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        self.assertEqual(len(analysis["ssl_vpn_assessments"]), 1)
        self.assertEqual(len(analysis["policy_assessments"]), 1)
        p = analysis["policy_assessments"][0]
        self.assertEqual(p["policy_id"], 42)
        self.assertEqual(p["source_interfaces"][0]["name"], "ssl.root")
        self.assertEqual(p["destination_interfaces"][0]["name"], "lan1")
        self.assertEqual(analysis["ssl_vpn_assessments"][0]["technical_context"], "SSL_VPN_REMOTE_ACCESS")
        self.assertEqual(analysis["ssl_vpn_assessments"][0]["purpose"], "SSL-VPN Remote Access Configuration")
        self.assertNotEqual(analysis["ssl_vpn_assessments"][0]["technical_context"], p.get("technical_context"))

    def test_34_strict_negative_non_claims(self):
        config_text = """
config system interface
    edit "wan1"
        set role wan
    next
end
config vpn ssl settings
    set status enable
    set source-interface "wan1"
    set port 10443
    set default-portal "full-access"
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        serialized = json.dumps({"config": config, "analysis": analysis, "health": health}).casefold()
        self.assertNotIn("confirmed reachable", serialized)
        self.assertNotIn("proven effective reachability", serialized)
        self.assertNotIn("proven effective non-exposure", serialized)
        self.assertNotIn("active session", serialized)
        self.assertNotIn("successful authentication", serialized)
        self.assertNotIn("live tunnel", serialized)
        self.assertNotIn("internet reachable", serialized)

    def test_35_user_group_parsing_and_isolation(self):
        config_text = """
config user group
    edit "Engineering"
        set member "alice" "bob"
        set comments "Engineering Team"
    next
end
"""
        groups = parse_user_groups(config_text)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["name"], "Engineering")
        self.assertEqual(groups[0]["member"], ["alice", "bob"])
        self.assertEqual(groups[0]["comments"], "Engineering Team")


if __name__ == "__main__":
    unittest.main()
