"""Tests for FortiOS interface policy parsing, analysis, and health checks."""

from __future__ import annotations

import json
import unittest

from analyzer import analyze_configuration, resolve_interface_policy_security_profiles
from health_check import run_health_check
from parser import parse_configuration, parse_interface_policies


class TestInterfacePolicy(unittest.TestCase):
    """Comprehensive test suite for config firewall interface-policy."""

    def test_01_basic_parsing_fields(self):
        """1. Basic parsing of interface policy fields."""
        config_text = """
config firewall interface-policy
    edit 10
        set interface "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTP" "HTTPS"
        set status enable
        set comments "Basic test policy"
    next
end
"""
        policies = parse_interface_policies(config_text)
        self.assertEqual(len(policies), 1)
        pol = policies[0]
        self.assertEqual(pol["id"], 10)
        self.assertEqual(pol["policyid"], 10)
        self.assertEqual(pol["interface"], "port1")
        self.assertEqual(pol["srcaddr"], ["all"])
        self.assertEqual(pol["dstaddr"], ["all"])
        self.assertEqual(pol["service"], ["HTTP", "HTTPS"])
        self.assertEqual(pol["status"], "enable")
        self.assertEqual(pol["comments"], "Basic test policy")

    def test_02_sequence_index_assignment(self):
        """2. Sequence index assigned per VDOM in configuration order."""
        config_text = """
config firewall interface-policy
    edit 50
        set interface "port1"
    next
    edit 20
        set interface "port2"
    next
end
"""
        policies = parse_interface_policies(config_text)
        self.assertEqual(len(policies), 2)
        self.assertEqual(policies[0]["id"], 50)
        self.assertEqual(policies[0]["sequence_index"], 0)
        self.assertEqual(policies[1]["id"], 20)
        self.assertEqual(policies[1]["sequence_index"], 1)

    def test_03_enabled_vs_disabled_policy(self):
        """3. Enabled vs disabled interface policy representation."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set status disable
        set ips-sensor-status enable
        set ips-sensor "default"
    next
    edit 2
        set interface "port2"
        set status enable
        set ips-sensor-status enable
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessments = analysis["interface_policy_assessments"]
        self.assertEqual(len(assessments), 2)

        p1 = next(item for item in assessments if item["policy_id"] == 1)
        self.assertEqual(p1["purpose"], "Disabled Interface Policy")
        self.assertEqual(p1["status"], "disable")
        self.assertIs(p1["inspection_profiles"]["ips"]["active"], False)

        p2 = next(item for item in assessments if item["policy_id"] == 2)
        self.assertEqual(p2["purpose"], "Interface Traffic IPS Inspection")
        self.assertEqual(p2["status"], "enable")
        self.assertIs(p2["inspection_profiles"]["ips"]["active"], True)

    def test_04_interface_role_wan(self):
        """4. Interface role resolution: WAN."""
        config_text = """
config system interface
    edit "wan1"
        set role wan
    next
end
config firewall interface-policy
    edit 1
        set interface "wan1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "wan1")
        self.assertEqual(p["interface_context"]["role"], "WAN")
        self.assertFalse(p["interface_context"]["role_inferred"])

    def test_05_interface_role_lan(self):
        """5. Interface role resolution: LAN."""
        config_text = """
config system interface
    edit "lan1"
        set role lan
    next
end
config firewall interface-policy
    edit 1
        set interface "lan1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "lan1")
        self.assertEqual(p["interface_context"]["role"], "LAN")

    def test_06_interface_role_management(self):
        """6. Interface role resolution: MANAGEMENT."""
        config_text = """
config system interface
    edit "mgmt1"
        set dedicated-to management
    next
end
config firewall interface-policy
    edit 1
        set interface "mgmt1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "mgmt1")
        self.assertEqual(p["interface_context"]["role"], "MANAGEMENT")
        self.assertTrue(p["interface_context"]["management_context"]["is_management"])

    def test_07_interface_role_vpn(self):
        """7. Interface role resolution: VPN route-based interface."""
        config_text = """
config vpn ipsec phase1-interface
    edit "to_branch"
        set interface "port1"
    next
end
config firewall interface-policy
    edit 1
        set interface "to_branch"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "to_branch")
        self.assertEqual(p["interface_context"]["role"], "VPN")

    def test_08_interface_role_unknown(self):
        """8. Interface role resolution: UNKNOWN interface."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "missing_port"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "missing_port")
        self.assertEqual(p["interface_context"]["role"], "UNKNOWN")
        self.assertFalse(p["interface_context"]["resolved"])

    def test_09_interface_role_system_zone(self):
        """9. Interface role resolution: System Zone."""
        config_text = """
config system interface
    edit "lan1"
        set role lan
    next
    edit "lan2"
        set role lan
    next
end
config system zone
    edit "LAN_Zone"
        set interface "lan1" "lan2"
    next
end
config firewall interface-policy
    edit 1
        set interface "LAN_Zone"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["interface"], "LAN_Zone")
        self.assertEqual(p["interface_context"]["role"], "LAN")
        self.assertEqual(p["interface_context"]["type"], "zone")

    def test_10_source_address_single_atom(self):
        """10. Source address resolution: single atom."""
        config_text = """
config firewall address
    edit "HOST_1"
        set subnet 10.1.1.5 255.255.255.255
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set srcaddr "HOST_1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        sources = analysis["interface_policy_assessments"][0]["resolved_sources"]
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["name"], "HOST_1")
        self.assertEqual(sources[0]["subnet"], "10.1.1.5/32")
        self.assertEqual(sources[0]["type"], "address")

    def test_11_source_address_group(self):
        """11. Source address resolution: address group with members."""
        config_text = """
config firewall address
    edit "HOST_A"
        set subnet 10.1.1.1 255.255.255.255
    next
    edit "HOST_B"
        set subnet 10.1.1.2 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_HOSTS"
        set member "HOST_A" "HOST_B"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set srcaddr "GRP_HOSTS"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        sources = analysis["interface_policy_assessments"][0]["resolved_sources"]
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["name"], "GRP_HOSTS")
        self.assertEqual(sources[0]["type"], "address_group")
        member_names = [m["name"] for m in sources[0]["members"]]
        self.assertEqual(member_names, ["HOST_A", "HOST_B"])

    def test_12_destination_address_single_atom(self):
        """12. Destination address resolution: single atom."""
        config_text = """
config firewall address
    edit "SERVER_1"
        set subnet 192.168.1.100 255.255.255.255
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set dstaddr "SERVER_1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        destinations = analysis["interface_policy_assessments"][0]["resolved_destinations"]
        self.assertEqual(len(destinations), 1)
        self.assertEqual(destinations[0]["name"], "SERVER_1")
        self.assertEqual(destinations[0]["subnet"], "192.168.1.100/32")

    def test_13_destination_address_group(self):
        """13. Destination address resolution: address group."""
        config_text = """
config firewall address
    edit "SRV_A"
        set subnet 192.168.1.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "SRV_GRP"
        set member "SRV_A"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set dstaddr "SRV_GRP"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        destinations = analysis["interface_policy_assessments"][0]["resolved_destinations"]
        self.assertEqual(len(destinations), 1)
        self.assertEqual(destinations[0]["name"], "SRV_GRP")
        self.assertEqual(len(destinations[0]["members"]), 1)

    def test_14_service_resolution_single(self):
        """14. Service resolution: single service."""
        config_text = """
config firewall service custom
    edit "CUSTOM_APP"
        set tcp-portrange 8080
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set service "CUSTOM_APP"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        services = analysis["interface_policy_assessments"][0]["resolved_services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "CUSTOM_APP")
        self.assertEqual(services[0]["tcp_ports"], ["8080"])

    def test_15_service_resolution_multiple_and_builtin(self):
        """15. Service resolution: multiple services including built-ins."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set service "HTTP" "HTTPS"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        services = analysis["interface_policy_assessments"][0]["resolved_services"]
        self.assertEqual(len(services), 2)
        names = [s["name"] for s in services]
        self.assertEqual(names, ["HTTP", "HTTPS"])
        self.assertEqual(services[0]["definition"], "TCP/80")
        self.assertEqual(services[1]["definition"], "TCP/443")

    def test_16_broad_selectors_no_false_positive_findings(self):
        """16. Broad selectors (all, ALL) are neutral facts, not security findings."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set ips-sensor-status enable
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        # Interface policy broad selectors must not produce analyzer findings or health findings
        self.assertEqual(len(analysis["findings"]), 0)
        broad_findings = [
            c for c in health["checks"]
            if "broad" in c.get("title", "").lower() or "any" in c.get("title", "").lower()
        ]
        self.assertEqual(len(broad_findings), 0)

    def test_17_ips_profile_enabled_and_resolved(self):
        """17. IPS profile resolution: status enable, reference resolved."""
        config_text = """
config ips sensor
    edit "custom-ips"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status enable
        set ips-sensor "custom-ips"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertEqual(ips["configured_reference"], "custom-ips")
        self.assertEqual(ips["activation_status"], "ENABLED")
        self.assertIs(ips["active"], True)
        self.assertIs(ips["resolved"], True)
        self.assertEqual(ips["source"], "custom")

    def test_18_ips_profile_enabled_and_unresolved(self):
        """18. IPS profile resolution: status enable, reference unresolved."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status enable
        set ips-sensor "non-existent-ips"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertEqual(ips["configured_reference"], "non-existent-ips")
        self.assertEqual(ips["activation_status"], "ENABLED")
        self.assertIs(ips["active"], True)
        self.assertIs(ips["resolved"], False)

        health = run_health_check(config, analysis)
        unresolved_checks = [
            c for c in health["checks"]
            if c.get("title") == "Referenced Security Profile Could Not Be Resolved"
        ]
        self.assertEqual(len(unresolved_checks), 1)
        self.assertTrue(any("non-existent-ips" in e for e in unresolved_checks[0]["evidence"]))

    def test_19_ips_profile_disabled_status_with_reference(self):
        """19. IPS profile status disable with reference: activation_status=DISABLED, active=False."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status disable
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertEqual(ips["configured_reference"], "default")
        self.assertEqual(ips["activation_status"], "DISABLED")
        self.assertIs(ips["active"], False)
        self.assertIs(ips["resolved"], True)

        health = run_health_check(config, analysis)
        # Disabled profile must NOT trigger health check finding even if reference is unknown
        unresolved_checks = [
            c for c in health["checks"]
            if c.get("title") == "Referenced Security Profile Could Not Be Resolved"
        ]
        self.assertEqual(len(unresolved_checks), 0)

    def test_20_profile_reference_present_status_not_observed(self):
        """20. Profile reference present, status NOT_OBSERVED -> active is 'unknown'."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertEqual(ips["configured_reference"], "default")
        self.assertEqual(ips["activation_status"], "NOT_OBSERVED")
        self.assertEqual(ips["active"], "unknown")
        self.assertIs(ips["resolved"], True)

        # Must not produce a health check failure
        health = run_health_check(config, analysis)
        unresolved_checks = [
            c for c in health["checks"]
            if c.get("title") == "Referenced Security Profile Could Not Be Resolved"
        ]
        self.assertEqual(len(unresolved_checks), 0)

    def test_21_profile_status_enable_without_reference(self):
        """21. Profile status enable, but reference NOT configured -> active is False."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status enable
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertIsNone(ips["configured_reference"])
        self.assertEqual(ips["activation_status"], "ENABLED")
        self.assertIs(ips["active"], False)
        self.assertIsNone(ips["resolved"])

    def test_22_profile_neither_status_nor_reference(self):
        """22. Neither status nor reference configured -> NOT_OBSERVED, active=False."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        ips = p["inspection_profiles"]["ips"]
        self.assertIsNone(ips["configured_reference"])
        self.assertEqual(ips["activation_status"], "NOT_OBSERVED")
        self.assertIs(ips["active"], False)

    def test_23_antivirus_profile_resolution(self):
        """23. Antivirus profile resolution."""
        config_text = """
config antivirus profile
    edit "av-block"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set av-profile-status enable
        set av-profile "av-block"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        av = p["inspection_profiles"]["antivirus"]
        self.assertEqual(av["configured_reference"], "av-block")
        self.assertEqual(av["activation_status"], "ENABLED")
        self.assertIs(av["active"], True)
        self.assertIs(av["resolved"], True)
        self.assertEqual(p["purpose"], "Interface Traffic Malware Inspection")

    def test_24_web_filter_profile_resolution(self):
        """24. Web filter profile resolution."""
        config_text = """
config webfilter profile
    edit "wf-block"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set webfilter-profile-status enable
        set webfilter-profile "wf-block"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        wf = p["inspection_profiles"]["web_filter"]
        self.assertEqual(wf["configured_reference"], "wf-block")
        self.assertEqual(wf["activation_status"], "ENABLED")
        self.assertIs(wf["active"], True)
        self.assertIs(wf["resolved"], True)

    def test_25_application_control_profile_resolution(self):
        """25. Application control profile resolution."""
        config_text = """
config application list
    edit "app-ctrl"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set application-list-status enable
        set application-list "app-ctrl"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        app = p["inspection_profiles"]["application_control"]
        self.assertEqual(app["configured_reference"], "app-ctrl")
        self.assertEqual(app["activation_status"], "ENABLED")
        self.assertIs(app["active"], True)

    def test_26_email_filter_profile_resolution(self):
        """26. Email filter profile resolution."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set emailfilter-profile-status enable
        set emailfilter-profile "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        em = p["inspection_profiles"]["email_filter"]
        self.assertEqual(em["configured_reference"], "default")
        self.assertEqual(em["activation_status"], "ENABLED")
        self.assertIs(em["active"], True)
        self.assertIs(em["resolved"], True)

    def test_27_dlp_profile_resolution(self):
        """27. DLP profile resolution (dlp-sensor / dlp-profile)."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set dlp-sensor-status enable
        set dlp-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        dlp = p["inspection_profiles"]["dlp"]
        self.assertEqual(dlp["configured_reference"], "default")
        self.assertEqual(dlp["activation_status"], "ENABLED")
        self.assertIs(dlp["active"], True)

    def test_28_casb_profile_resolution(self):
        """28. CASB profile resolution (casb-profile)."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set casb-profile-status enable
        set casb-profile "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        casb = p["inspection_profiles"]["casb"]
        self.assertEqual(casb["configured_reference"], "default")
        self.assertEqual(casb["activation_status"], "ENABLED")
        self.assertIs(casb["active"], True)

    def test_29_multiple_active_profiles_purpose(self):
        """29. Multiple active inspection profiles -> Interface Traffic Security Inspection."""
        config_text = """
config ips sensor
    edit "custom-ips"
    next
end
config antivirus profile
    edit "custom-av"
    next
end
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status enable
        set ips-sensor "custom-ips"
        set av-profile-status enable
        set av-profile "custom-av"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["purpose"], "Interface Traffic Security Inspection")
        self.assertEqual(sorted(p["active_profiles"]), ["antivirus", "ips"])

    def test_30_single_ips_purpose(self):
        """30. Single active IPS profile -> Interface Traffic IPS Inspection."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set ips-sensor-status enable
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["purpose"], "Interface Traffic IPS Inspection")

    def test_31_single_av_purpose(self):
        """31. Single active Antivirus profile -> Interface Traffic Malware Inspection."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set av-profile-status enable
        set av-profile "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["purpose"], "Interface Traffic Malware Inspection")

    def test_32_no_active_profile_purpose(self):
        """32. No active profile -> Interface Traffic Monitoring / Inspection Policy."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["purpose"], "Interface Traffic Monitoring / Inspection Policy")
        self.assertEqual(p["active_profiles"], [])

    def test_33_operational_logtraffic_setting(self):
        """33. logtraffic setting preserved in configured_facts."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set logtraffic all
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["configured_facts"]["logtraffic"], "all")
        self.assertTrue(any("all" in obs for obs in p["security_observations"]))

    def test_34_operational_dsri_setting(self):
        """34. dsri setting preserved in configured_facts."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set dsri enable
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        p = analysis["interface_policy_assessments"][0]
        self.assertEqual(p["configured_facts"]["dsri"], "enable")
        self.assertTrue(any("dsri" in obs.lower() for obs in p["security_observations"]))

    def test_35_negative_not_in_policy_assessments(self):
        """35. Negative assertion: Interface policy is NOT in policy_assessments."""
        config_text = """
config firewall interface-policy
    edit 100
        set interface "port1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        self.assertEqual(len(analysis["policy_assessments"]), 0)

    def test_36_negative_not_in_local_in_assessments(self):
        """36. Negative assertion: Interface policy is NOT in local_in_assessments."""
        config_text = """
config firewall interface-policy
    edit 100
        set interface "port1"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        self.assertEqual(len(analysis["local_in_assessments"]), 0)

    def test_37_negative_no_authorization_or_reachability_claims(self):
        """37. Negative assertion: No ACCEPT/DENY, routing, or reachability claims."""
        config_text = """
config firewall interface-policy
    edit 1
        set interface "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set ips-sensor-status enable
        set ips-sensor "default"
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis)
        dumped = json.dumps({"config": config, "analysis": analysis, "health": health}).casefold()
        self.assertNotIn("action", analysis["interface_policy_assessments"][0])
        self.assertNotIn("confirmed reachable", dumped)
        self.assertNotIn("proven effective non-exposure", dumped)
        self.assertNotIn("traffic allowed", dumped)
        self.assertNotIn("traffic permitted", dumped)
        self.assertNotIn("forwarding authorization", dumped)

    def test_38_vdom_isolation(self):
        """38. VDOM isolation: profiles and objects in one VDOM do not resolve in another."""
        config_text = """
config vdom
    edit "vdom_a"
        config ips sensor
            edit "ips_a"
            next
        end
        config firewall interface-policy
            edit 1
                set interface "port1"
                set ips-sensor-status enable
                set ips-sensor "ips_a"
            next
        end
    next
    edit "vdom_b"
        config firewall interface-policy
            edit 2
                set interface "port2"
                set ips-sensor-status enable
                set ips-sensor "ips_a"
            next
        end
    next
end
"""
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        assessments = analysis["interface_policy_assessments"]
        self.assertEqual(len(assessments), 2)

        p_vdom_a = next(item for item in assessments if item["vdom"] == "vdom_a")
        self.assertTrue(p_vdom_a["inspection_profiles"]["ips"]["resolved"])
        self.assertEqual(p_vdom_a["inspection_profiles"]["ips"]["vdom"], "vdom_a")

        p_vdom_b = next(item for item in assessments if item["vdom"] == "vdom_b")
        # In vdom_b, ips_a was not configured, so it must not resolve
        self.assertFalse(p_vdom_b["inspection_profiles"]["ips"]["resolved"])


if __name__ == "__main__":
    unittest.main()
