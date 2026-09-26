"""Product-level golden regression tests using sanitized synthetic configs."""

import json
import os
import unittest

from analyzer import analyze_configuration, classify_interface
from health_check import run_health_check
from parser import parse_configuration


GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "golden")


def load_golden(name):
    with open(os.path.join(GOLDEN_DIR, name), encoding="utf-8") as handle:
        config = parse_configuration(handle.read())
    analysis = analyze_configuration(config)
    health = run_health_check(config, analysis)
    return config, analysis, health


def assessment(analysis, policy_id, vdom=None):
    return next(
        item
        for item in analysis["policy_assessments"]
        if item["policy_id"] == policy_id and item.get("vdom") == vdom
    )


class TestGoldenRegression(unittest.TestCase):
    def test_normal_internet_access_explicit_and_inferred_wan(self):
        _, analysis, _ = load_golden("internet_access.conf")
        explicit = assessment(analysis, 1)
        inferred = assessment(analysis, 2)
        for item in (explicit, inferred):
            self.assertEqual(item["traffic_direction"], "LAN -> WAN")
            self.assertEqual(item["flow_type"], "OUTBOUND_INTERNET")
            self.assertEqual(item["purpose"], "Internet Access")
            self.assertTrue(all(i["resolved"] for i in item["source_interfaces"] + item["destination_interfaces"]))
        self.assertFalse(explicit["destination_interfaces"][0]["role_inferred"])
        self.assertTrue(inferred["destination_interfaces"][0]["role_inferred"])
        self.assertEqual(analysis["findings"], [])

    def test_vip_publishing_resolves_without_calling_all_insecure(self):
        _, analysis, _ = load_golden("vip_publishing.conf")
        item = assessment(analysis, 10)
        self.assertEqual(item["flow_type"], "INBOUND_PUBLIC")
        self.assertEqual(item["purpose"], "Public Server Publishing")
        self.assertEqual(item["vip_references"][0]["name"], "PUBLIC-WEB")
        self.assertEqual(item["vip_references"][0]["type"], "vip")
        self.assertFalse(any(f.get("policy_id") == 10 for f in analysis["findings"]))

    def test_internal_web_and_custom_service_access(self):
        _, analysis, _ = load_golden("internal_access.conf")
        web = assessment(analysis, 1)
        custom = assessment(analysis, 2)
        self.assertEqual(web["flow_type"], "INTERNAL_ACCESS")
        self.assertEqual(web["purpose"], "Web Access")
        self.assertEqual(custom["flow_type"], "INTERNAL_ACCESS")
        self.assertEqual(custom["purpose"], "Inter-VLAN Access")
        self.assertEqual(custom["resolved_services"][0]["type"], "custom_service")

    def test_system_zone_to_sdwan_and_mixed_zone(self):
        _, analysis, _ = load_golden("zones_sdwan.conf")
        internet = assessment(analysis, 1)
        mixed = assessment(analysis, 2)
        self.assertEqual(internet["traffic_direction"], "LAN -> WAN")
        self.assertEqual(internet["purpose"], "Internet Access")
        self.assertEqual(internet["source_interfaces"][0]["type"], "zone")
        self.assertEqual(internet["destination_interfaces"][0]["type"], "sdwan_zone")
        self.assertEqual(mixed["source_interfaces"][0]["role"], "UNKNOWN")
        self.assertEqual(mixed["purpose"], "Custom / Unknown Access")

    def test_builtin_any_is_resolved_without_integrity_false_positive(self):
        _, analysis, health = load_golden("zones_sdwan.conf")
        item = assessment(analysis, 3)["source_interfaces"][0]
        self.assertTrue(item["resolved"])
        self.assertEqual(item["role"], "UNKNOWN")
        evidence = " ".join(e for c in health["checks"] for e in c["evidence"])
        self.assertNotIn("unresolved interface any", evidence)

    def test_ipsec_static_context_recognizes_route_based_vpn_role(self):
        config, analysis, health = load_golden("ipsec_access.conf")
        self.assertEqual(len(config["ipsec_phase1"]), 1)
        outbound = assessment(analysis, 1)
        inbound = assessment(analysis, 2)
        self.assertTrue(outbound["destination_interfaces"][0]["resolved"])
        self.assertEqual(outbound["traffic_direction"], "LAN -> VPN")
        self.assertEqual(outbound["purpose"], "Site-to-Site VPN Access")
        self.assertEqual(inbound["traffic_direction"], "VPN -> LAN")
        self.assertEqual(inbound["purpose"], "VPN-to-Internal Access")
        self.assertFalse(any("tunnel is down" in c["description"].casefold() for c in health["checks"]))

    def test_wan_administration_protocol_findings_and_lan_exclusion(self):
        _, _, health = load_golden("admin_exposure.conf")
        titles = [item["title"] for item in health["checks"]]
        self.assertIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertIn("Telnet Management Exposed on WAN", titles)
        self.assertEqual(titles.count("Remote Management Accessible from WAN"), 2)
        all_evidence = [e for item in health["checks"] for e in item["evidence"]]
        self.assertFalse(any("Interface: lan1" in e for e in all_evidence))

    def test_admin_trusted_host_and_role_evidence_are_cautious(self):
        _, _, health = load_golden("admin_exposure.conf")
        self.assertTrue(any(c["title"] == "Administrative Access Lacks Trusted Host Restrictions" for c in health["checks"]))
        evidence = " ".join(e for c in health["checks"] for e in c["evidence"])
        self.assertIn("Role: WAN", evidence)
        self.assertIn("WAN (inferred from interface name or alias)", evidence)
        self.assertIn("review-admin", evidence)
        self.assertNotIn("restricted-admin", next(c for c in health["checks"] if c["title"] == "Administrative Access Lacks Trusted Host Restrictions")["evidence"])

    def test_security_profile_resolution_and_builtins(self):
        _, analysis, _ = load_golden("profiles.conf")
        profiled = assessment(analysis, 1)["security_profiles"]
        self.assertTrue(profiled["antivirus"]["resolved"])
        self.assertEqual(profiled["antivirus"]["source"], "custom")
        self.assertTrue(profiled["ssl_inspection"]["resolved"])
        self.assertEqual(profiled["ssl_inspection"]["source"], "built-in")
        self.assertTrue(assessment(analysis, 3)["security_profiles"]["ips"]["resolved"])

    def test_profile_health_positive_and_negative_expectations(self):
        _, analysis, health = load_golden("profiles.conf")
        titles = [item["title"] for item in health["checks"]]
        self.assertIn("Referenced Security Profile Could Not Be Resolved", titles)
        self.assertEqual(titles.count("No Security Profiles Detected on Outbound Internet Policy"), 1)
        self.assertNotIn("IPS Not Detected on Internet-Facing Policy", titles)
        self.assertEqual(sum(f["title"] == "Duplicate Firewall Policy" for f in analysis["findings"]), 1)

    def test_isdb_selector_types_and_resolution_states(self):
        _, analysis, _ = load_golden("isdb.conf")
        expected = {
            1: ("id", "known_in_backup"),
            2: ("name", "known_in_backup"),
            3: ("group", "local"),
            4: ("custom", "local"),
            6: ("fortiguard", "predefined_offline"),
        }
        for policy_id, expected_state in expected.items():
            selector = assessment(analysis, policy_id)["internet_service_matching"]["destination"]["selectors"][0]
            self.assertEqual((selector["type"], selector["resolution"]), expected_state)
        self.assertTrue(assessment(analysis, 5)["internet_service_matching"]["source"]["enabled"])

    def test_isdb_absent_traditional_fields_and_relationships_are_safe(self):
        _, analysis, health = load_golden("isdb.conf")
        for policy_id in (1, 2, 3, 4, 6):
            item = assessment(analysis, policy_id)
            self.assertEqual(item["purpose"], "Internet Access")
            self.assertEqual(item["resolved_destinations"], [])
            self.assertEqual(item["resolved_services"], [])
        titles = {f["title"] for f in analysis["findings"]}
        self.assertFalse(titles & {"Duplicate Firewall Policy", "Fully Shadowed Firewall Policy", "Conflicting Policy Shadowing"})
        integrity = " ".join(e for c in health["checks"] if c["category"] == "Configuration Integrity" for e in c["evidence"])
        self.assertNotIn("Valid-Predefined", integrity)

    def test_isdb_profile_review_remains_active(self):
        _, _, health = load_golden("isdb.conf")
        titles = [c["title"] for c in health["checks"]]
        self.assertIn("No Security Profiles Detected on Outbound Internet Policy", titles)
        self.assertIn("IPS Not Detected on Internet-Facing Policy", titles)

    def test_multivdom_resolution_and_independent_sequence(self):
        config, analysis, _ = load_golden("multivdom.conf")
        policies_a = [p for p in config["policies"] if p["vdom"] == "VDOM-A"]
        policies_b = [p for p in config["policies"] if p["vdom"] == "VDOM-B"]
        self.assertEqual([p["sequence_index"] for p in policies_a], [0, 1])
        self.assertEqual([p["sequence_index"] for p in policies_b], [0])
        a = assessment(analysis, 1, "VDOM-A")
        b = assessment(analysis, 1, "VDOM-B")
        self.assertEqual(a["source_interfaces"][0]["role"], "LAN")
        self.assertEqual(b["source_interfaces"][0]["role"], "DMZ")
        self.assertEqual(a["resolved_sources"][0]["subnet"], "10.1.0.0/16")
        self.assertEqual(b["resolved_sources"][0]["subnet"], "10.2.0.0/16")
        self.assertTrue(a["security_profiles"]["antivirus"]["resolved"])
        self.assertTrue(b["security_profiles"]["antivirus"]["resolved"])

    def test_relationship_golden_cases(self):
        _, analysis, _ = load_golden("relationships.conf")
        relationships = {(f["title"], f.get("policy_id"), f.get("shadowed_by_policy_id")) for f in analysis["findings"]}
        self.assertIn(("Duplicate Firewall Policy", 2, 1), relationships)
        self.assertIn(("Fully Shadowed Firewall Policy", 4, 3), relationships)
        self.assertIn(("Conflicting Policy Shadowing", 6, 5), relationships)

    def test_relationship_negative_cases(self):
        _, analysis, _ = load_golden("relationships.conf")
        related_ids = {
            f.get("policy_id")
            for f in analysis["findings"]
            if f["title"] in {"Duplicate Firewall Policy", "Fully Shadowed Firewall Policy", "Conflicting Policy Shadowing"}
        }
        for policy_id in (8, 10, 12, 14):
            self.assertNotIn(policy_id, related_ids)

    def test_different_vdoms_do_not_interact(self):
        _, analysis, _ = load_golden("multivdom.conf")
        duplicate = next(f for f in analysis["findings"] if f["title"] == "Duplicate Firewall Policy")
        self.assertEqual(duplicate["vdom"], "VDOM-A")
        self.assertEqual(duplicate["policy_id"], 2)

    def test_unresolved_references_and_valid_special_references(self):
        _, analysis, health = load_golden("unresolved.conf")
        integrity = next(c for c in health["checks"] if c["title"] == "Configuration References Could Not Be Fully Resolved")
        evidence = " ".join(integrity["evidence"])
        for value in ("missing-interface", "missing-address", "missing-service"):
            self.assertIn(value, evidence)
        self.assertNotIn("unresolved interface any", evidence)
        self.assertNotIn("LAN-ZONE", evidence)
        self.assertNotIn("WAN-ZONE", evidence)
        self.assertNotIn("Valid-Predefined-Offline", evidence)
        selector = assessment(analysis, 3)["internet_service_matching"]["destination"]["selectors"][0]
        self.assertEqual(selector["resolution"], "predefined_offline")

    def test_disabled_policy_is_not_active_exposure_or_shadow_source(self):
        _, analysis, _ = load_golden("relationships.conf")
        disabled = assessment(analysis, 7)
        self.assertEqual(disabled["purpose"], "Disabled Policy")
        disabled_findings = [f for f in analysis["findings"] if f.get("policy_id") == 7]
        self.assertEqual([f["title"] for f in disabled_findings], ["Disabled Policy"])
        self.assertFalse(any(f.get("shadowed_by_policy_id") == 7 for f in analysis["findings"]))

    def test_combined_realistic_fixture_stable_counts_and_purposes(self):
        config, analysis, _ = load_golden("combined_realistic.conf")
        self.assertEqual(len(config["interfaces"]), 7)
        self.assertEqual(len(config["addresses"]), 3)
        self.assertEqual(len(config["services"]), 1)
        self.assertEqual(len(config["vips"]), 1)
        self.assertEqual(len(config["policies"]), 6)
        self.assertEqual(assessment(analysis, 10)["purpose"], "Internet Access")
        self.assertEqual(assessment(analysis, 20)["flow_type"], "INTERNAL_ACCESS")
        self.assertEqual(assessment(analysis, 30)["purpose"], "Public Server Publishing")
        self.assertEqual(assessment(analysis, 40)["traffic_direction"], "VPN -> LAN")
        self.assertEqual(assessment(analysis, 40)["purpose"], "VPN-to-Internal Access")
        self.assertEqual(assessment(analysis, 50)["purpose"], "Internet Access")
        self.assertEqual(assessment(analysis, 60)["purpose"], "Disabled Policy")

    def test_combined_realistic_fixture_resolution_and_health_negatives(self):
        _, analysis, health = load_golden("combined_realistic.conf")
        self.assertEqual(assessment(analysis, 30)["vip_references"][0]["type"], "vip")
        self.assertTrue(assessment(analysis, 10)["security_profiles"]["antivirus"]["resolved"])
        self.assertTrue(assessment(analysis, 30)["security_profiles"]["ips"]["resolved"])
        titles = {c["title"] for c in health["checks"]}
        self.assertEqual(titles, {"Disabled Firewall Policies Present"})
        self.assertNotIn("Configuration References Could Not Be Fully Resolved", titles)
        self.assertNotIn("IPS Not Detected on Internet-Facing Policy", titles)

    def test_secret_values_never_reach_public_result_structures(self):
        config, analysis, health = load_golden("secrets.conf")
        streamlit_facing = []
        try:
            from app import _policy_inventory_rows
            streamlit_facing = _policy_inventory_rows(config["policies"])
        except ImportError:
            pass

        public_text = json.dumps(
            {"config": config, "analysis": analysis, "health": health, "ui": streamlit_facing},
            sort_keys=True,
        )
        for secret in (
            "FAKE_PASSWORD_123",
            "FAKE_OLD_PASSWORD_456",
            "FAKE_API_TOKEN_789",
            "FAKE_PSK_SECRET_ABC",
            "FAKE_PRIVATE_KEY_DEF",
            "FAKE_SNMP_COMMUNITY_GHI",
        ):
            self.assertNotIn(secret, public_text)

    def test_empty_whitespace_random_and_unsupported_inputs_are_safe(self):
        for text in ("", "   \n\t", "random harmless text", "config unsupported feature\n set thing value\nend"):
            config = parse_configuration(text)
            analysis = analyze_configuration(config)
            health = run_health_check(config, analysis)
            self.assertEqual(config["policies"], [])
            self.assertEqual(analysis["policy_assessments"], [])
            self.assertIsInstance(health["checks"], list)

    def test_truncated_and_partial_policy_inputs_do_not_invent_policy(self):
        samples = (
            'config firewall policy\n edit 1\n  set name "unfinished',
            "config firewall policy\n edit 1\n  set srcintf",
            "config firewall policy\n edit 1\n  set action accept\nend",
        )
        for text in samples:
            config = parse_configuration(text)
            analysis = analyze_configuration(config)
            self.assertEqual(config["policies"], [])
            self.assertEqual(analysis["findings"], [])

    def test_missing_end_after_complete_next_is_tolerated_without_invention(self):
        text = '''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set service "HTTPS"
set action accept
next'''
        config = parse_configuration(text)
        analysis = analyze_configuration(config)
        self.assertEqual(len(config["policies"]), 1)
        self.assertEqual(config["policies"][0]["id"], 1)
        self.assertEqual(analysis["findings"], [])

    def test_review_findings_do_not_claim_proven_vulnerability_or_live_state(self):
        _, _, health = load_golden("vip_publishing.conf")
        serialized = json.dumps(health).casefold()
        self.assertNotIn("confirmed vulnerability", serialized)
        self.assertNotIn("tunnel is down", serialized)
        self.assertNotIn("traffic is reachable", serialized)

    def test_unknown_interface_role_is_not_guessed(self):
        _, analysis, _ = load_golden("unresolved.conf")
        context = assessment(analysis, 1)["source_interfaces"][0]
        self.assertFalse(context["resolved"])
        self.assertEqual(context["role"], "UNKNOWN")
        self.assertFalse(context["role_inferred"])

    def test_repeated_complete_blocks_remain_deterministic(self):
        text = '''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set service "HTTPS"
set action accept
next
end
config firewall policy
edit 2
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set service "HTTP"
set action accept
next
end'''
        config = parse_configuration(text)
        self.assertEqual([p["id"] for p in config["policies"]], [1, 2])
        self.assertEqual([p["sequence_index"] for p in config["policies"]], [0, 1])

    def test_missing_optional_fields_do_not_create_findings_by_themselves(self):
        config = parse_configuration('''config firewall policy
edit 1
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set service "HTTPS"
set action accept
next
end''')
        analysis = analyze_configuration(config)
        self.assertEqual(analysis["findings"], [])

    def test_management_context_negative_assertions(self):
        """Golden negative assertions for Management Context."""
        config_text = """
config system global
    set management-vdom "root"
end
config system interface
    edit "mgmt-users"
        set role lan
        set allowaccess ping https ssh
    next
    edit "mgmt"
    next
    edit "port5"
    next
end
config system ha
    set ha-mgmt-status disable
    set hbdev "port5" 50
    config ha-mgmt-interfaces
        edit 1
            set interface "port5"
        next
    end
end
config system dedicated-mgmt
    set status disable
    set interface "mgmt"
end
"""
        parsed = parse_configuration(config_text)

        # 1. "mgmt" in name != MANAGEMENT
        mgmt_intf = next(i for i in parsed["interfaces"] if i["name"] == "mgmt")
        res_mgmt = classify_interface(mgmt_intf, config=parsed)
        self.assertNotEqual(res_mgmt["role"], "MANAGEMENT")

        # 2. management-vdom != dedicated interface
        users_intf = next(
            i for i in parsed["interfaces"] if i["name"] == "mgmt-users"
        )
        res_users = classify_interface(users_intf, config=parsed)
        self.assertEqual(res_users["role"], "LAN")
        self.assertNotEqual(res_users["role"], "MANAGEMENT")

        # 3. allowaccess != dedicated management context
        self.assertFalse(res_users["management_context"]["is_management"])

        # 4. HA heartbeat != HA management
        hb_intf = next(i for i in parsed["interfaces"] if i["name"] == "port5")
        res_hb = classify_interface(hb_intf, config=parsed)
        self.assertNotEqual(res_hb["role"], "MANAGEMENT")

        # 5. disabled dedicated management config != active management context
        self.assertFalse(res_mgmt["management_context"]["is_management"])

        # 6. MANAGEMENT != WAN and MANAGEMENT != INTERNAL
        self.assertNotEqual(res_users["role"], "MANAGEMENT")

        # 7. static configuration != proof of reachability
        analysis = analyze_configuration(parsed)
        serialized = json.dumps(analysis)
        self.assertNotIn("reachable", serialized.lower())
        self.assertNotIn("live session", serialized.lower())

    def test_local_in_golden_fixture(self):
        """Verify local_in.conf golden fixture assertions."""
        config, analysis, health = load_golden("local_in.conf")
        local_in = analysis["local_in_assessments"]
        self.assertEqual(len(local_in), 6)

        # Policy 1: WAN SSH ACCEPT from ADMIN_NET
        p1 = next(item for item in local_in if item["policy_id"] == 1)
        self.assertEqual(p1["interface_context"], "WAN")
        self.assertEqual(p1["action"], "accept")
        self.assertEqual(p1["purpose"], "Administrative Service Access to FortiGate")
        self.assertEqual(p1["resolved_sources"][0]["subnet"], "192.168.1.0/24")

        # Policy 2: WAN PING DENY
        p2 = next(item for item in local_in if item["policy_id"] == 2)
        self.assertEqual(p2["action"], "deny")
        self.assertEqual(p2["purpose"], "Diagnostic Access to FortiGate")

        # Policy 3: MANAGEMENT HTTPS ACCEPT
        p3 = next(item for item in local_in if item["policy_id"] == 3)
        self.assertEqual(p3["interface_context"], "MANAGEMENT")
        self.assertEqual(p3["purpose"], "Management Interface Access to FortiGate")

        # Policy 4: Disabled HTTP Policy
        p4 = next(item for item in local_in if item["policy_id"] == 4)
        self.assertEqual(p4["purpose"], "Disabled Local-In Policy")

        # Policy 5: Unresolved Reference
        p5 = next(item for item in local_in if item["policy_id"] == 5)
        self.assertEqual(p5["resolved_sources"][0]["type"], "unknown")

        # Policy 6: ISDB source
        p6 = next(item for item in local_in if item["policy_id"] == 6)
        self.assertTrue(p6["internet_service_source"]["enabled"])

        # Negative assertions (product non-claims)
        full_output = json.dumps({"config": config, "analysis": analysis, "health": health})
        self.assertNotIn("login succeeds", full_output.lower())
        self.assertNotIn("vpn is established", full_output.lower())
        self.assertNotIn("interface is online", full_output.lower())
        self.assertNotIn("traffic is currently flowing", full_output.lower())
        self.assertNotIn("confirmed reachable", full_output.lower())
        self.assertNotIn("confirmed exposure", full_output.lower())
        self.assertNotIn("proven effective non-exposure", full_output.lower())

    def test_likely_full_backup_golden_fixture(self):
        """Verify likely_full_backup.conf golden fixture assertions."""
        config, analysis, health = load_golden("likely_full_backup.conf")
        assessment = analysis.get("input_assessment", {})
        self.assertEqual(assessment.get("classification"), "LIKELY_FULL_BACKUP")
        self.assertTrue(assessment.get("fortigate_detected"))
        self.assertEqual(assessment.get("fortios", {}).get("version"), "7.2.11")
        self.assertEqual(assessment.get("fortios", {}).get("build"), 1740)
        self.assertEqual(assessment.get("fortios", {}).get("platform"), "FG100F")
        self.assertEqual(
            assessment.get("analysis_scope", {}).get("firewall_policies", {}).get("status"),
            "COVERED",
        )
        self.assertEqual(
            assessment.get("analysis_scope", {}).get("ipsec_vpn", {}).get("status"),
            "UNOBSERVED_IN_INPUT",
        )

    def test_partial_policy_golden_fixture(self):
        """Verify partial_policy.conf golden fixture assertions."""
        config, analysis, health = load_golden("partial_policy.conf")
        assessment = analysis.get("input_assessment", {})
        self.assertEqual(assessment.get("classification"), "PARTIAL_CONFIGURATION")
        self.assertTrue(assessment.get("fortigate_detected"))
        self.assertEqual(assessment.get("fortios", {}).get("version"), "unknown")
        self.assertEqual(
            assessment.get("analysis_scope", {}).get("firewall_policies", {}).get("status"),
            "COVERED",
        )
        self.assertEqual(
            assessment.get("analysis_scope", {}).get("administrators", {}).get("status"),
            "UNAVAILABLE_NOT_SUPPLIED",
        )

    def test_truncated_backup_golden_fixture(self):
        """Verify truncated_backup.conf golden fixture assertions."""
        config, analysis, health = load_golden("truncated_backup.conf")
        assessment = analysis.get("input_assessment", {})
        self.assertTrue(assessment.get("fortigate_detected"))
        self.assertTrue(len(assessment.get("structural_warnings", [])) > 0)
        self.assertIn("Truncated or unclosed", assessment.get("structural_warnings", [])[0])

    def test_version_default_applied_golden_fixture(self):
        """Verify version_default_applied.conf golden fixture assertions."""
        config, analysis, health = load_golden("version_default_applied.conf")
        from fortios_defaults import infer_field_default

        # 1. Raw parsed config fact is preserved unmutated (type is None)
        self.assertIsNone(config["ntp"].get("type"))
        self.assertEqual(config["ntp"].get("ntpsync"), "enable")

        # 2. Documented default inference applies for omitted ntp type on 7.2.11 full backup
        ntp_inference = infer_field_default(config, "ntp", "type", config["ntp"].get("type"))
        self.assertTrue(ntp_inference["applicable"])
        self.assertEqual(ntp_inference["status"], "DOCUMENTED_DEFAULT_APPLIED")
        self.assertEqual(ntp_inference["effective_value"], "fortiguard")
        self.assertEqual(ntp_inference["value_source"], "DOCUMENTED_DEFAULT")
        self.assertEqual(ntp_inference["rule_id"], "system_ntp.type")
        self.assertEqual(ntp_inference["fortios_version"], "7.2.11")
        self.assertIn("FortiOS 7.2 CLI Reference", ntp_inference["documentation"])

        # 3. Explicit value wins for admintimeout (30)
        timeout_inference = infer_field_default(
            config, "system_global", "admintimeout", config["system_global"].get("admintimeout")
        )
        self.assertFalse(timeout_inference["applicable"])
        self.assertEqual(timeout_inference["status"], "EXPLICIT_VALUE")
        self.assertEqual(str(timeout_inference["effective_value"]), "30")
        self.assertEqual(timeout_inference["value_source"], "EXPLICIT_CONFIG")

        # 4. Documented default applied does NOT create a security finding by itself
        health_titles = [c["title"] for c in health["checks"]]
        self.assertNotIn("FortiGuard NTP Default Synchronization Active", health_titles)
        self.assertNotIn("NTP Server Configuration Could Not Be Confirmed", health_titles)

        # 5. Documented defaults are exposed in structured interpretation metadata
        applied_defaults = health.get("documented_defaults", [])
        self.assertTrue(any(d["rule_id"] == "system_ntp.type" and d["effective_value"] == "fortiguard" for d in applied_defaults))
        analysis_defaults = analysis.get("documented_defaults", [])
        self.assertTrue(any(d["rule_id"] == "system_ntp.type" and d["effective_value"] == "fortiguard" for d in analysis_defaults))

    def test_version_default_overridden_golden_fixture(self):
        """Verify version_default_overridden.conf golden fixture assertions."""
        config, analysis, health = load_golden("version_default_overridden.conf")
        from fortios_defaults import infer_field_default

        # 1. Raw config has explicit custom type
        self.assertEqual(config["ntp"].get("type"), "custom")

        # 2. Explicit setting overrides default
        ntp_inference = infer_field_default(config, "ntp", "type", config["ntp"].get("type"))
        self.assertFalse(ntp_inference["applicable"])
        self.assertEqual(ntp_inference["status"], "EXPLICIT_VALUE")
        self.assertEqual(ntp_inference["effective_value"], "custom")
        self.assertEqual(ntp_inference["value_source"], "EXPLICIT_CONFIG")

        # 3. Health check does not report FortiGuard default
        health_titles = [c["title"] for c in health["checks"]]
        self.assertNotIn("FortiGuard NTP Default Synchronization Active", health_titles)

    def test_interface_policy_golden_fixture(self):
        """Verify interface_policy.conf golden fixture assertions."""
        config, analysis, health = load_golden("interface_policy.conf")
        interface_policies = config.get("interface_policies", [])
        self.assertEqual(len(interface_policies), 6)

        assessments = analysis.get("interface_policy_assessments", [])
        self.assertEqual(len(assessments), 6)

        # Policy 1: WAN IPS Inspection
        p1 = next(item for item in assessments if item["policy_id"] == 1)
        self.assertEqual(p1["interface"], "wan1")
        self.assertEqual(p1["interface_context"]["role"], "WAN")
        self.assertEqual(p1["purpose"], "Interface Traffic IPS Inspection")
        self.assertEqual(p1["technical_context"], "INTERFACE_INSPECTION_POLICY")
        self.assertEqual(p1["active_profiles"], ["ips"])
        ips_p1 = p1["inspection_profiles"]["ips"]
        self.assertEqual(ips_p1["configured_reference"], "ips-custom")
        self.assertEqual(ips_p1["activation_status"], "ENABLED")
        self.assertIs(ips_p1["active"], True)
        self.assertIs(ips_p1["resolved"], True)
        self.assertEqual(p1["configured_facts"]["logtraffic"], "all")

        # Policy 2: LAN Malware Inspection
        p2 = next(item for item in assessments if item["policy_id"] == 2)
        self.assertEqual(p2["interface"], "lan1")
        self.assertEqual(p2["interface_context"]["role"], "LAN")
        self.assertEqual(p2["purpose"], "Interface Traffic Malware Inspection")
        self.assertEqual(p2["active_profiles"], ["antivirus"])
        av_p2 = p2["inspection_profiles"]["antivirus"]
        self.assertEqual(av_p2["configured_reference"], "av-custom")
        self.assertEqual(av_p2["activation_status"], "ENABLED")
        self.assertIs(av_p2["active"], True)
        self.assertIs(av_p2["resolved"], True)
        self.assertEqual(p2["configured_facts"]["dsri"], "enable")

        # Policy 3: Disabled profile status with resolved reference
        p3 = next(item for item in assessments if item["policy_id"] == 3)
        self.assertEqual(p3["purpose"], "Interface Traffic Monitoring / Inspection Policy")
        ips_p3 = p3["inspection_profiles"]["ips"]
        self.assertEqual(ips_p3["configured_reference"], "default")
        self.assertEqual(ips_p3["activation_status"], "DISABLED")
        self.assertIs(ips_p3["active"], False)
        self.assertIs(ips_p3["resolved"], True)
        self.assertEqual(p3["active_profiles"], [])

        # Policy 4: Unresolved profile reference while enabled
        p4 = next(item for item in assessments if item["policy_id"] == 4)
        ips_p4 = p4["inspection_profiles"]["ips"]
        self.assertEqual(ips_p4["configured_reference"], "missing-ips-sensor")
        self.assertEqual(ips_p4["activation_status"], "ENABLED")
        self.assertIs(ips_p4["active"], True)
        self.assertIs(ips_p4["resolved"], False)

        # Health check catches unresolved profile on enabled policy 4
        unresolved_profile_checks = [
            c for c in health["checks"]
            if c.get("title") == "Referenced Security Profile Could Not Be Resolved"
        ]
        self.assertTrue(len(unresolved_profile_checks) >= 1)
        evidence_lines = [e for c in unresolved_profile_checks for e in c.get("evidence", [])]
        self.assertTrue(any("missing-ips-sensor" in e for e in evidence_lines))
        # Disabled profile in Policy 3 must NOT trigger unresolved profile check
        self.assertFalse(any("default" in e for e in evidence_lines))

        # Policy 5: Disabled interface policy
        p5 = next(item for item in assessments if item["policy_id"] == 5)
        self.assertEqual(p5["purpose"], "Disabled Interface Policy")
        self.assertEqual(p5["status"], "disable")
        self.assertIs(p5["inspection_profiles"]["ips"]["active"], False)

        # Policy 6: Multi-profile security inspection
        p6 = next(item for item in assessments if item["policy_id"] == 6)
        self.assertEqual(p6["purpose"], "Interface Traffic Security Inspection")
        self.assertIn("ips", p6["active_profiles"])
        self.assertIn("antivirus", p6["active_profiles"])

        # Strict separation & negative assertions
        self.assertEqual(len(config.get("policies", [])), 0)
        self.assertEqual(len(config.get("local_in_policies", [])), 0)
        serialized = json.dumps({"config": config, "analysis": analysis, "health": health}).casefold()
        self.assertNotIn("confirmed reachable", serialized)
        self.assertNotIn("proven effective non-exposure", serialized)
        self.assertNotIn("live session", serialized)
        self.assertNotIn("forwarding authorization", serialized)

    def test_ssl_vpn_golden_fixture(self):
        """Verify SSL-VPN golden fixture static analysis, relationships, and negative assertions."""
        config, analysis, health = load_golden("ssl_vpn.conf")

        # Parser assertions
        self.assertEqual(len(config.get("ssl_vpn_settings", [])), 1)
        self.assertEqual(len(config.get("ssl_vpn_portals", [])), 2)
        self.assertEqual(len(config.get("user_locals", [])), 1)
        self.assertEqual(len(config.get("user_groups", [])), 1)
        self.assertEqual(len(config.get("policies", [])), 1)

        # User and group secret suppression
        self.assertNotIn("passwd", config["user_locals"][0])
        self.assertNotIn("password", config["user_locals"][0])

        # Analyzer assessments
        ssl_assessments = analysis.get("ssl_vpn_assessments", [])
        self.assertEqual(len(ssl_assessments), 1)
        assessment = ssl_assessments[0]

        # Settings assessment
        self.assertEqual(assessment["status"], "ENABLED")
        self.assertEqual(str(assessment["port"]), "10443")
        self.assertEqual(assessment["servercert"], "Fortinet_Factory")
        self.assertEqual(assessment["min_tls_version"], "tls1-2")

        # Listening interface resolution
        source_interfaces = assessment["source_interfaces"]
        self.assertEqual(len(source_interfaces), 1)
        self.assertEqual(source_interfaces[0]["name"], "wan1")
        self.assertTrue(source_interfaces[0]["resolved"])
        self.assertEqual(source_interfaces[0]["role"], "WAN")

        # Source address resolution
        source_addresses = assessment["source_addresses"]
        self.assertEqual(len(source_addresses), 1)
        self.assertEqual(source_addresses[0]["name"], "Restricted_Admins")
        self.assertEqual(source_addresses[0]["type"], "address")

        # Default portal resolution (predefined/builtin)
        default_portal = assessment["default_portal_resolution"]
        self.assertEqual(default_portal["name"], "full-access")
        self.assertEqual(default_portal["source"], "builtin")
        self.assertTrue(default_portal["resolved"])

        # Portals assessed
        portals = assessment["portals"]
        self.assertEqual(len(portals), 2)
        tunnel_portal = next(p for p in portals if p["name"] == "corporate-tunnel")
        self.assertEqual(tunnel_portal["tunnel_mode"], "ENABLED")
        self.assertEqual(tunnel_portal["web_mode"], "DISABLED")
        self.assertEqual(tunnel_portal["split_tunneling"], "ENABLED")
        self.assertTrue(all(a["type"] != "unknown" for a in tunnel_portal["resolved_split_routing_addresses"]))
        self.assertEqual(tunnel_portal["ip_pools"], ["SSL_VPN_Pool"])

        web_portal = next(p for p in portals if p["name"] == "vendor-web")
        self.assertEqual(web_portal["tunnel_mode"], "DISABLED")
        self.assertEqual(web_portal["web_mode"], "ENABLED")

        # Authentication rules assessed
        auth_rules = assessment["authentication_rules"]
        self.assertEqual(len(auth_rules), 3)

        # Rule 1: Group + custom portal + wan1
        rule1 = auth_rules[0]
        self.assertEqual(rule1["id"], 1)
        self.assertTrue(rule1["portal_resolution"]["resolved"])
        self.assertEqual(rule1["portal_resolution"]["source"], "custom")
        self.assertEqual(rule1["portal_resolution"]["name"], "corporate-tunnel")
        self.assertTrue(all(g["resolved"] for g in rule1["resolved_groups"]))
        self.assertTrue(all(i["resolved"] for i in rule1["source_interfaces"]))

        # Rule 2: User + custom portal
        rule2 = auth_rules[1]
        self.assertEqual(rule2["id"], 2)
        self.assertTrue(rule2["portal_resolution"]["resolved"])
        self.assertEqual(rule2["portal_resolution"]["name"], "vendor-web")
        self.assertTrue(all(u["resolved"] for u in rule2["resolved_users"]))

        # Rule 3: Unresolved group + unresolved portal
        rule3 = auth_rules[2]
        self.assertEqual(rule3["id"], 3)
        self.assertFalse(rule3["portal_resolution"]["resolved"])
        self.assertEqual(rule3["portal_resolution"]["source"], "unresolved")
        self.assertFalse(rule3["resolved_groups"][0]["resolved"])

        # Health checks catch unresolved items in Rule 3
        integrity_checks = [
            c for c in health["checks"]
            if c.get("title") == "Configuration References Could Not Be Fully Resolved"
        ]
        self.assertTrue(len(integrity_checks) >= 1)
        evidence = [e for c in integrity_checks for e in c.get("evidence", [])]
        self.assertTrue(any("nonexistent-portal" in e for e in evidence))
        self.assertTrue(any("Unresolved_Group" in e for e in evidence))

        # Built-in portal full-access must NOT be flagged as unresolved
        self.assertFalse(any("full-access" in e for e in evidence))

        # Forwarding policy ssl.root is separate
        fwd_policy = analysis["policy_assessments"][0]
        self.assertEqual(fwd_policy["policy_id"], 1)
        self.assertEqual(fwd_policy["source_interfaces"][0]["name"], "ssl.root")

        # Strict negative assertions: no claims of reachability, active sessions, authentication
        serialized = json.dumps({"config": config, "analysis": analysis, "health": health}).casefold()
        self.assertNotIn("confirmed reachable", serialized)
        self.assertNotIn("proven effective non-exposure", serialized)
        self.assertNotIn("active session", serialized)
        self.assertNotIn("successful authentication", serialized)
        self.assertNotIn("live session", serialized)

    def test_ipv6_golden_fixture(self):
        """Verify ipv6.conf golden fixture static analysis, relationships, and negative assertions."""
        config, analysis, health = load_golden("ipv6.conf")

        # Parser assertions
        self.assertEqual(len(config.get("policies", [])), 5)
        self.assertEqual(len(config.get("addresses6", [])), 4)
        self.assertEqual(len(config.get("address_groups6", [])), 1)
        self.assertEqual(len(config.get("vips6", [])), 1)
        self.assertEqual(len(config.get("local_in_policies6", [])), 2)
        self.assertEqual(len(config.get("interface_policies6", [])), 1)

        # Forwarding policy family assertions
        policies = analysis["policy_assessments"]
        self.assertEqual(policies[0]["address_family"], "IPv4")
        self.assertEqual(policies[1]["address_family"], "IPv6")
        self.assertEqual(policies[2]["address_family"], "IPv6")
        self.assertEqual(policies[3]["address_family"], "IPv6")
        self.assertEqual(policies[4]["address_family"], "IPv6")

        # Policy 3 shadowed by Policy 2 (same IPv6 family)
        shadow_findings = [
            f for f in analysis["findings"]
            if f.get("title") == "Fully Shadowed Firewall Policy"
        ]
        self.assertEqual(len(shadow_findings), 1)
        self.assertEqual(shadow_findings[0]["policy_id"], 3)
        self.assertEqual(shadow_findings[0]["shadowed_by_policy_id"], 2)

        # Local-in policies (IPv6)
        lip_assessments = analysis["local_in_policy6_assessments"]
        self.assertEqual(len(lip_assessments), 2)
        self.assertEqual(lip_assessments[0]["address_family"], "IPv6")
        self.assertEqual(lip_assessments[0]["action"], "deny")
        self.assertEqual(lip_assessments[1]["address_family"], "IPv6")
        self.assertEqual(lip_assessments[1]["action"], "accept")

        # Interface policies (IPv6)
        ip_assessments = analysis["interface_policy6_assessments"]
        self.assertEqual(len(ip_assessments), 1)
        self.assertEqual(ip_assessments[0]["address_family"], "IPv6")
        ips_profile = ip_assessments[0]["inspection_profiles"]["ips"]
        self.assertTrue(ips_profile["active"])
        self.assertTrue(ips_profile["resolved"])

        # SSL-VPN IPv6 settings
        ssl_assessments = analysis["ssl_vpn_assessments"]
        self.assertEqual(len(ssl_assessments), 1)
        ssl = ssl_assessments[0]
        self.assertEqual(len(ssl["resolved_sources6"]), 1)
        self.assertEqual(ssl["resolved_sources6"][0]["name"], "CORP_NET6")
        self.assertEqual(len(ssl["authentication_rules"][0]["resolved_addresses6"]), 1)

        # Strict negative assertions
        serialized = json.dumps({"config": config, "analysis": analysis, "health": health}).casefold()
        self.assertNotIn("confirmed reachable", serialized)
        self.assertNotIn("proven effective non-exposure", serialized)
        self.assertNotIn("active session", serialized)
        self.assertNotIn("successful authentication", serialized)
        self.assertNotIn("live session", serialized)


if __name__ == "__main__":
    unittest.main()



