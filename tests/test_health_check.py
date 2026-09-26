"""Unit tests for health_check.py baseline behavior."""

import os
import unittest
from parser import parse_configuration
from health_check import run_health_check
from analyzer import analyze_configuration


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> str:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


class TestHealthCheck(unittest.TestCase):

    def setUp(self):
        self.basic_config = parse_configuration(read_fixture("basic.conf"))
        self.basic_health = run_health_check(self.basic_config)
        self.hardening_config = parse_configuration(read_fixture("hardening.conf"))
        self.hardening_health = run_health_check(self.hardening_config)
        self.vpn_config = parse_configuration(read_fixture("vpn.conf"))
        self.vpn_health = run_health_check(self.vpn_config)
        self.profile_config = parse_configuration(read_fixture("profiles.conf"))
        self.profile_health = run_health_check(self.profile_config)
        self.v4_config = parse_configuration(read_fixture("health_v4.conf"))
        self.v4_health = run_health_check(self.v4_config)

    def test_admin_wan_management_protocols(self):
        checks = self.hardening_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("Insecure HTTP Management Exposed on WAN", titles)
        self.assertIn("Telnet Management Exposed on WAN", titles)
        self.assertIn("Remote Management Accessible from WAN", titles)

    def test_admin_trusted_host_restrictions(self):
        checks = self.hardening_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("Administrative Access Lacks Trusted Host Restrictions", titles)

    def test_inbound_policy_missing_ips(self):
        # basic.conf policy 30 is WAN -> LAN ACCEPT without IPS
        checks = self.basic_health["checks"]
        ips_checks = [c for c in checks if c["title"] == "IPS Not Detected on Internet-Facing Policy"]
        self.assertTrue(len(ips_checks) >= 1)

    def test_outbound_internet_policy_no_profiles(self):
        # basic.conf policy 40 is LAN/port2 -> DMZ (internal), policy 10 has AV/Webfilter
        # Let's test with a config having outbound internet policy with no profiles
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
    edit "port2"
        set role lan
    next
end
config firewall policy
    edit 100
        set name "Outbound No Profile"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        cfg = parse_configuration(config_text)
        res = run_health_check(cfg)
        titles = {c["title"] for c in res["checks"]}
        self.assertIn("No Security Profiles Detected on Outbound Internet Policy", titles)

    def test_unresolved_profile_reference(self):
        checks = self.profile_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("Referenced Security Profile Could Not Be Resolved", titles)

    def test_utm_enable_no_detected_profiles(self):
        checks = self.profile_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("UTM Enabled Without Detected Security Profiles", titles)

    def test_utm_disabled_profile_referenced(self):
        checks = self.profile_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("Security Profile Referenced While UTM Is Disabled", titles)

    def test_logging_explicit_disable_vs_absent(self):
        # basic.conf policy 30 has explicit "set logtraffic disable"
        # Analyzer emits "Logging Disabled on Security-Relevant Policy", so health check suppresses duplicate check
        checks = self.basic_health["checks"]
        logging_checks = [c for c in checks if "Logging" in c["title"]]
        self.assertEqual(len(logging_checks), 0)

        # When analysis_result has empty findings (no analyzer logging finding), health check falls back to emitting it
        empty_analysis = {"policy_assessments": parse_configuration(read_fixture("basic.conf"))}
        fallback_health = run_health_check(self.basic_config, analysis_result={"policy_assessments": self.basic_config["policies"], "findings": []})
        # Policy with absent logtraffic line must NOT trigger "Traffic Logging Disabled" check
        config_text = """
config system interface
    edit "port1"
        set role wan
    next
    edit "port2"
        set role lan
    next
end
config firewall policy
    edit 200
        set name "No Logtraffic Setting"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""
        cfg = parse_configuration(config_text)
        res = run_health_check(cfg)
        log_disabled_titles = [c["title"] for c in res["checks"] if "Logging Disabled" in c["title"]]
        self.assertEqual(len(log_disabled_titles), 0)

    def test_configuration_hygiene_aggregated_disabled_policies(self):
        checks = self.basic_health["checks"]
        disabled_checks = [c for c in checks if c["title"] == "Disabled Firewall Policies Present"]
        self.assertEqual(len(disabled_checks), 1)
        evidence = disabled_checks[0]["evidence"]
        self.assertTrue(any("Disabled policies detected: 1" in e for e in evidence))

    def test_configuration_integrity_unresolved_and_builtins(self):
        # basic.conf policy 10 uses built-ins "all", "port1", "port2", "LAN_NET", "WEB_SERVICES" -> all resolved
        # Now test an unresolved reference
        config_text = """
config system interface
    edit "port1"
        set role lan
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "MISSING_INTF"
        set srcaddr "MISSING_ADDR"
        set dstaddr "all"
        set action accept
        set service "MISSING_SVC"
    next
end
"""
        cfg = parse_configuration(config_text)
        res = run_health_check(cfg)
        integrity_checks = [c for c in res["checks"] if c["title"] == "Configuration References Could Not Be Fully Resolved"]
        self.assertEqual(len(integrity_checks), 1)
        evidence = integrity_checks[0]["evidence"]
        self.assertTrue(any("MISSING_INTF" in e for e in evidence))

    def test_no_false_configuration_integrity_for_vdom_root_interface_zone_sdwan_any(self):
        config_text = """
config system interface
    edit "port1"
        set vdom "root"
        set role lan
    next
    edit "port2"
        set vdom "root"
        set role wan
    next
    edit "port3"
        set vdom "root"
        set role wan
    next
end
config system zone
    edit "LAN_ZONE"
        set interface "port1"
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
            set interface "port2"
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
        set srcintf "LAN_ZONE"
        set dstintf "SD-WAN"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 2
        set srcintf "any"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        cfg = parse_configuration(config_text)
        res = run_health_check(cfg)
        integrity_checks = [
            c for c in res["checks"]
            if c["title"] == "Configuration References Could Not Be Fully Resolved"
        ]
        self.assertEqual(len(integrity_checks), 0)

    def test_vpn_modern_ikev2_no_findings(self):
        # vpn.conf P1_MODERN & P2_MODERN
        checks = self.vpn_health["checks"]
        modern_evidence = [c for c in checks if any("P1_MODERN" in e or "P2_MODERN" in e for e in c.get("evidence", []))]
        # P1_MODERN and P2_MODERN are clean AES256-SHA256, IKEv2, DH 14/19, PFS enabled, specific subnets
        self.assertEqual(len(modern_evidence), 0)

    def test_vpn_legacy_crypto(self):
        checks = self.vpn_health["checks"]
        crypto_checks = [c for c in checks if c["title"] == "Legacy Cryptographic Algorithm Detected"]
        self.assertTrue(len(crypto_checks) >= 1)

    def test_vpn_legacy_dh_group(self):
        checks = self.vpn_health["checks"]
        dh_checks = [c for c in checks if c["title"] == "Legacy Diffie-Hellman Group Detected"]
        self.assertTrue(len(dh_checks) >= 1)

    def test_vpn_ikev1(self):
        checks = self.vpn_health["checks"]
        ike1_checks = [c for c in checks if c["title"] == "IKEv1 Configuration Detected"]
        self.assertEqual(len(ike1_checks), 1)

    def test_vpn_pfs_disabled(self):
        checks = self.vpn_health["checks"]
        pfs_checks = [c for c in checks if c["title"] == "Perfect Forward Secrecy Disabled"]
        self.assertEqual(len(pfs_checks), 1)

    def test_vpn_broad_selectors(self):
        checks = self.vpn_health["checks"]
        broad_checks = [c for c in checks if c["title"] == "Broad IPsec Traffic Selectors"]
        self.assertEqual(len(broad_checks), 1)

    def test_vpn_missing_phase1_relationship(self):
        checks = self.vpn_health["checks"]
        missing_p1 = [c for c in checks if c["title"] == "IPsec Phase 2 References Unknown Phase 1"]
        self.assertEqual(len(missing_p1), 1)

    def test_system_hardening_checks(self):
        checks = self.hardening_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("SSH Version 1 Enabled for Administration", titles)
        self.assertIn("Legacy TLS Version Enabled for Administrative HTTPS", titles)
        self.assertIn("Strong Cryptography Mode Disabled", titles)
        self.assertIn("Long Administrative Session Timeout", titles)

    def test_ntp_health_checks(self):
        # hardening.conf has ntpsync disable -> triggers "NTP Synchronization Disabled"
        checks = self.hardening_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("NTP Synchronization Disabled", titles)

        # Config with NTP enabled and server configured -> no NTP finding
        config_text = """
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "pool.ntp.org"
        next
    end
end
"""
        cfg = parse_configuration(config_text)
        res = run_health_check(cfg)
        ntp_titles = [c["title"] for c in res["checks"] if "NTP" in c["title"]]
        self.assertEqual(len(ntp_titles), 0)

    def test_dns_health_checks(self):
        # hardening.conf has config system dns with no primary/secondary -> triggers DNS Server Configuration Could Not Be Confirmed
        checks = self.hardening_health["checks"]
        titles = {c["title"] for c in checks}
        self.assertIn("DNS Server Configuration Could Not Be Confirmed", titles)

    def test_secret_safety_in_parsed_data_and_evidence(self):
        # Verify secrets (passwords, PSKs, etc.) NEVER leak into evidence or parsed configuration data
        all_checks = (
            self.basic_health["checks"]
            + self.hardening_health["checks"]
            + self.vpn_health["checks"]
            + self.profile_health["checks"]
        )
        forbidden_tokens = [
            "SUPER_SECRET_PSK",
            "ANOTHER_SECRET_PSK",
            "HASHED_ADMIN_PASSWORD_SECRET",
            "ENC_HASH_12345",
        ]
        for check in all_checks:
            for text_field in (
                check.get("title", ""),
                check.get("description", ""),
                check.get("recommendation", ""),
                " ".join(check.get("evidence", [])),
            ):
                for secret in forbidden_tokens:
                    self.assertNotIn(secret, text_field)

    def test_multivdom_health_uses_scoped_analysis_results(self):
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
        config = parse_configuration(config_text)
        analysis = analyze_configuration(config)
        health = run_health_check(config, analysis_result=analysis)
        checks = health["checks"]

        integrity = next(
            check
            for check in checks
            if check["title"]
            == "Configuration References Could Not Be Fully Resolved"
        )
        unresolved_profiles = next(
            check
            for check in checks
            if check["title"]
            == "Referenced Security Profile Could Not Be Resolved"
        )
        self.assertTrue(
            any(
                "VDOM: root" in evidence and "BRANCH_ONLY" in evidence
                for evidence in integrity["evidence"]
            )
        )
        self.assertTrue(
            any(
                "VDOM: root" in evidence and "BRANCH_IPS" in evidence
                for evidence in unresolved_profiles["evidence"]
            )
        )

    def test_multivdom_ipsec_parent_resolution_is_scope_isolated(self):
        config_text = """
config vdom
    edit "root"
        config vpn ipsec phase2-interface
            edit "ROOT_P2"
                set phase1name "SHARED_P1"
                set proposal aes256-sha256
            next
        end
    next
    edit "VDOM-B"
        config vpn ipsec phase1-interface
            edit "SHARED_P1"
                set ike-version 2
                set proposal aes256-sha256
            next
        end
    next
end
"""
        health = run_health_check(parse_configuration(config_text))
        missing_parent = [
            check
            for check in health["checks"]
            if check["title"]
            == "IPsec Phase 2 References Unknown Phase 1"
        ]

        self.assertEqual(len(missing_parent), 1)
        self.assertIn("VDOM: root", missing_parent[0]["evidence"])

    def test_admin_two_factor_disabled_and_enabled_behavior(self):
        findings = [
            check
            for check in self.v4_health["checks"]
            if check["title"]
            == "Two-Factor Authentication Disabled for Administrator"
        ]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        evidence = " ".join(findings[0]["evidence"])
        self.assertIn("admin_no_2fa", evidence)
        self.assertNotIn("admin_with_2fa", evidence)
        self.assertNotIn("disabled_admin", evidence)

    def test_long_administrator_idle_timeout(self):
        finding = next(
            check
            for check in self.v4_health["checks"]
            if check["title"] == "Long Administrator Idle Timeout"
        )
        self.assertEqual(finding["severity"], "LOW")
        self.assertIn("admintimeout: 45", finding["evidence"])

    def test_telnet_administration_enabled(self):
        finding = next(
            check
            for check in self.v4_health["checks"]
            if check["title"] == "Telnet Administration Enabled"
        )
        self.assertEqual(finding["severity"], "HIGH")

    def test_custom_administrative_ports_are_inventory_only(self):
        titles = {check["title"] for check in self.v4_health["checks"]}
        self.assertFalse(any("Port" in title for title in titles))
        self.assertEqual(self.v4_config["system_global"]["admin-ssh-port"], "2222")
        self.assertEqual(self.v4_config["system_global"]["admin-sport"], "8443")

    def test_https_redirect_disabled(self):
        finding = next(
            check
            for check in self.v4_health["checks"]
            if check["title"]
            == "HTTP-to-HTTPS Administrative Redirect Disabled"
        )
        self.assertEqual(finding["severity"], "LOW")

    def test_password_policy_disabled(self):
        config = parse_configuration(
            """
config system password-policy
    set status disable
end
"""
        )
        titles = {check["title"] for check in run_health_check(config)["checks"]}
        self.assertIn("Administrator Password Policy Disabled", titles)

    def test_password_policy_short_minimum_length(self):
        finding = next(
            check
            for check in self.v4_health["checks"]
            if check["title"]
            == "Short Administrator Password Minimum Length"
        )
        self.assertEqual(finding["severity"], "LOW")
        self.assertIn("minimum-length: 8", finding["evidence"])

    def test_cli_and_implicit_logging_disabled(self):
        checks_by_title = {
            check["title"]: check for check in self.v4_health["checks"]
        }
        self.assertEqual(
            checks_by_title["CLI Audit Logging Disabled"]["severity"], "MEDIUM"
        )
        self.assertEqual(
            checks_by_title["Implicit Policy Logging Disabled"]["severity"],
            "LOW",
        )

    def test_policy_packet_capture_and_offload_results(self):
        checks_by_title = {
            check["title"]: check for check in self.v4_health["checks"]
        }
        capture = checks_by_title["Packet Capture Enabled on Firewall Policy"]
        offload = checks_by_title["Hardware Offload Disabled on Firewall Policy"]

        self.assertEqual(capture["severity"], "LOW")
        self.assertEqual(capture["category"], "Configuration Hygiene")
        self.assertEqual(capture["policy_id"], 100)
        self.assertEqual(offload["severity"], "INFO")
        self.assertEqual(offload["category"], "Operational Review")
        self.assertEqual(self.v4_health["summary"]["info"], 1)

    def test_logtraffic_start_is_inventory_only(self):
        titles = {check["title"].casefold() for check in self.v4_health["checks"]}
        self.assertFalse(any("log traffic start" in title for title in titles))
        policy = next(item for item in self.v4_config["policies"] if item["id"] == 100)
        self.assertEqual(policy["logtraffic-start"], "enable")

    def test_antivirus_and_ips_fail_open(self):
        checks_by_title = {
            check["title"]: check for check in self.v4_health["checks"]
        }
        self.assertEqual(
            checks_by_title["Antivirus Fail-Open Behavior Enabled"]["severity"],
            "MEDIUM",
        )
        self.assertIn(
            "av-failopen: pass",
            checks_by_title["Antivirus Fail-Open Behavior Enabled"]["evidence"],
        )
        self.assertEqual(
            checks_by_title["IPS Fail-Open Behavior Enabled"]["severity"],
            "MEDIUM",
        )

    def test_ips_traffic_submit_and_dos_inventory_do_not_warn(self):
        titles = {check["title"].casefold() for check in self.v4_health["checks"]}
        self.assertFalse(any("traffic submit" in title for title in titles))
        self.assertFalse(any("dos policy" in title for title in titles))
        self.assertEqual(self.v4_config["ips_global"]["traffic-submit"], "enable")
        self.assertEqual(len(self.v4_config["dos_policies"]), 1)

    def test_v4_multivdom_checks_remain_scope_isolated(self):
        config_text = """
config vdom
    edit "root"
        config antivirus settings
            set av-failopen pass
        end
        config ips global
            set fail-open enable
        end
        config log setting
            set implicit-log disable
        end
    next
    edit "VDOM-B"
        config antivirus settings
            set av-failopen off
        end
        config ips global
            set fail-open disable
        end
        config log setting
            set implicit-log enable
        end
    next
end
"""
        checks = run_health_check(parse_configuration(config_text))["checks"]
        scoped_checks = [
            check
            for check in checks
            if check["title"]
            in {
                "Antivirus Fail-Open Behavior Enabled",
                "IPS Fail-Open Behavior Enabled",
                "Implicit Policy Logging Disabled",
            }
        ]

        self.assertEqual(len(scoped_checks), 3)
        self.assertTrue(all(check.get("vdom") == "root" for check in scoped_checks))


from unittest.mock import patch
class TestPipelineRefactor(unittest.TestCase):

    def setUp(self):
        self.config = parse_configuration(read_fixture("basic.conf"))

    def test_run_health_check_without_analysis_result(self):
        result = run_health_check(self.config)
        self.assertIn("checks", result)
        self.assertIn("summary", result)
        self.assertTrue(result["summary"]["total"] >= 1)

    def test_run_health_check_with_analysis_result(self):
        analysis = analyze_configuration(self.config)
        result_with = run_health_check(self.config, analysis_result=analysis)
        result_without = run_health_check(self.config)
        self.assertEqual(result_with, result_without)

    @patch("health_check.analyze_configuration")
    def test_analyze_configuration_not_called_when_supplied(self, mock_analyze):
        analysis = analyze_configuration(self.config)
        mock_analyze.reset_mock()
        run_health_check(self.config, analysis_result=analysis)
        mock_analyze.assert_not_called()

    @patch("health_check.analyze_configuration")
    def test_health_helpers_do_not_rerun_analyze(self, mock_analyze):
        analysis = analyze_configuration(self.config)
        mock_analyze.reset_mock()
        from health_check import _policy_health_checks, _configuration_integrity_check
        _policy_health_checks(self.config, analysis)
        _configuration_integrity_check(self.config, analysis)
        mock_analyze.assert_not_called()

    def test_logging_finding_duplication_suppressed(self):
        analysis = analyze_configuration(self.config)
        # Verify analyzer emitted the finding for policy 30
        analyzer_logging_findings = [f for f in analysis["findings"] if f.get("policy_id") == 30 and f.get("title") == "Logging Disabled on Security-Relevant Policy"]
        self.assertEqual(len(analyzer_logging_findings), 1)

        health = run_health_check(self.config, analysis_result=analysis)
        # Verify health check suppressed duplicate check for policy 30
        health_logging_checks = [c for c in health["checks"] if c.get("policy_id") == 30 and "Logging" in c.get("title", "")]
        self.assertEqual(len(health_logging_checks), 0)

    @patch("health_check.analyze_configuration", wraps=analyze_configuration)
    def test_performance_sanity_call_count(self, mock_analyze):
        # Synthetic flow: exactly 1 call to analyze_configuration in total
        config = parse_configuration(read_fixture("basic.conf"))
        analysis = mock_analyze(config)
        self.assertEqual(mock_analyze.call_count, 1)

        run_health_check(config, analysis_result=analysis)
        # Must still be exactly 1 call!
        self.assertEqual(mock_analyze.call_count, 1)


if __name__ == "__main__":
    unittest.main()

    unittest.main()
