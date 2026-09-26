"""Unit tests for parser.py baseline behavior."""

import os
import unittest
from parser import parse_configuration, parse_firewall_policies, parse_admins, parse_ipsec_phase1


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(filename: str) -> str:
    with open(os.path.join(FIXTURES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


class TestParser(unittest.TestCase):

    def test_policy_order_and_sequence_index(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        policies = parsed["policies"]
        self.assertEqual(len(policies), 5)
        # Policy IDs are 10, 20, 30, 40, 50
        self.assertEqual([p["id"] for p in policies], [10, 20, 30, 40, 50])
        # sequence_index should be 0..4 in exact configuration order
        self.assertEqual([p["sequence_index"] for p in policies], [0, 1, 2, 3, 4])

    def test_interfaces_role_and_allowaccess(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        interfaces = parsed["interfaces"]
        self.assertTrue(any(i["name"] == "port1" and i.get("role") == "wan" for i in interfaces))
        port1 = next(i for i in interfaces if i["name"] == "port1")
        self.assertEqual(port1.get("allowaccess"), ["ping", "https", "ssh"])

    def test_addresses_subnet_range_fqdn(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        addresses = parsed["addresses"]
        lan_net = next(a for a in addresses if a["name"] == "LAN_NET")
        self.assertEqual(lan_net.get("subnet"), ["10.0.0.0", "255.255.255.0"])
        web_server = next(a for a in addresses if a["name"] == "WEB_SERVER")
        self.assertEqual(web_server.get("fqdn"), "web.example.com")

    def test_address_groups(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        groups = parsed["address_groups"]
        internal = next(g for g in groups if g["name"] == "INTERNAL_SERVERS")
        self.assertEqual(internal.get("member"), ["SERVER_1"])

    def test_custom_services(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        services = parsed["services"]
        custom_8080 = next(s for s in services if s["name"] == "CUSTOM_8080")
        self.assertEqual(custom_8080.get("tcp-portrange"), "8080")

    def test_service_groups(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        groups = parsed["service_groups"]
        web_services = next(g for g in groups if g["name"] == "WEB_SERVICES")
        self.assertEqual(web_services.get("member"), ["HTTP", "HTTPS", "CUSTOM_8080"])

    def test_vips(self):
        config_text = read_fixture("basic.conf")
        parsed = parse_configuration(config_text)
        vips = parsed["vips"]
        vip = next(v for v in vips if v["name"] == "VIP_WEB")
        self.assertEqual(vip.get("extip"), "203.0.113.10")
        self.assertEqual(vip.get("mappedip"), "10.0.0.50")
        self.assertEqual(vip.get("extport"), "443")
        self.assertEqual(vip.get("mappedport"), "8443")

    def test_admins_whitelisted_fields(self):
        config_text = read_fixture("hardening.conf")
        parsed = parse_configuration(config_text)
        admins = parsed["admins"]
        self.assertEqual(len(admins), 2)
        admin = next(a for a in admins if a["name"] == "admin")
        self.assertEqual(admin.get("accprofile"), "super_admin")
        self.assertEqual(admin.get("trusthost1"), ["0.0.0.0", "0.0.0.0"])

    def test_secrets_excluded_admin(self):
        config_text = read_fixture("hardening.conf")
        admins = parse_admins(config_text)
        for admin in admins:
            self.assertNotIn("password", admin)
            self.assertNotIn("password_hash", admin)
            self.assertNotIn("secret", admin)

    def test_ipsec_phase1_phase2(self):
        config_text = read_fixture("vpn.conf")
        parsed = parse_configuration(config_text)
        p1 = parsed["ipsec_phase1"]
        p2 = parsed["ipsec_phase2"]
        self.assertEqual(len(p1), 2)
        self.assertEqual(len(p2), 3)

        p1_legacy = next(p for p in p1 if p["name"] == "P1_LEGACY")
        self.assertEqual(p1_legacy.get("ike-version"), "1")
        self.assertEqual(p1_legacy.get("proposal"), ["3des-sha1", "des-md5"])
        self.assertEqual(p1_legacy.get("dhgrp"), ["1", "2", "5"])

        p2_legacy = next(p for p in p2 if p["name"] == "P2_LEGACY")
        self.assertEqual(p2_legacy.get("phase1name"), "P1_LEGACY")
        self.assertEqual(p2_legacy.get("pfs"), "disable")

    def test_secrets_excluded_vpn(self):
        config_text = read_fixture("vpn.conf")
        p1 = parse_ipsec_phase1(config_text)
        for phase in p1:
            self.assertNotIn("psksecret", phase)
            self.assertNotIn("psk", phase)
            self.assertNotIn("private-key", phase)

    def test_system_global_dns_ntp(self):
        config_text = read_fixture("hardening.conf")
        parsed = parse_configuration(config_text)
        sys_global = parsed["system_global"]
        dns = parsed["dns"]
        ntp = parsed["ntp"]

        self.assertEqual(sys_global.get("hostname"), "FortiGate-Core")
        self.assertEqual(sys_global.get("admin-ssh-v1"), "enable")
        self.assertEqual(sys_global.get("strong-crypto"), "disable")
        self.assertEqual(dns.get("domain"), "example.local")
        self.assertEqual(dns.get("_configured"), True)
        self.assertEqual(ntp.get("ntpsync"), "disable")

    def test_security_profiles_names(self):
        config_text = read_fixture("profiles.conf")
        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["ips_sensors"]), 1)
        self.assertEqual(parsed["ips_sensors"][0]["name"], "custom_ips")
        self.assertEqual(parsed["antivirus_profiles"][0]["name"], "custom_av")
        self.assertEqual(parsed["webfilter_profiles"][0]["name"], "custom_wf")
        self.assertEqual(parsed["application_lists"][0]["name"], "custom_app")
        self.assertEqual(parsed["ssl_ssh_profiles"][0]["name"], "custom_ssl")
        self.assertEqual(parsed["dnsfilter_profiles"][0]["name"], "custom_dns")

    def test_nested_security_profile_does_not_crash(self):
        config_text = read_fixture("profiles.conf")
        parsed = parse_configuration(config_text)
        ips = parsed["ips_sensors"][0]
        self.assertEqual(ips["name"], "custom_ips")
        self.assertEqual(ips.get("comment"), "Custom IPS Sensor")

    def test_multiblock_multivdom_behavior(self):
        """Repeated policy blocks are all parsed in configuration order."""
        multiblock_config = """
config firewall policy
    edit 1
        set name "Policy VDOM 1"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
config firewall policy
    edit 2
        set name "Policy VDOM 2"
        set srcintf "port3"
        set dstintf "port4"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        policies = parse_firewall_policies(multiblock_config)
        self.assertEqual([policy["id"] for policy in policies], [1, 2])
        self.assertEqual(
            [policy["sequence_index"] for policy in policies], [0, 1]
        )
        self.assertTrue(all(policy["vdom"] is None for policy in policies))

    def test_multivdom_policies_and_sequence_indexes(self):
        parsed = parse_configuration(read_fixture("multivdom.conf"))
        policies = parsed["policies"]

        self.assertEqual(len(policies), 5)
        root_policies = [p for p in policies if p["vdom"] == "root"]
        branch_policies = [p for p in policies if p["vdom"] == "VDOM-B"]
        self.assertEqual(
            [policy["sequence_index"] for policy in root_policies],
            [0, 1, 2],
        )
        self.assertEqual(
            [policy["sequence_index"] for policy in branch_policies],
            [0, 1],
        )

    def test_multivdom_repeated_object_sections_preserve_scope(self):
        parsed = parse_configuration(read_fixture("multivdom.conf"))
        scoped_collections = (
            "interfaces",
            "addresses",
            "services",
            "service_groups",
            "vips",
            "ips_sensors",
            "ipsec_phase1",
        )

        for collection_name in scoped_collections:
            scopes = {item["vdom"] for item in parsed[collection_name]}
            self.assertEqual(scopes, {"root", "VDOM-B"}, collection_name)

    def test_global_sections_remain_global_in_multivdom_backup(self):
        parsed = parse_configuration(read_fixture("multivdom.conf"))

        self.assertEqual(
            parsed["system_global"].get("hostname"), "MultiVDOM-FortiGate"
        )
        self.assertEqual(parsed["dns"].get("primary"), "192.0.2.53")
        self.assertEqual(
            parsed["ntp"].get("servers", [])[0].get("server"),
            "time.example.net",
        )

    def test_multivdom_secret_suppression(self):
        parsed = parse_configuration(read_fixture("multivdom.conf"))
        serialized = repr(parsed)

        for secret in (
            "ROOT_PROFILE_SECRET",
            "BRANCH_PRIVATE_SECRET",
            "ROOT_PSK_SECRET",
            "BRANCH_PSK_SECRET",
        ):
            self.assertNotIn(secret, serialized)

    def test_health_v4_administrator_and_global_fields(self):
        parsed = parse_configuration(read_fixture("health_v4.conf"))
        system_global = parsed["system_global"]
        admin = next(
            item for item in parsed["admins"] if item["name"] == "admin_no_2fa"
        )

        self.assertEqual(system_global["admintimeout"], "45")
        self.assertEqual(system_global["admin-telnet"], "enable")
        self.assertEqual(system_global["admin-ssh-port"], "2222")
        self.assertEqual(system_global["admin-sport"], "8443")
        self.assertEqual(system_global["admin-https-redirect"], "disable")
        self.assertEqual(system_global["cli-audit-log"], "disable")
        self.assertEqual(admin["two-factor"], "disable")

    def test_health_v4_settings_inventory(self):
        parsed = parse_configuration(read_fixture("health_v4.conf"))

        self.assertEqual(parsed["password_policy"]["minimum-length"], "8")
        self.assertEqual(parsed["log_setting"]["implicit-log"], "disable")
        self.assertEqual(
            parsed["antivirus_setting"]["av-failopen"], "pass"
        )
        self.assertEqual(
            parsed["antivirus_setting"]["traffic-submit"], "enable"
        )
        self.assertEqual(parsed["ips_global"]["fail-open"], "enable")
        self.assertEqual(parsed["ips_global"]["traffic-submit"], "enable")

    def test_health_v4_policy_operational_fields(self):
        parsed = parse_configuration(read_fixture("health_v4.conf"))
        policy = next(item for item in parsed["policies"] if item["id"] == 100)

        self.assertEqual(policy["inspection-mode"], "flow")
        self.assertEqual(policy["logtraffic-start"], "enable")
        self.assertEqual(policy["capture-packet"], "enable")
        self.assertEqual(policy["auto-asic-offload"], "disable")

    def test_dos_policy_inventory_and_anomalies(self):
        parsed = parse_configuration(read_fixture("health_v4.conf"))
        policy = parsed["dos_policies"][0]

        self.assertEqual(policy["id"], 1)
        self.assertEqual(policy["name"], "WAN DoS Inventory")
        self.assertEqual(policy["interface"], "wan")
        self.assertEqual(policy["srcaddr"], ["all"])
        self.assertEqual(policy["anomalies"], ["tcp_syn_flood", "udp_flood"])

    def test_health_v4_multivdom_settings_and_dos_scope(self):
        config_text = """
config vdom
    edit "root"
        config antivirus settings
            set av-failopen pass
        end
        config firewall DoS-policy
            edit 1
                set interface "wan1"
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
            next
        end
    next
    edit "VDOM-B"
        config antivirus settings
            set av-failopen off
        end
        config firewall DoS-policy
            edit 1
                set interface "wan2"
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
            next
        end
    next
end
"""
        parsed = parse_configuration(config_text)

        self.assertEqual(
            {item["vdom"] for item in parsed["antivirus_settings"]},
            {"root", "VDOM-B"},
        )
        self.assertEqual(
            {(item["vdom"], item["sequence_index"]) for item in parsed["dos_policies"]},
            {("root", 0), ("VDOM-B", 0)},
        )

    def test_health_v4_secret_suppression(self):
        parsed = parse_configuration(read_fixture("health_v4.conf"))
        serialized = repr(parsed)

        for secret in (
            "ADMIN_PASSWORD_SECRET",
            "TOKEN_SECRET",
            "PASSWORD_POLICY_SECRET",
            "ANTIVIRUS_PRIVATE_SECRET",
            "IPS_TOKEN_SECRET",
        ):
            self.assertNotIn(secret, serialized)

    def test_interface_preserves_parser_vdom_and_stores_configured_vdom(self):
        config_text = """
config system interface
    edit "wan1"
        set vdom "root"
        set role wan
        set alias "WAN-ISP"
    next
end
"""
        parsed = parse_configuration(config_text)
        self.assertEqual(len(parsed["interfaces"]), 1)
        intf = parsed["interfaces"][0]
        self.assertIsNone(intf.get("vdom"))
        self.assertEqual(intf.get("configured_vdom"), "root")
        self.assertEqual(intf.get("role"), "wan")
        self.assertEqual(intf.get("alias"), "WAN-ISP")

    def test_system_zones_parsing(self):
        config_text = """
config system zone
    edit "emir_LOCAL"
        set intrazone allow
        set interface "port2" "port3"
    next
    edit "DMZ_ZONE"
        set interface "port4"
    next
end
"""
        parsed = parse_configuration(config_text)
        zones = parsed["zones"]
        self.assertEqual(len(zones), 2)
        local_zone = next(z for z in zones if z["name"] == "emir_LOCAL")
        self.assertEqual(local_zone["interfaces"], ["port2", "port3"])
        self.assertIsNone(local_zone.get("vdom"))
        dmz_zone = next(z for z in zones if z["name"] == "DMZ_ZONE")
        self.assertEqual(dmz_zone["interfaces"], ["port4"])

    def test_sdwan_parsing(self):
        config_text = """
config system sdwan
    set status enable
    config zone
        edit "SD-WAN"
        next
    end
    config members
        edit 1
            set interface "port5"
            set zone "SD-WAN"
            set gateway 192.168.1.1
        next
        edit 2
            set interface "port3"
            set zone "SD-WAN"
            set gateway 192.168.2.1
        next
    end
end
"""
        parsed = parse_configuration(config_text)
        sdwan = parsed["sdwan"]
        self.assertEqual(sdwan["status"], "enable")
        self.assertEqual(len(sdwan["zones"]), 1)
        zone = sdwan["zones"][0]
        self.assertEqual(zone["name"], "SD-WAN")
        self.assertEqual(zone["interfaces"], ["port5", "port3"])
        self.assertEqual(len(sdwan["members"]), 2)
        m1 = next(m for m in sdwan["members"] if m["id"] == 1)
        self.assertEqual(m1["interface"], "port5")
        self.assertEqual(m1["gateway"], "192.168.1.1")


if __name__ == "__main__":
    unittest.main()

