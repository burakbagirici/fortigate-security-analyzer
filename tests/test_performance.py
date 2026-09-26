"""Architectural, regression, and performance tests for FortiOS parsing engine."""

import unittest
from unittest.mock import patch

from analyzer import analyze_configuration
from health_check import run_health_check
import parser
from parser import (
    ParserContext,
    build_block_index,
    parse_configuration,
    parse_interfaces,
    parse_firewall_policies,
    detect_section_presence,
    assess_input_quality,
)


class TestParserArchitecture(unittest.TestCase):
    """Verify architectural invariants of the single-pass parser."""

    def test_single_annotated_scan_during_parse_configuration(self):
        """parse_configuration must invoke _annotated_config_lines exactly once."""
        sample_config = """
        # config-version=FG60E-7.0.5-build1234
        config system interface
            edit "port1"
                set role lan
            next
        end
        config firewall policy
            edit 1
                set srcintf "port1"
                set dstintf "port2"
                set action accept
            next
        end
        """
        with patch.object(
            parser, "_annotated_config_lines", wraps=parser._annotated_config_lines
        ) as mock_scan:
            parsed = parse_configuration(sample_config)
            self.assertEqual(
                mock_scan.call_count,
                1,
                f"Expected exactly 1 full-text scan, but _annotated_config_lines was called {mock_scan.call_count} times",
            )
            self.assertEqual(len(parsed["policies"]), 1)
            self.assertEqual(len(parsed["interfaces"]), 1)

    def test_structural_index_depth_tracking(self):
        """Verify depth tracking handles nested blocks without regex fragility."""
        config_text = """
        config system ha
            set ha-mgmt-status enable
            config ha-mgmt-interfaces
                edit 1
                    set interface "port1"
                next
            end
        end
        config vpn ssl settings
            set status enable
            config authentication-rule
                edit 1
                    set groups "Admins"
                    set portal "full-access"
                next
            end
        end
        """
        index = build_block_index(config_text)
        ha_sections = index.get(("config", "system", "ha"), [])
        self.assertEqual(len(ha_sections), 1)
        vdom, ha_lines = ha_sections[0]
        self.assertIsNone(vdom)
        # Verify ha-mgmt-interfaces block tokens are retained inside ha section
        has_sub = any(
            t == ["config", "ha-mgmt-interfaces"] for t in ha_lines
        )
        self.assertTrue(has_sub)

        ssl_sections = index.get(("config", "vpn", "ssl", "settings"), [])
        self.assertEqual(len(ssl_sections), 1)

    def test_vdom_isolation_in_block_index(self):
        """Sections in different VDOMs are tagged with their respective VDOM."""
        config_text = """
        config vdom
            edit "root"
                config firewall policy
                    edit 1
                        set name "root-p1"
                    next
                end
            next
            edit "tenant-a"
                config firewall policy
                    edit 2
                        set name "tenant-p2"
                    next
                end
            next
        end
        """
        ctx = ParserContext(config_text)
        policies = ctx.get_sections(("config", "firewall", "policy"))
        self.assertEqual(len(policies), 2)
        vdoms = [vdom for vdom, _ in policies]
        self.assertEqual(vdoms, ["root", "tenant-a"])

    def test_unknown_and_custom_sections_tolerated(self):
        """Unrecognized FortiOS sections are structurally indexed without crashing."""
        config_text = """
        config custom unknown-future-module
            edit "foo"
                set value 123
            next
        end
        """
        index = build_block_index(config_text)
        self.assertIn(("config", "custom", "unknown-future-module"), index)
        # parse_configuration should succeed without error
        parsed = parse_configuration(config_text)
        self.assertIn("input_assessment", parsed)

    def test_malformed_and_truncated_tolerance(self):
        """Malformed lines and unclosed blocks do not raise uncaught exceptions."""
        malformed_config = """
        config firewall policy
            edit 1
                set name "unclosed quote string
                set action accept
            # no next or end
        """
        parsed = parse_configuration(malformed_config)
        self.assertIsInstance(parsed, dict)
        self.assertTrue(
            any(
                "Truncated or unclosed" in w
                for w in parsed["input_assessment"]["structural_warnings"]
            )
        )

    def test_secret_suppression_strictly_preserved(self):
        """Passwords, PSKs, private keys are not exposed in parsed configuration."""
        config_with_secrets = """
        config user local
            edit "admin_user"
                set type password
                set passwd ENC secretpass123
                set status enable
            next
        end
        config vpn ipsec phase1-interface
            edit "to_branch"
                set interface "wan1"
                set psksecret ENC secretkeyxyz
            next
        end
        """
        parsed = parse_configuration(config_with_secrets)
        user = parsed["user_locals"][0]
        self.assertNotIn("passwd", user)
        self.assertNotIn("password", user)
        self.assertEqual(user["name"], "admin_user")

        phase1 = parsed["ipsec_phase1"][0]
        self.assertNotIn("psksecret", phase1)
        self.assertNotIn("secretkeyxyz", str(parsed))

    def test_standalone_parser_backwards_compatibility(self):
        """Standalone functions work with or without explicit context."""
        config_text = """
        config system interface
            edit "port1"
                set role lan
                set allowaccess ping https ssh
            next
        end
        """
        # Call without context
        intfs_no_ctx = parse_interfaces(config_text)
        # Call with context
        ctx = ParserContext(config_text)
        intfs_with_ctx = parse_interfaces(config_text, context=ctx)
        self.assertEqual(intfs_no_ctx, intfs_with_ctx)
        self.assertEqual(intfs_no_ctx[0]["name"], "port1")
        self.assertEqual(intfs_no_ctx[0]["allowaccess"], ["ping", "https", "ssh"])

    def test_deterministic_output(self):
        """Parsing identical configurations multiple times produces identical structures."""
        sample_config = """
        # config-version=FG60E-7.0.5-build1234
        config system interface
            edit "port1"
                set role lan
            next
        end
        config firewall policy
            edit 1
                set srcintf "port1"
                set dstintf "port2"
                set action accept
            next
        end
        """
        parsed1 = parse_configuration(sample_config)
        parsed2 = parse_configuration(sample_config)
        self.assertEqual(parsed1, parsed2)


if __name__ == "__main__":
    unittest.main()
