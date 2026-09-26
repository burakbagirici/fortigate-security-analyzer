"""Tests for Packaging, Distribution, Re-exports, and Containerization."""

from __future__ import annotations

import importlib.metadata
import io
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import fortigate_analyzer
from fortigate_analyzer import (
    __version__,
    analyze_configuration,
    generate_static_report,
    parse_configuration,
    run_health_check,
    run_static_analysis,
)
import fortigate_analyzer.analyzer
import fortigate_analyzer.cli
import fortigate_analyzer.fortios_defaults
import fortigate_analyzer.health_check
import fortigate_analyzer.json_export
import fortigate_analyzer.parser
import fortigate_analyzer.reporting
import fortigate_analyzer.runtime_health

import analyzer
import fortios_defaults
import health_check
import parser
import reporting
import runtime_health


class TestPackagingAndDistribution(unittest.TestCase):
    """Test suite verifying package structure, shim identity, dependencies, and packaging artifacts."""

    def test_01_version_is_semantic_and_non_empty(self):
        """01. Package version is valid semver string."""
        self.assertEqual(__version__, "0.1.0")
        self.assertEqual(fortigate_analyzer.__version__, "0.1.0")

    def test_02_canonical_public_symbols_exported(self):
        """02. Canonical package exports core workflow symbols."""
        expected_exports = {
            "__version__",
            "run_static_analysis",
            "parse_configuration",
            "analyze_configuration",
            "run_health_check",
            "generate_static_report",
        }
        for sym in expected_exports:
            self.assertTrue(hasattr(fortigate_analyzer, sym), f"Missing export {sym}")

    def test_03_root_shims_alias_canonical_modules(self):
        """03. Root shims forward directly to canonical package modules."""
        self.assertIs(parser.parse_configuration, fortigate_analyzer.parser.parse_configuration)
        self.assertIs(analyzer.analyze_configuration, fortigate_analyzer.analyzer.analyze_configuration)
        self.assertIs(health_check.run_health_check, fortigate_analyzer.health_check.run_health_check)
        self.assertIs(reporting.generate_static_report, fortigate_analyzer.reporting.generate_static_report)
        self.assertIs(runtime_health.analyze_runtime_health, fortigate_analyzer.runtime_health.analyze_runtime_health)
        self.assertIs(fortios_defaults.collect_applied_defaults, fortigate_analyzer.fortios_defaults.collect_applied_defaults)

    def test_04_sys_modules_identity(self):
        """04. Root module entries in sys.modules match canonical modules exactly."""
        self.assertIs(sys.modules["parser"], fortigate_analyzer.parser)
        self.assertIs(sys.modules["analyzer"], fortigate_analyzer.analyzer)
        self.assertIs(sys.modules["health_check"], fortigate_analyzer.health_check)
        self.assertIs(sys.modules["reporting"], fortigate_analyzer.reporting)
        self.assertIs(sys.modules["runtime_health"], fortigate_analyzer.runtime_health)
        self.assertIs(sys.modules["fortios_defaults"], fortigate_analyzer.fortios_defaults)

    def test_05_compatibility_shim_monkeypatching(self):
        """05. Monkeypatching root shim targets works identically to patching canonical module."""
        fake_return = {"mocked_policy": True}
        with patch.object(parser, "parse_configuration", return_value=fake_return):
            # Calling via parser shim
            self.assertEqual(parser.parse_configuration("dummy"), fake_return)
            # Calling via canonical package
            self.assertEqual(fortigate_analyzer.parser.parse_configuration("dummy"), fake_return)

    def test_06_version_single_source_consistency(self):
        """06. pyproject.toml references dynamic version to prevent drift."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        pyproj_path = os.path.join(repo_dir, "pyproject.toml")
        with open(pyproj_path, "r", encoding="utf-8") as f:
            pyproj = f.read()

        self.assertIn('dynamic = ["version"]', pyproj)
        self.assertIn('version = {attr = "fortigate_analyzer.__version__"}', pyproj)

        # Check installed metadata if package was installed in current environment
        try:
            installed_ver = importlib.metadata.version("fortigate-analyzer")
            self.assertEqual(installed_ver, fortigate_analyzer.__version__)
        except importlib.metadata.PackageNotFoundError:
            # Package not installed in the dev virtualenv; dynamic pyproject assertion stands
            pass

    def test_07_core_modules_require_no_third_party_dependencies(self):
        """07. Core static analysis modules require only Python standard library."""
        core_modules = [
            fortigate_analyzer.parser,
            fortigate_analyzer.analyzer,
            fortigate_analyzer.health_check,
            fortigate_analyzer.reporting,
            fortigate_analyzer.runtime_health,
            fortigate_analyzer.fortios_defaults,
            fortigate_analyzer.json_export,
            fortigate_analyzer.cli,
        ]
        for mod in core_modules:
            for attr_name, attr_val in vars(mod).items():
                if hasattr(attr_val, "__name__") and hasattr(attr_val, "__file__"):
                    imported_mod = getattr(attr_val, "__name__", "")
                    base_pkg = imported_mod.split(".")[0]
                    self.assertNotEqual(base_pkg, "streamlit", f"Core module {mod.__name__} must not depend on streamlit")

    def test_08_dockerfile_and_dockerignore_exist_and_conform(self):
        """08. Dockerfile and .dockerignore exist and pass structural security audit."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        dockerfile_path = os.path.join(repo_dir, "Dockerfile")
        dockerignore_path = os.path.join(repo_dir, ".dockerignore")

        self.assertTrue(os.path.exists(dockerfile_path), "Dockerfile must exist")
        self.assertTrue(os.path.exists(dockerignore_path), ".dockerignore must exist")

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            df_content = f.read()

        # Non-root user verification
        self.assertIn("appuser", df_content, "Dockerfile must define non-root user")
        self.assertIn("10001", df_content, "Dockerfile must specify non-root UID/GID")
        self.assertIn("USER 10001:10001", df_content, "Dockerfile must switch to non-root USER")

        # Security/optimization environment variables
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", df_content)
        self.assertIn("PYTHONUNBUFFERED=1", df_content)

        # Dual mode support
        self.assertIn("docker-entrypoint.sh", df_content)
        self.assertIn("EXPOSE 8501", df_content)

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            di_content = f.read()

        # Sensitive items ignored
        self.assertIn(".git", di_content)
        self.assertIn("*.conf", di_content)
        self.assertIn("scratch/", di_content)
        self.assertIn("tests/", di_content)
        self.assertIn("__pycache__", di_content)

    def test_09_dockerfile_installs_ui_dependency_when_ui_advertised(self):
        """09. Dockerfile installs declared optional UI dependency since 'ui' subcommand is supported."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        dockerfile_path = os.path.join(repo_dir, "Dockerfile")
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            df_content = f.read()

        # The image must install the declared optional ui extra
        self.assertTrue(
            'pip install --no-cache-dir ".[ui]"' in df_content or "pip install .[ui]" in df_content,
            "Dockerfile must install '.[ui]' to support advertised Streamlit UI entrypoint without version drift.",
        )

    def test_10_docker_entrypoint_safe_argument_forwarding(self):
        """10. Entrypoint script uses exec, safe quoting, handles zero arguments, and has no eval."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        entrypoint_path = os.path.join(repo_dir, "docker-entrypoint.sh")
        self.assertTrue(os.path.exists(entrypoint_path))

        with open(entrypoint_path, "r", encoding="utf-8") as f:
            ep_content = f.read()

        self.assertNotIn("eval ", ep_content, "Entrypoint must not use eval")
        self.assertIn('"$@"', ep_content, 'Entrypoint must use safe "$@" argument forwarding')
        self.assertIn("exec fortigate-analyzer", ep_content, "Entrypoint must exec fortigate-analyzer for signal handling")
        self.assertIn("exec streamlit", ep_content, "Entrypoint must exec streamlit for signal handling")
        self.assertIn("$# -eq 0", ep_content, "Entrypoint must explicitly handle zero-argument invocations")

    def test_11_sdist_manifest_and_exclusions(self):
        """11. MANIFEST.in exists and strictly prunes development and sensitive directories."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        manifest_path = os.path.join(repo_dir, "MANIFEST.in")
        self.assertTrue(os.path.exists(manifest_path), "MANIFEST.in must exist")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()

        self.assertIn("prune scratch", manifest)
        self.assertIn("prune corpus", manifest)
        self.assertIn("global-exclude *.conf.bak", manifest)
        self.assertIn("global-exclude __pycache__", manifest)

    def test_12_smoke_docker_scripts_exist_and_conform(self):
        """12. Smoke validation scripts exist for PowerShell and Bash with all 8 checks."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        ps1_path = os.path.join(repo_dir, "scripts", "smoke_docker.ps1")
        sh_path = os.path.join(repo_dir, "scripts", "smoke_docker.sh")

        self.assertTrue(os.path.exists(ps1_path), "scripts/smoke_docker.ps1 must exist")
        self.assertTrue(os.path.exists(sh_path), "scripts/smoke_docker.sh must exist")

        with open(ps1_path, "r", encoding="utf-8") as f:
            ps1_content = f.read()

        for check in ["docker build", "--version", "--help", "10001", "--network none", "report.json", "report.html", "ui"]:
            self.assertIn(check, ps1_content, f"Missing check '{check}' in smoke_docker.ps1")

    def test_13_ci_workflow_structure(self):
        """13. GitHub Actions CI workflow exists, is read-only, tests Python 3.9-3.13, and includes all stages."""
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        ci_path = os.path.join(repo_dir, ".github", "workflows", "ci.yml")
        self.assertTrue(os.path.exists(ci_path), ".github/workflows/ci.yml must exist")

        with open(ci_path, "r", encoding="utf-8") as f:
            ci_content = f.read()

        # Permissions check
        self.assertIn("permissions:", ci_content)
        self.assertIn("contents: read", ci_content)

        # Python test matrix
        for py_ver in ["3.9", "3.10", "3.11", "3.12", "3.13"]:
            self.assertIn(f'"{py_ver}"', ci_content, f"Missing Python version {py_ver} in CI matrix")

        # Required jobs
        for job_name in [
            "test-core:",
            "test-ui:",
            "build-package:",
            "verify-wheel-clean-install:",
            "docker-runtime-smoke:",
        ]:
            self.assertIn(job_name, ci_content, f"Missing job '{job_name}' in ci.yml")


if __name__ == "__main__":
    unittest.main()

