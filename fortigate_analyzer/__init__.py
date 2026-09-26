"""FortiGate Security Analyzer - Static Configuration & Health Analysis Package."""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_configuration
from .health_check import run_health_check
from .parser import parse_configuration
from .reporting import generate_static_report

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "run_static_analysis",
    "parse_configuration",
    "analyze_configuration",
    "run_health_check",
    "generate_static_report",
]


def run_static_analysis(
    config_text: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the complete FortiGate static analysis pipeline once.

    Orchestrates:
      1. parse_configuration(config_text)
      2. analyze_configuration(config)
      3. run_health_check(config, analysis_result=analysis)

    Returns:
      {
          "config": config,
          "analysis": analysis,
          "health": health,
          "metadata": metadata or {},
      }
    """
    metadata = dict(metadata or {})
    config = parse_configuration(config_text)
    analysis = analyze_configuration(config)
    health = run_health_check(config, analysis_result=analysis)

    return {
        "config": config,
        "analysis": analysis,
        "health": health,
        "metadata": metadata,
    }
