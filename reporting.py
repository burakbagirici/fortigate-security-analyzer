"""Backward-compatibility shim for reporting.

The canonical implementation now resides in `fortigate_analyzer.reporting`.
"""
from __future__ import annotations

import sys
import fortigate_analyzer.reporting as _canonical

globals().update({
    _k: _v for _k, _v in _canonical.__dict__.items()
    if not _k.startswith("__") or _k in ("__all__", "__doc__")
})
sys.modules[__name__] = _canonical
