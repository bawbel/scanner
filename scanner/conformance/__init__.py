"""
Bawbel Scanner — MCP spec conformance scoring.

Public API:
    from scanner.conformance import score_conformance
    report = score_conformance(manifest_dict)

    report.score        # 0.0–100.0
    report.grade        # A+/A/B/C/D/F
    report.is_conformant # True if all REQUIRED checks pass
    report.results      # list[CheckResult], FAIL first

Adding a new check:
    1. Add a ConformanceCheck to scanner/conformance/checks.py
    2. Add a check function to scorer.py
    3. Add to _RUN_MAP in scorer.py
    That's it — score_conformance() picks it up automatically.
"""

from scanner.conformance.scorer import score_conformance
from scanner.conformance.checks import (
    ConformanceCheck,
    CheckCategory,
    CheckStatus,
    CONFORMANCE_CHECKS,
)
from scanner.conformance.scorer import ConformanceReport, CheckResult

__all__ = [
    "score_conformance",
    "ConformanceReport",
    "CheckResult",
    "ConformanceCheck",
    "CheckCategory",
    "CheckStatus",
    "CONFORMANCE_CHECKS",
]
