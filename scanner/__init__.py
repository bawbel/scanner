"""
Bawbel Scanner — Agentic AI component security scanner.

Public API (stable — import from here, not from sub-modules):

    from scanner import scan, ScanResult, Finding, Severity

    result = scan("/path/to/skill.md")
    if not result.is_clean:
        for finding in result.findings:
            print(f"[{finding.severity.value}] {finding.title}")

Version follows semantic versioning (semver).
Breaking changes (removing/renaming public API) require a major version bump.
"""

__version__ = "0.3.0"
__author__ = "Bawbel <bawbel.io@gmail.com>"
__license__ = "Apache-2.0"

# ── Public API ────────────────────────────────────────────────────────────────
# All public symbols are imported here.
# Callers should ALWAYS import from `scanner`, not from sub-modules.
# Sub-module paths (scanner.scanner, scanner.models.finding) are internal
# and may change without notice.

from scanner.scanner import scan  # main entry point
from scanner.models import Finding, ScanResult, Severity, SEVERITY_SCORES

__all__ = [
    # Core function
    "scan",
    # Data models
    "Finding",
    "ScanResult",
    "Severity",
    "SEVERITY_SCORES",
    # Package metadata
    "__version__",
    "__author__",
    "__license__",
]
