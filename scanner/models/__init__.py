"""
Bawbel Scanner — Data models.

Exports all public data models used across the scanner package.
Import from here, not from individual model files.

    from scanner.models import Finding, ScanResult, Severity, SEVERITY_SCORES
"""

from scanner.models.finding import Finding
from scanner.models.result import ScanResult
from scanner.models.severity import SEVERITY_SCORES, Severity

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "SEVERITY_SCORES",
]
