"""
Bawbel Scanner — Data models.

Exports all public data models used across the scanner package.
Import from here, not from individual model files.

    from scanner.models import Finding, ScanResult, Severity, SEVERITY_SCORES
"""

from scanner.models.finding import Finding, Severity, SEVERITY_SCORES
from scanner.models.result import ScanResult

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "SEVERITY_SCORES",
]
