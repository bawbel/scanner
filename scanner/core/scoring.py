"""
Bawbel Scanner - AIVSS scoring (OWASP AIVSS v0.8).

Public interface for AIVSS calculation. Functions live in scanner.models.severity
and are re-exported here as the canonical scanner.core location per the layer model.
"""

from scanner.models.severity import calc_aivss, severity_from_aivss

__all__ = ["calc_aivss", "severity_from_aivss"]
