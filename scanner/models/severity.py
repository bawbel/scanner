"""
Bawbel Scanner — Severity model.

Severity enum, AIVSS scoring formula, and AARF defaults.
These are pure data and pure math — no I/O.
"""

from enum import Enum


class Severity(str, Enum):
    """
    AVE severity levels - maps to AIVSS score ranges (OWASP AIVSS v0.8).

    Do not change enum values - they are stable public API.
    External tools (CI/CD, SIEM) depend on these string values.
    """

    CRITICAL = "CRITICAL"  # 9.0-10.0
    HIGH = "HIGH"  # 7.0-8.9
    MEDIUM = "MEDIUM"  # 4.0-6.9
    LOW = "LOW"  # 0.1-3.9
    INFO = "INFO"  # 0.0


def severity_from_aivss(score: float) -> "Severity":
    """Derive Severity from an AIVSS score (OWASP AIVSS v0.8 bands)."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def calc_aivss(
    cvss_base: float,
    aarf: dict[str, float],
    thm: float = 0.75,
    mitigation_factor: float = 1.0,
) -> float:
    """
    Compute AIVSS score per OWASP AIVSS v0.8 formula.

    Formula: AIVSS = ((CVSS_Base + AARS) / 2) * ThM * Mitigation_Factor

    Args:
        cvss_base:          CVSSv4.0 base score (0.0-10.0)
        aarf:               Dict of 10 AARF factors, each 0.0/0.5/1.0
        thm:                Threat multiplier: 1.0=active exploit,
                            0.9=PoC, 0.75=theoretical (default)
        mitigation_factor:  1.0=none, 0.83=partial, 0.67=strong

    Returns:
        AIVSS score clamped to 0.0-10.0, rounded to 1 decimal place.
    """
    aars = sum(aarf.values())
    score = ((cvss_base + aars) / 2.0) * thm * mitigation_factor
    return round(min(max(score, 0.0), 10.0), 1)


# Severity -> numeric score mapping for comparisons and sorting
SEVERITY_SCORES: dict[str, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Default AARF values for unknown component types
# All factors at 0.5 (partial) gives a conservative baseline
DEFAULT_AARF: dict[str, float] = {
    "autonomy": 0.5,
    "tool_use": 0.5,
    "multi_agent": 0.0,
    "non_determinism": 0.5,
    "self_modification": 0.0,
    "dynamic_identity": 0.0,
    "persistent_memory": 0.0,
    "natural_language_input": 1.0,
    "data_access": 0.5,
    "external_dependencies": 0.0,
}

__all__ = [
    "Severity",
    "severity_from_aivss",
    "calc_aivss",
    "SEVERITY_SCORES",
    "DEFAULT_AARF",
]
