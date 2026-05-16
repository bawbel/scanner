"""
Bawbel Scanner - Finding model.

A Finding represents a single detected vulnerability in an agentic component.
Immutable after creation. All fields are sanitised by _make_finding() in scanner.py.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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


@dataclass(frozen=False)
class Finding:
    """
    Single vulnerability detection result.

    Created only by _make_finding() in scanner.py - never instantiate directly.
    This ensures all fields are properly sanitised (truncated, validated, typed).

    Fields marked with (stable) must not be renamed - they are public API.
    """

    # -- Identity (stable) ---------------------------------------------------
    rule_id: str  # (stable) kebab-case unique identifier
    ave_id: Optional[str]  # (stable) AVE-2026-NNNNN or None

    # -- Description (stable) ------------------------------------------------
    title: str  # (stable) max 80 chars, human-readable
    description: str  # (stable) full description for reports

    # -- Scoring (stable) ----------------------------------------------------
    severity: Severity  # (stable) Severity enum value
    aivss_score: float  # (stable) 0.0-10.0 OWASP AIVSS v0.8 score

    # -- AIVSS detail (new in v1.2.0) ----------------------------------------
    cvss_base: float = 0.0  # CVSSv4.0 base score
    aarf: dict = field(default_factory=lambda: dict(DEFAULT_AARF))
    aars: float = 0.0  # sum of aarf values
    thm: float = 0.75  # threat multiplier
    mitigation_factor: float = 1.0  # mitigation factor
    aivss_spec_version: str = "0.8"  # OWASP AIVSS spec version

    # -- Location ------------------------------------------------------------
    line: Optional[int] = None  # source line number (1-indexed)
    match: Optional[str] = None  # matched text, truncated to MAX_MATCH_LENGTH

    # -- Classification ------------------------------------------------------
    engine: str = "pattern"
    owasp: list[str] = field(default_factory=list)  # ["ASI01", "ASI08"]
    owasp_mcp: list[str] = field(default_factory=list)  # ["MCP01", "MCP05"]

    # -- Threat intelligence -------------------------------------------------
    piranha_url: Optional[str] = None  # https://api.piranha.bawbel.io/records/{ave_id}

    # -- Suppression ---------------------------------------------------------
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    def to_aivss_dict(self) -> dict:
        """Return a dict matching the OWASP AIVSS v0.8 JSON schema."""
        return {
            "cvss_base": self.cvss_base,
            "aarf": self.aarf,
            "aars": round(self.aars, 1),
            "thm": self.thm,
            "mitigation_factor": self.mitigation_factor,
            "aivss_score": self.aivss_score,
            "aivss_severity": self.severity.value,
            "spec_version": self.aivss_spec_version,
        }
