"""
Bawbel Scanner — Finding model.

A Finding represents a single detected vulnerability in an agentic component.
Immutable after creation. All fields are sanitised by _make_finding() in scanner.py.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """
    AVE severity levels — maps to CVSS-AI score ranges.

    Do not change enum values — they are stable public API.
    External tools (CI/CD, SIEM) depend on these string values.
    """

    CRITICAL = "CRITICAL"  # 9.0–10.0
    HIGH = "HIGH"  # 7.0–8.9
    MEDIUM = "MEDIUM"  # 4.0–6.9
    LOW = "LOW"  # 0.1–3.9
    INFO = "INFO"  # 0.0


# Severity → numeric score mapping for comparisons and sorting
SEVERITY_SCORES: dict[str, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(frozen=False)
class Finding:
    """
    Single vulnerability detection result.

    Created only by _make_finding() in scanner.py — never instantiate directly.
    This ensures all fields are properly sanitised (truncated, validated, typed).

    Fields marked with (stable) must not be renamed — they are public API.
    """

    # ── Identity (stable) ────────────────────────────────────────────────────
    rule_id: str  # (stable) kebab-case unique identifier
    ave_id: Optional[str]  # (stable) AVE-2026-NNNNN or None

    # ── Description (stable) ─────────────────────────────────────────────────
    title: str  # (stable) max 80 chars, human-readable
    description: str  # (stable) full description for reports

    # ── Scoring (stable) ─────────────────────────────────────────────────────
    severity: Severity  # (stable) Severity enum value
    cvss_ai: float  # (stable) 0.0–10.0, validated by parse_cvss()

    # ── Location ─────────────────────────────────────────────────────────────
    line: Optional[int]  # source line number (1-indexed), or None
    match: Optional[str]  # matched text — always truncated to MAX_MATCH_LENGTH

    # ── Classification ───────────────────────────────────────────────────────
    engine: str  # "pattern" | "yara" | "semgrep" | "llm"
    owasp: list[str] = field(default_factory=list)  # ["ASI01", "ASI08"]
