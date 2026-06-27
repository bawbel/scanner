"""
Bawbel Scanner - Finding model.

A Finding represents a single detected vulnerability in an agentic component.
Immutable after creation. All fields are sanitised by _make_finding() in scanner.py.
"""

from dataclasses import dataclass, field
from typing import Optional

from scanner.models.severity import DEFAULT_AARF, Severity


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

    # -- Evidence (new in v1.3.0) --------------------------------------------
    # confidence starts at ave.confidence_baseline, adjusted by the FP pipeline.
    confidence: float = 0.0
    evidence_kind: Optional[str] = (
        None  # "multi_engine"|"behavioral_pattern"|"semantic_inference"|...
    )
    detection_stage: Optional[str] = None  # "static_detection"|"runtime_observed"
    detection_layer: Optional[str] = None  # "content"|"server_card"|"runtime"|"registry_metadata"

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
