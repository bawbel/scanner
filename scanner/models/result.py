"""
Bawbel Scanner - ScanResult model.

ScanResult is the complete output of a single file scan.
Returned by scanner.scan() - never instantiated directly by callers.
"""

from dataclasses import dataclass, field
from typing import Optional

from scanner.models.finding import Finding
from scanner.models.severity import SEVERITY_SCORES, Severity


@dataclass
class ScanResult:
    """
    Complete scan result for one file.

    All fields marked (stable) are public API - never rename or remove.
    New fields may be added (additive change) without version bump.
    """

    # -- Identity (stable) ---------------------------------------------------
    file_path: str  # (stable) resolved absolute path of scanned file
    component_type: str  # (stable) "skill"|"mcp"|"prompt"|"plugin"|"a2a"|"rag"|"model"|"unknown"

    # -- Results (stable) ----------------------------------------------------
    findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    scan_time_ms: int = 0

    # -- Toxic flows ---------------------------------------------------------
    toxic_flows: list = field(default_factory=list)  # ToxicFlow objects

    # -- Justified suppression (v1.2.0) --------------------------------------
    # AcceptedFinding objects - false positives and accepted risks
    # These are separate from suppressed_findings which are auto-suppressed by FP pipeline
    accepted_findings: list = field(default_factory=list)

    # -- Error ---------------------------------------------------------------
    error: Optional[str] = None  # (stable) error code if scan failed, else None

    # -- Computed properties (stable) ----------------------------------------

    @property
    def max_severity(self) -> Optional[Severity]:
        """Highest severity finding, or None if no findings."""
        if not self.findings:
            return None
        return max(
            self.findings,
            key=lambda f: SEVERITY_SCORES.get(f.severity.value, 0),
        ).severity

    @property
    def risk_score(self) -> float:
        """Highest AIVSS score across all active findings and toxic flows."""
        scores = [f.aivss_score for f in self.findings]
        scores += [tf.aivss_score for tf in self.toxic_flows]
        return max(scores) if scores else 0.0

    @property
    def is_clean(self) -> bool:
        """True only if no findings, no toxic flows, and no error."""
        return len(self.findings) == 0 and len(self.toxic_flows) == 0 and self.error is None

    @property
    def has_error(self) -> bool:
        """True if scan failed with an error."""
        return self.error is not None

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Findings grouped by severity level."""
        groups: dict[str, list[Finding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for f in self.findings:
            groups[f.severity.value].append(f)
        return groups

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict. Stable output format."""
        return {
            "file_path": self.file_path,
            "component_type": self.component_type,
            "scan_time_ms": self.scan_time_ms,
            "error": self.error,
            "risk_score": self.risk_score,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "ave_id": f.ave_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "aivss_score": f.aivss_score,
                    "aivss": f.to_aivss_dict(),
                    "engine": f.engine,
                    "line": f.line,
                    "match": f.match,
                    "owasp": f.owasp,
                    "owasp_mcp": f.owasp_mcp,
                    "piranha_url": f.piranha_url,
                    "suppressed": f.suppressed,
                }
                for f in self.findings
            ],
            "toxic_flows": [tf.to_dict() for tf in self.toxic_flows] if self.toxic_flows else [],
            # J4: accepted_findings in JSON output
            "accepted_findings": (
                [af.to_dict() for af in self.accepted_findings] if self.accepted_findings else []
            ),
        }
