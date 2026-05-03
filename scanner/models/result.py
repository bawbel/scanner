"""
Bawbel Scanner — ScanResult model.

ScanResult is the complete output of a single file scan.
Returned by scanner.scan() — never instantiated directly by callers.
"""

from dataclasses import dataclass, field
from typing import Optional

from scanner.models.finding import Finding, Severity, SEVERITY_SCORES


@dataclass
class ScanResult:
    """
    Complete scan result for one file.

    All fields marked (stable) are public API — never rename or remove.
    New fields may be added (additive change) without version bump.
    """

    # ── Identity (stable) ────────────────────────────────────────────────────
    file_path: str  # (stable) resolved absolute path of scanned file
    component_type: str  # (stable) "skill"|"mcp"|"prompt"|"plugin"|"a2a"|"rag"|"model"|"unknown"

    # ── Results (stable) ─────────────────────────────────────────────────────
    findings: list[Finding] = field(default_factory=list)  # (stable) sorted by severity
    suppressed_findings: list[Finding] = field(default_factory=list)  # (stable)
    scan_time_ms: int = 0  # (stable) elapsed time

    # ── Toxic flows (stable) ──────────────────────────────────────────────────
    # Detected attack chains — computed from findings after deduplication.
    # Empty list if no toxic flows detected or if findings < 2.
    toxic_flows: list = field(
        default_factory=list
    )  # list[ToxicFlow] — typed loosely to avoid circular import

    # ── Error ─────────────────────────────────────────────────────────────────
    error: Optional[str] = None  # (stable) error code if scan failed, else None

    # ── Computed properties (stable) ─────────────────────────────────────────

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
        """
        Highest risk score across findings and toxic flows.
        Toxic flows elevate the risk score above individual findings.
        """
        scores = [f.cvss_ai for f in self.findings]
        scores += [tf.cvss_ai for tf in self.toxic_flows]
        return max(scores, default=0.0)

    @property
    def is_clean(self) -> bool:
        """True only if no findings, no toxic flows, and no error."""
        return len(self.findings) == 0 and len(self.toxic_flows) == 0 and self.error is None

    @property
    def has_error(self) -> bool:
        """True if scan failed with an error."""
        return self.error is not None
