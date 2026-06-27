"""
Bawbel Scanner - Toxic Flow models.

A ToxicFlow is a detected attack chain - two or more findings whose
capabilities combine to form a complete, exploitable attack path.

Example:
    Finding 1: AVE-2026-00003  credential-read  (reads .env / API keys)
    Finding 2: AVE-2026-00026  data-exfil       (encodes and transmits data)
    → ToxicFlow: credential-exfiltration  CRITICAL 9.8

ToxicFlow is intentionally separate from Finding - it is a derived
artifact, not a raw detection. It is always computed from two or more
existing findings, never created directly by an engine.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ToxicFlow:
    """
    A detected attack chain formed by two or more findings.

    Immutable - computed once after deduplication, never modified.

    Fields marked (stable) are public API - SARIF, JSON output,
    external tooling may depend on them.
    """

    # ── Identity (stable) ────────────────────────────────────────────────────
    flow_id: str  # (stable) kebab-case e.g. "credential-exfiltration"
    title: str  # (stable) human-readable e.g. "Credential Exfiltration Chain"

    # ── Chain (stable) ───────────────────────────────────────────────────────
    ave_ids: tuple[str, ...]  # (stable) ordered AVE IDs forming the chain
    capabilities: tuple[str, ...]  # (stable) capability tags e.g. ("credential-read", "data-exfil")

    # ── Scoring (stable) ─────────────────────────────────────────────────────
    severity: str  # (stable) "CRITICAL" | "HIGH" | "MEDIUM"
    aivss_score: float  # (stable) combined AIVSS v0.8 score - always >= max(individual scores)

    # ── Context ──────────────────────────────────────────────────────────────
    description: str  # what the combined attack achieves
    owasp_mcp: tuple[str, ...]  # OWASP MCP categories for the combined flow
    remediation: str  # how to break the chain
    confidence: float  # min confidence across contributing findings (new in v1.3.0)

    def to_dict(self) -> dict:
        """Serialise for JSON output."""
        return {
            "flow_id": self.flow_id,
            "title": self.title,
            "ave_ids": list(self.ave_ids),
            "capabilities": list(self.capabilities),
            "severity": self.severity,
            "aivss_score": self.aivss_score,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "owasp_mcp": list(self.owasp_mcp),
            "remediation": self.remediation,
        }
