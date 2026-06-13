# Evidence Lifecycle

AIVSS answers: "How bad would this be?"
Confidence answers: "How certain are we?"
These are separate. Never collapse them into one score.

## Lifecycle states

| State | Meaning |
|---|---|
| raw_source | Unprocessed input |
| static_detection | Engine matched — not through FP pipeline yet |
| active_finding | Passed FP pipeline, above threshold |
| low_confidence_suppressed | Below threshold — in suppressed_findings[] |
| inline_suppressed | bawbel-ignore comment |
| block_suppressed | bawbel-ignore-start/end block |
| ignored_by_bawbelignore | .bawbelignore pattern |
| justified_false_positive | Human-confirmed FP, permanent |
| accepted_risk_active | Human-accepted risk, before expiry |
| accepted_risk_expired | Past expiry — resurfaces next scan |
| resurfaced_finding | Was suppressed, now active again |
| toxic_flow_participant | Finding contributed to a ToxicFlow |
| toxic_flow_derived | The ToxicFlow artifact itself |
| runtime_observed | (Phase 4) Runtime observation |
| runtime_drift_detected | (Phase 4) Differs from contract |
| runtime_blocked | (Phase 4) Blocked by bawbel-hook |
| reported | Included in final output |

## Invariants

1. suppressed ≠ deleted. Evidence persists in suppressed_findings[].
2. accepted_risk_expired resurfaces automatically on next scan.
3. ToxicFlow is always derived: true. Never active_finding.
4. ToxicFlow confidence ≤ min(constituent finding confidences).
5. aivss_score ≠ confidence. Separate fields, separate meaning.
6. runtime_observed is stronger evidence than static_detection.

## State transitions

raw_source → static_detection (engine fires)
static_detection → active_finding (confidence >= threshold)
static_detection → low_confidence_suppressed (confidence < threshold)
active_finding → accepted_risk_active (bawbel accept --type accepted-risk)
active_finding → justified_false_positive (bawbel accept --type false-positive)
active_finding → toxic_flow_participant (capability matches chain)
toxic_flow_participant → toxic_flow_derived (ToxicFlow created)
accepted_risk_active → accepted_risk_expired (expiry passes)
accepted_risk_expired → resurfaced_finding (next scan run)
resurfaced_finding → active_finding (re-enters pipeline)

## Expected JSON shape (after Issue #69)

Finding:
{
  "ave_id": "AVE-2026-00001",
  "severity": "HIGH",
  "aivss_score": 8.0,
  "confidence": 0.92,
  "confidence_band": "high",
  "evidence_stage": "active_finding",
  "evidence_kind": "tool_description_pattern",
  "evidence_basis": ["pattern", "semgrep"],
  "confidence_reason": "two engines agreed, file profile was skill",
  "derived": false
}

ToxicFlow:
{
  "flow_id": "credential-exfiltration",
  "severity": "CRITICAL",
  "aivss_score": 9.8,
  "confidence": 0.78,
  "confidence_band": "medium",
  "derived": true,
  "chain_confidence_reason": "one leg is statically inferred",
  "derived_from_findings": [
    {"ave_id": "AVE-2026-00003", "confidence": 0.91, "engine": "pattern"},
    {"ave_id": "AVE-2026-00026", "confidence": 0.65, "engine": "semgrep"}
  ]
}
