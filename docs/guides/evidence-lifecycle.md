# Evidence Lifecycle

AIVSS answers: "How bad would this be if exploited?"
Confidence answers: "How certain are we that this is real?"
These are separate scores. Never collapse them into one field.

## The confidence chain

```
AVE_META[ave_id].confidence_baseline
        │
        ▼  set by engine at detection time (Finding.confidence)
FP-2: has_negation_context()
        │  suppresses immediately if preceding line is a documentation signal
        ▼  (negation suppression skips all subsequent stages)
FP-3: score_confidence()
        │  adjusts confidence ± based on file context:
        │    -0.40  negation context in same line check
        │    -0.45  match is inside a markdown table row
        │    -0.55  match is inside a markdown heading
        │    -0.35  file path contains docs/, guides/, examples/, …
        │    -0.20  match string is < 6 characters
        │    +0.15  match is on line ≤ 30 (not in docs path)
        │    +0.25  same AVE ID detected by a second engine
        │    +0.15  filename is a known skill name (skill.md, system_prompt.*)
        │    +0.05  aivss_score ≥ 9.0
        │  result is clamped to [0.0, 1.0]
        ▼
Threshold check (profile-specific)
        │    skill           threshold 0.60
        │    mcp_manifest    threshold 0.55
        │    documentation   threshold 0.85
        │    unknown         threshold 0.60
        │  below threshold → low_confidence_suppressed
        ▼  (above threshold → active finding)
FP-4: meta-analyzer (medium-confidence window: 0.35–0.80)
        │  LLM reviews context around the match
        │    "real"          → confidence += 0.15  (capped at 1.0)
        │    "needs_review"  → confidence -= 0.05  (floored at 0.0)
        │    "false_positive"→ suppressed = True
        │  Skipped when: no LLM provider, disabled, or no medium findings
        ▼
Finding.confidence  (final value in ScanResult output)
        │
        ▼  detect_toxic_flows() runs BEFORE FP pipeline (pre-adjustment baselines)
ToxicFlow.confidence = min(baseline confidence across contributing findings)
```

## confidence_band()

The `confidence_band()` function in `scanner.core.fp_pipeline` maps a score to a
human-readable tier:

| Score range | Band | Meaning |
|---|---|---|
| 0.80 – 1.00 | `high` | Meta-analyzer skips; trusted as-is |
| 0.55 – 0.79 | `medium` | Within LLM review window; worth inspecting |
| 0.00 – 0.54 | `low` | Below most profile thresholds; typically suppressed |

## Pipeline ordering note

`detect_toxic_flows()` is called **before** the FP pipeline runs, so
`ToxicFlow.confidence` reflects the raw AVE baselines, not the post-FP-adjusted
values. This is intentional: toxic flows are detected from all findings (including
those that the FP pipeline will later suppress), preserving attack chain visibility
even for borderline findings.

## Invariants

1. `suppressed ≠ deleted`. Suppressed findings appear in `suppressed_findings[]`.
2. `accepted_risk_expired` resurfaces automatically on next scan.
3. `ToxicFlow` is always derived from existing findings, never created by an engine.
4. `ToxicFlow.confidence ≤ min(constituent finding baselines)`.
5. `aivss_score ≠ confidence`. Separate fields, separate meaning.
6. `detection_stage = "runtime_observed"` carries higher confidence than `"static_detection"`.

## Lifecycle states (conceptual)

| State | When |
|---|---|
| raw detection | Engine matched — Finding created with AVE baseline |
| active_finding | Passed FP pipeline, confidence ≥ threshold |
| low_confidence_suppressed | Confidence < profile threshold |
| negation_suppressed | Preceding line was a documentation signal |
| meta_analyzer_fp | LLM classified as false positive |
| inline_suppressed | `bawbel-ignore` comment on matched line |
| block_suppressed | Inside `bawbel-ignore-start` / `bawbel-ignore-end` |
| ignored_by_bawbelignore | Matched a `.bawbelignore` pattern |
| justified_false_positive | Human-confirmed FP via `bawbel accept` |
| accepted_risk | Human-accepted risk, before expiry |
| accepted_risk_expired | Past expiry — resurfaces next scan |
| toxic_flow_participant | Finding contributed to a ToxicFlow |

## Finding fields (implemented in v1.3.0)

```json
{
  "rule_id": "bawbel-external-fetch",
  "ave_id": "AVE-2026-00001",
  "severity": "CRITICAL",
  "aivss_score": 8.0,
  "confidence": 0.98,
  "evidence_kind": "multi_engine",
  "detection_stage": "static_detection",
  "detection_layer": "content",
  "engine": "pattern",
  "suppressed": false
}
```

## ToxicFlow fields (implemented in v1.3.0)

```json
{
  "flow_id": "credential-exfiltration",
  "severity": "CRITICAL",
  "aivss_score": 9.8,
  "confidence": 0.83,
  "ave_ids": ["AVE-2026-00003", "AVE-2026-00026"],
  "capabilities": ["credential-read", "data-exfil"]
}
```