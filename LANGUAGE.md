# LANGUAGE.md — Bawbel Domain Language

Every name in this codebase must come from this file.
No improvised terms. Add here first, then use.

Banned: `component`, `service`, `API`, `boundary`, `check`,
`violation`, `issue_item`, `validate`, `trust score`.

---

## Architecture terms (Matt Pocock / A Philosophy of Software Design)

**Module** — anything with interface + implementation
**Interface** — everything a caller must know: types, invariants, error modes
**Depth** — leverage: lot of behavior behind a small interface
**Seam** — where an interface lives; alterable without editing in place
**Adapter** — concrete implementation at a seam
**Deletion test** — would deleting this concentrate complexity, or just move it?

---

## Core domain

**Finding**
A single detected vulnerability instance produced by one or more engines.
Fields: `rule_id`, `ave_id`, `title`, `severity`, `aivss_score`, `line`,
`match`, `engine`, `owasp`, `owasp_mcp`, `piranha_url`, `confidence`,
`confidence_band`, `evidence_stage`, `evidence_kind`, `evidence_basis`,
`confidence_reason`, `derived`.
Immutable after creation. Suppression state set once.

**ScanResult**
Complete output of scanning one file.
Contains: `findings`, `suppressed_findings`, `accepted_findings`,
`toxic_flows`, `risk_score`, `max_severity`, `component_type`,
`scan_time_ms`, optionally `error`.

**ToxicFlow**
A derived artifact — NOT raw evidence.
Computed from two or more Findings whose capability tags match a known
chain definition.
Fields: `flow_id`, `title`, `severity`, `aivss_score`, `confidence`,
`confidence_band`, `derived: true`, `derived_from_findings[]`,
`chain_confidence_reason`.
A ToxicFlow is never created as raw evidence. It is always derived.

**AVERecord**
Vulnerability definition from the AVE standard.
`ave_id`, `title`, `severity`, `aivss_score`, `attack_class`,
`behavioral_fingerprint`, `owasp_mcp`, `remediation`.

**AcceptedFinding**
A Finding explicitly acknowledged by a human reviewer.
Has: `reason`, `reviewer`, `reviewed`, optional `expires`.
Lives in `ScanResult.accepted_findings`.
NOT the same as SuppressedFinding.

**SuppressedFinding**
A Finding filtered by the FP pipeline or inline directive.
Has `suppression_reason`. Lives in `ScanResult.suppressed_findings`.
Suppressed ≠ deleted. The evidence still exists.

---

## Evidence metadata (PFEM model — Issues #69-72)

AIVSS / severity answers: "How bad would this be?"
Confidence / evidence answers: "How certain are we, and what kind of evidence?"
These are SEPARATE. Never merge them.

**confidence** — float 0.0–1.0. Certainty that this finding is real.
**confidence_band** — "high" (>=0.80) | "medium" (>=0.55) | "low" (<0.55)
**evidence_stage** — current lifecycle state (see below)
**evidence_kind** — what type of evidence:
  "tool_description_pattern" | "config_schema" | "file_type_mismatch" |
  "behavioral_pattern" | "semantic_inference" | "multi_engine"
**evidence_basis** — list of engine names that produced this finding
**confidence_reason** — human-readable explanation of the confidence score
**derived** — bool. True for ToxicFlow. False for raw Finding.

---

## Evidence lifecycle vocabulary (Issue #71)

These are the states a finding can be in. Use these exact strings in code,
docs, and tests. Never invent new state names.

| State | Meaning |
|---|---|
| `raw_source` | Unprocessed input |
| `static_detection` | Engine matched — not yet through FP pipeline |
| `active_finding` | Passed FP pipeline, above confidence threshold |
| `low_confidence_suppressed` | Below threshold — in suppressed_findings[] |
| `inline_suppressed` | Suppressed by bawbel-ignore comment |
| `block_suppressed` | Suppressed by bawbel-ignore-start/end |
| `ignored_by_bawbelignore` | Matched .bawbelignore pattern |
| `justified_false_positive` | Human-confirmed FP, permanent |
| `accepted_risk_active` | Human-accepted risk, before expiry |
| `accepted_risk_expired` | Past expiry — resurfaces automatically |
| `resurfaced_finding` | Was suppressed/accepted, now active again |
| `toxic_flow_participant` | Finding contributed to a ToxicFlow |
| `toxic_flow_derived` | The ToxicFlow artifact itself |
| `runtime_observed` | (Phase 4) Observed at runtime |
| `runtime_drift_detected` | (Phase 4) Runtime differs from contract |
| `runtime_blocked` | (Phase 4) Blocked by bawbel-hook |
| `reported` | In final output |

**Key invariants:**
- `suppressed` ≠ deleted. Evidence persists.
- `accepted_risk_expired` → `resurfaced_finding` automatically.
- `ToxicFlow` is always `toxic_flow_derived`. Never `active_finding`.
- `runtime_observed` is stronger evidence than `static_detection`.

---

## Registry/ecosystem trust (Issue #72 — Phase 4+)

Evidence objects: `registry_entry`, `server_card`, `package_version`,
`source_repository`, `publisher_identity`, `install_event`, `local_pin`,
`scan_result`, `conformance_report`, `accepted_exception`,
`runtime_observation`, `runtime_drift_event`, `vulnerability_database_record`

Trust transitions: `discovered_in_registry`, `scanned_at_version`,
`pinned_locally`, `approved_in_git_review`, `updated_in_registry`,
`local_pin_outdated`, `schema_drift_detected`, `runtime_behavior_mismatch`,
`new_vulnerability_record_applies`, `exception_accepted`, `exception_expired`,
`server_delisted_or_deprecated`

---

## Scoring

**AIVSS** — AI Vulnerability Severity Score. OWASP standard v0.8.
NOT confidence. NOT certainty. Severity/impact only.
Formula: `((cvss_base + aars) / 2) * thm * mitigation_factor`

**AARS** — Agentic Attack Risk Score. Sum of 10 amplification factors.

**RiskScore** — max AIVSS across all active Findings AND ToxicFlows.

**Confidence** — float 0.0–1.0. Certainty of the finding. NOT severity.

---

## FP pipeline layers

**FP-1** Code fence stripping — scanner/core/preprocessor.py
**FP-2** Negation context — scanner/core/fp_pipeline.py
**FP-3** Confidence scoring — scanner/core/fp_pipeline.py
**FP-4** LLM meta-analyzer — scanner/engines/meta_analyzer.py
**FP-5** File-type scan profiles — scanner/core/fp_pipeline.py
**FP-6** Justified suppression — scanner/suppression/justified.py

---

## Detection engines

**PatternEngine** — regex, 40 rules, always active
**YARAEngine** — binary/behavioral, 39 rules
**SemgrepEngine** — structural, 41 rules
**LLMEngine** — semantic, optional
**SandboxEngine** — Docker behavioral, optional
**MagikaEngine** — ML file-type, optional
**MetaAnalyzer** — FP-4 LLM filter, NOT a detection engine

---

## Suppression mechanisms

**InlineSuppression** — `<!-- bawbel-ignore -->`
**BlockSuppression** — `<!-- bawbel-ignore-start/end -->`
**BawbelIgnore** — `.bawbelignore` glob patterns
**JustifiedSuppression** — `bawbel-accept` with metadata
**NoIgnore** — `--no-ignore` audit mode, bypasses ALL suppression

---

## Infrastructure

**PiranhaDB** — threat intel API at `api.piranha.bawbel.io`
**ServerCard** — `.well-known/mcp.json` published by MCP server
**Pin** — SHA-256 hash in `.bawbel-pins.json` for rug-pull detection
**Contract** *(Phase 4)* — signed scan artifact for runtime enforcement

---

## Banned terms

| Banned | Use instead |
|---|---|
| component | module |
| service | module |
| boundary | seam |
| check | finding |
| violation | finding |
| validate | score_confidence / classify_file |
| process | scan / detect / suppress |
| trust score | confidence + aivss_score (separate fields) |
