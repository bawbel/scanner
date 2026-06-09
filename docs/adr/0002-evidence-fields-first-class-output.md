# ADR-0002: Evidence confidence fields are first-class in public JSON output

**Status:** Accepted
**Date:** 2026-06-05
**GitHub Issues:** #69, #70, #71
**Review:** lightrock (PFEM architectural review)

---

## Context

Bawbel Scanner computes a confidence score for each finding internally during
the FP pipeline (FP-3). This score influences whether a finding appears in
`findings[]` or `suppressed_findings[]`. However, `Finding.to_dict()` does not
serialize confidence as a stable first-class field in the JSON output.

External tools consuming Bawbel's JSON cannot distinguish between:
- A HIGH severity finding with 0.92 confidence (act immediately)
- A HIGH severity finding with 0.41 confidence (verify before acting)

This conflates two independent measurements: risk severity (AIVSS) and
evidence certainty (confidence). In production security tooling, these require
different responses.

## Decision

Severity (AIVSS) and confidence (evidence certainty) are SEPARATE first-class
fields in all public output. They are never merged into one score.

`Finding.to_dict()` must include: `confidence`, `confidence_band`,
`evidence_stage`, `evidence_kind`, `evidence_basis`, `confidence_reason`,
`derived`.

`ToxicFlow` must include: `confidence`, `confidence_band`, `derived: true`,
`derived_from_findings`, `chain_confidence_reason`.

The output contract is locked by golden JSON fixtures in `tests/fixtures/golden/`.
Any change to the JSON shape that breaks a golden fixture is a breaking change
and requires a semver major bump.

## Consequences

**Positive:**
- Downstream CI gates can filter on confidence independently of severity
- `bawbel-hook` (Phase 4) can make enforcement decisions using both signals
- `bawbel-trace` (Phase 5) can track evidence lineage through derived artifacts
- Human reviewers can triage by certainty before acting on severity
- Golden fixtures prevent silent contract breakage during engine refactors
- lightrock/PFEM's architectural concern is directly addressed

**Negative:**
- All JSON consumers must be updated to handle new fields (backward-compatible
  additions, so existing tools will not break)
- `Finding` dataclass gains 7 new optional fields with defaults
- Every engine must be updated to populate `evidence_kind` and `evidence_basis`

## Alternatives rejected

**Merge confidence into aivss_score:** Rejected. These are independent measurements.
AIVSS is defined by the OWASP standard and measures impact. Confidence measures
certainty. Merging them produces a score that answers neither question correctly.

**Expose confidence only in verbose/debug mode:** Rejected. Downstream automation
needs confidence in every output, not just debug mode. The field is first-class
or it is not useful.
