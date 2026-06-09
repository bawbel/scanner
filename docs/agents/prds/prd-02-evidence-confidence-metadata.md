# PRD-02: First-class evidence/confidence metadata and golden fixtures

**Status:** Ready
**GitHub Issues:** #69, #70, #71
**Created:** 2026-06-05
**Author:** chaksaray
**Reviewer:** lightrock (PFEM architectural review)

---

## Problem

Bawbel Scanner separates AIVSS severity scoring from FP-pipeline confidence
scoring internally, but the public JSON output collapses them.

`Finding.to_dict()` serializes `severity` and `aivss_score` as stable fields.
`confidence` is computed by the FP pipeline and stored as `f.confidence`
internally but is NOT serialized into the public JSON output.

`ToxicFlow` output has `severity` and `aivss_score` but no `confidence`,
no `chain_confidence_reason`, no `derived_from_findings` evidence links.

This means downstream CI systems, dashboards, SARIF consumers, and the
planned `bawbel-hook` runtime enforcer cannot distinguish:
- HIGH severity, HIGH confidence (urgent) from
- HIGH severity, LOW confidence (verify first)

It also means there is no stable output contract. A future engine refactor
could silently drop `aivss_score` or rename `suppression_reason` and no
test would catch it.

## Goal

1. Add `confidence`, `confidence_band`, `evidence_stage`, `evidence_kind`,
   `evidence_basis`, `confidence_reason`, `derived` as stable serialized
   fields on Finding and ToxicFlow JSON output.

2. Lock the output contract with golden JSON fixtures and pytest contract tests
   for every public output shape.

3. Document the evidence lifecycle state machine in `docs/guides/evidence-lifecycle.md`.

## Out of scope

- Changing AIVSS scoring logic
- Changing any detection engine behavior
- Adding new AVE records
- bawbel-hook runtime enforcement (Phase 4)

## Domain terms

From LANGUAGE.md:
`confidence`, `confidence_band`, `evidence_stage`, `evidence_kind`,
`evidence_basis`, `confidence_reason`, `derived`, `ToxicFlow`,
`AcceptedFinding`, `SuppressedFinding`, `active_finding`,
`accepted_risk_expired`, `resurfaced_finding`

## Interface contract

### Finding model additions

```python
# scanner/models/finding.py

@dataclass
class Finding:
    # ... existing fields unchanged ...

    # New evidence fields — all optional with defaults for backward compat
    confidence: float = 0.0
    confidence_band: str = "low"          # "high" | "medium" | "low"
    evidence_stage: str = "static_detection"  # see LANGUAGE.md lifecycle vocab
    evidence_kind: str = ""               # "tool_description_pattern" | etc
    evidence_basis: list[str] = field(default_factory=list)  # engine names
    confidence_reason: str = ""
    derived: bool = False

    def to_dict(self) -> dict:
        """
        Serialize to public JSON output.
        All evidence fields included.
        AIVSS and confidence are SEPARATE keys — never merge them.
        """
```

### ToxicFlow model additions

```python
# scanner/core/toxic_flows/models.py

@dataclass
class ToxicFlow:
    # ... existing fields unchanged ...

    # New evidence fields
    confidence: float = 0.0
    confidence_band: str = "low"
    derived: bool = True                  # ALWAYS True for ToxicFlow
    derived_from_findings: list[dict] = field(default_factory=list)
    chain_confidence_reason: str = ""
```

### Golden fixture contract test

```python
# tests/unit/test_output_contracts.py

def test_finding_json_has_required_evidence_fields(active_finding_result):
    d = active_finding_result.findings[0].to_dict()
    assert "confidence" in d
    assert "confidence_band" in d
    assert "evidence_stage" in d
    assert "evidence_kind" in d
    assert "evidence_basis" in d
    assert "derived" in d
    assert d["derived"] is False
    assert d["aivss_score"] != d["confidence"]  # they must never be equal by coincidence

def test_toxic_flow_json_is_derived(toxic_flow_result):
    flow = toxic_flow_result.toxic_flows[0]
    d = flow.to_dict()
    assert d["derived"] is True
    assert len(d["derived_from_findings"]) >= 2
    assert "chain_confidence_reason" in d
```

## Layer placement

| Code | File | Layer |
|---|---|---|
| Evidence field additions | `scanner/models/finding.py` | models (data) |
| Evidence field additions | `scanner/core/toxic_flows/models.py` | core (pure) |
| confidence_band calculation | `scanner/core/fp_pipeline.py` | core (pure) |
| evidence_stage assignment | `scanner/core/fp_pipeline.py` | core (pure) |
| evidence_kind assignment | `scanner/engines/*.py` | engines |
| evidence_basis population | `scanner/engines/*.py` | engines |
| Golden fixtures | `tests/fixtures/golden/` | tests |
| Contract tests | `tests/unit/test_output_contracts.py` | unit tests |

## Test plan

| Test | Behavior | Speed |
|---|---|---|
| `test_finding_has_confidence_field_in_dict_output` | confidence in to_dict() | unit |
| `test_finding_confidence_band_is_high_when_above_0_80` | 0.92 → "high" | unit |
| `test_finding_confidence_band_is_low_when_below_0_55` | 0.40 → "low" | unit |
| `test_finding_aivss_not_equal_confidence_are_separate_fields` | no collision | unit |
| `test_finding_derived_is_false_for_raw_finding` | derived: false | unit |
| `test_toxic_flow_derived_is_always_true` | derived: true | unit |
| `test_toxic_flow_has_derived_from_findings` | evidence links | unit |
| `test_toxic_flow_confidence_lte_min_constituent` | chain certainty | unit |
| `test_golden_clean_scan_matches_fixture` | output contract | unit |
| `test_golden_active_finding_matches_fixture` | output contract | unit |
| `test_golden_accepted_risk_expired_resurfaces` | lifecycle | unit |
| `test_golden_toxic_flow_has_evidence_fields` | output contract | unit |

## Acceptance criteria

- [ ] `pytest tests/unit/test_output_contracts.py` passes
- [ ] `pytest tests/unit/test_finding_evidence_metadata.py` passes
- [ ] `pytest tests/` passes (no regressions)
- [ ] `mypy scanner/models/finding.py scanner/core/` clean
- [ ] All 11 golden fixtures exist in `tests/fixtures/golden/`
- [ ] ARCHITECTURE.md evidence fields table updated to "Serialized"
- [ ] `docs/guides/evidence-lifecycle.md` exists and reviewed
- [ ] GitHub Issue #69 closed
- [ ] GitHub Issue #70 closed
- [ ] GitHub Issue #71 closed

## Implementation order

Do NOT do all tasks in one session. One per session.

1. Add evidence fields to `Finding` dataclass (models layer) — no behavior change
2. Include evidence fields in `Finding.to_dict()` — no behavior change
3. Add `confidence_band` calculation to `fp_pipeline.py`
4. Add `evidence_stage` assignment in `fp_pipeline.py`
5. Add `evidence_kind` and `evidence_basis` population in each engine
6. Add evidence fields to `ToxicFlow` — model first, then serialization
7. Add `chain_confidence_reason` to ToxicFlow chain detection
8. Write golden fixture JSON for clean scan
9. Write golden fixture JSON for active finding (with evidence fields)
10. Write remaining golden fixtures
11. Write contract tests that load and compare golden fixtures
