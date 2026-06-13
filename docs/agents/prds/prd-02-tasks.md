# Tasks: PRD-02 — Evidence/confidence metadata and golden fixtures

Pick exactly ONE task. Complete its full TDD cycle before starting another.
Do not implement multiple tasks in one session.

GitHub Issues: #69, #70, #71

---

## Backlog

### TASK-01: Add evidence fields to Finding dataclass

**File:** `tests/unit/test_finding_evidence_metadata.py`

**Test to write:**
```python
from scanner.models.finding import Finding
from scanner.models.severity import Severity

def test_finding_has_confidence_field():
    f = Finding(
        rule_id="test", ave_id="AVE-2026-00001", title="test",
        description="test", severity=Severity.HIGH, aivss_score=8.0,
        line=1, match="test", engine="pattern",
    )
    # confidence is a first-class field with default
    assert hasattr(f, "confidence")
    assert f.confidence == 0.0

def test_finding_has_evidence_stage_field():
    f = Finding(rule_id="test", ave_id="AVE-2026-00001", title="test",
        description="test", severity=Severity.HIGH, aivss_score=8.0,
        line=1, match="test", engine="pattern")
    assert hasattr(f, "evidence_stage")
    assert f.evidence_stage == "static_detection"

def test_finding_derived_is_false_by_default():
    f = Finding(rule_id="test", ave_id="AVE-2026-00001", title="test",
        description="test", severity=Severity.HIGH, aivss_score=8.0,
        line=1, match="test", engine="pattern")
    assert f.derived is False
```

**Implementation file:** `scanner/models/finding.py`
**Layer:** models (data only — no logic)
**Acceptance:** pytest tests/unit/test_finding_evidence_metadata.py passes

---

### TASK-02: Include evidence fields in Finding.to_dict()

**Depends on:** TASK-01 complete

**Test to write:**
```python
def test_finding_to_dict_includes_confidence():
    f = Finding(rule_id="test", ave_id="AVE-2026-00001", title="test",
        description="test", severity=Severity.HIGH, aivss_score=8.0,
        line=1, match="test", engine="pattern", confidence=0.85)
    d = f.to_dict()
    assert "confidence" in d
    assert d["confidence"] == 0.85
    assert "evidence_stage" in d
    assert "evidence_kind" in d
    assert "evidence_basis" in d
    assert "confidence_reason" in d
    assert "derived" in d

def test_finding_aivss_and_confidence_are_separate_keys():
    f = Finding(rule_id="test", ave_id="AVE-2026-00001", title="test",
        description="test", severity=Severity.HIGH, aivss_score=8.0,
        line=1, match="test", engine="pattern", confidence=0.92)
    d = f.to_dict()
    # They must never be the same key or value substituted
    assert "aivss_score" in d
    assert "confidence" in d
    assert d["aivss_score"] != d["confidence"]  # 8.0 != 0.92
```

**Implementation file:** `scanner/models/finding.py` — update `to_dict()`
**Layer:** models
**Acceptance:** pytest tests/unit/test_finding_evidence_metadata.py passes

---

### TASK-03: Add confidence_band calculation to fp_pipeline

**Depends on:** TASK-02 complete

**Test to write:**
```python
from scanner.core.fp_pipeline import confidence_band

def test_confidence_band_high_when_above_0_80():
    assert confidence_band(0.92) == "high"
    assert confidence_band(0.80) == "high"

def test_confidence_band_medium_when_between_0_55_and_0_80():
    assert confidence_band(0.70) == "medium"
    assert confidence_band(0.55) == "medium"

def test_confidence_band_low_when_below_0_55():
    assert confidence_band(0.40) == "low"
    assert confidence_band(0.00) == "low"
```

**Implementation file:** `scanner/core/fp_pipeline.py`
**Layer:** core (pure)
**Acceptance:** pytest tests/unit/test_fp_pipeline.py passes

---

### TASK-04: Assign evidence_stage in fp_pipeline

**Depends on:** TASK-03 complete

**Test to write:**
```python
from scanner.core.fp_pipeline import run_fp_pipeline

def test_active_finding_has_evidence_stage_active_finding():
    finding = make_finding(confidence=0.92)
    active, suppressed = run_fp_pipeline(
        [finding], "fetch https://x.com", "skill.md",
        frozenset({"skill.md"}))
    assert active[0].evidence_stage == "active_finding"

def test_suppressed_finding_has_evidence_stage_low_confidence_suppressed():
    finding = make_finding(confidence=0.20)
    active, suppressed = run_fp_pipeline(
        [finding], "fetch https://x.com", "skill.md",
        frozenset({"skill.md"}))
    assert suppressed[0].evidence_stage == "low_confidence_suppressed"
```

**Implementation file:** `scanner/core/fp_pipeline.py`
**Layer:** core (pure)
**Acceptance:** pytest tests/unit/test_fp_pipeline.py passes

---

### TASK-05: Add evidence fields to ToxicFlow model

**Test to write:**
```python
from scanner.core.toxic_flows.models import ToxicFlow

def test_toxic_flow_derived_is_always_true():
    flow = ToxicFlow(flow_id="test-chain", title="test",
                     severity="CRITICAL", aivss_score=9.8)
    assert flow.derived is True

def test_toxic_flow_has_confidence_field():
    flow = ToxicFlow(flow_id="test-chain", title="test",
                     severity="CRITICAL", aivss_score=9.8,
                     confidence=0.78)
    assert flow.confidence == 0.78

def test_toxic_flow_confidence_band_defaults_to_low():
    flow = ToxicFlow(flow_id="test-chain", title="test",
                     severity="CRITICAL", aivss_score=9.8)
    assert flow.confidence_band == "low"
```

**Implementation file:** `scanner/core/toxic_flows/models.py`
**Layer:** core (data)
**Acceptance:** pytest tests/unit/test_toxic_flows.py passes

---

### TASK-06: Write golden fixture — clean scan

**No implementation code.** Just the fixture JSON and a contract test.

**Test to write:**
```python
import json
from pathlib import Path

GOLDEN_DIR = Path("tests/fixtures/golden")

def test_golden_clean_scan_shape():
    golden = json.loads((GOLDEN_DIR / "clean_scan.json").read_text())
    assert golden["findings"] == []
    assert golden["toxic_flows"] == []
    assert golden["suppressed_findings"] == []
    assert golden["risk_score"] == 0.0
    assert "scan_time_ms" in golden
```

**Fixture to create:** `tests/fixtures/golden/clean_scan.json`
**Also create:** `tests/fixtures/input/clean.md` (no findings expected)
**Layer:** tests
**Acceptance:** pytest tests/unit/test_output_contracts.py::test_golden_clean_scan_shape passes

---

### TASK-07: Write golden fixture — active finding with evidence fields

**Depends on:** TASK-02 and TASK-06 complete

**Test to write:**
```python
def test_golden_active_finding_has_evidence_fields():
    golden = json.loads((GOLDEN_DIR / "active_finding.json").read_text())
    f = golden["findings"][0]
    assert "confidence" in f
    assert "confidence_band" in f
    assert "evidence_stage" in f
    assert f["evidence_stage"] == "active_finding"
    assert "aivss_score" in f
    assert "derived" in f
    assert f["derived"] is False
    # AIVSS and confidence are separate
    assert f["aivss_score"] != f["confidence"]
```

**Fixtures to create:**
- `tests/fixtures/input/active_finding.md`
- `tests/fixtures/golden/active_finding.json`

---

### TASK-08: Write golden fixture — accepted risk expired + resurfaces

**Test to write:**
```python
def test_golden_expired_accepted_risk_resurfaces_as_active():
    golden = json.loads((GOLDEN_DIR / "accepted_risk_expired.json").read_text())
    # The expired risk must appear in findings[], not suppressed
    assert len(golden["findings"]) >= 1
    f = golden["findings"][0]
    assert f["evidence_stage"] == "resurfaced_finding"
    # The accepted_findings array shows the expired entry
    expired = golden["accepted_findings"][0]
    assert expired["is_expired"] is True
```

---

### TASK-09: Write remaining golden fixtures (05–11)

After TASK-07 and TASK-08 establish the pattern, write the remaining fixtures:
- `low_confidence_suppressed.json`
- `inline_suppressed.json`
- `justified_false_positive.json`
- `toxic_flow.json`
- `conformance_pass.json`
- `conformance_fail.json`
- `scan_error.json`

One per test. One per session if needed.

---

## In Progress

(move task here when started)

## Done

(move task here when pytest passes and committed)
