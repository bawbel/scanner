"""
Golden JSON fixture contract tests.
Issue #70 — lock the public output schema.

Run: pytest tests/unit/test_output_contracts.py -x -q

Fixtures live in tests/fixtures/golden/
Generate them with:
  bawbel scan tests/fixtures/input/clean.md --format json | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(json.dumps(d[0],indent=2))" \
    > tests/fixtures/golden/clean_scan.json
"""

from pathlib import Path

GOLDEN = Path("tests/fixtures/golden")


# Uncomment each test as the corresponding fixture is created.

# def test_golden_clean_scan_shape():
#     data = json.loads((GOLDEN / "clean_scan.json").read_text())
#     assert data["findings"] == []
#     assert data["toxic_flows"] == []
#     assert data["risk_score"] == 0.0
#     assert "scan_time_ms" in data

# def test_golden_active_finding_has_evidence_fields():
#     data = json.loads((GOLDEN / "active_finding.json").read_text())
#     f = data["findings"][0]
#     assert "confidence" in f
#     assert "evidence_stage" in f
#     assert f["evidence_stage"] == "active_finding"
#     assert f["derived"] is False
#     assert f["aivss_score"] != f["confidence"]

# def test_golden_toxic_flow_is_derived():
#     data = json.loads((GOLDEN / "toxic_flow.json").read_text())
#     flow = data["toxic_flows"][0]
#     assert flow["derived"] is True
#     assert len(flow["derived_from_findings"]) >= 2
#     assert "chain_confidence_reason" in flow
