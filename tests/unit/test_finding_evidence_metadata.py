"""
Tests for evidence/confidence metadata fields on Finding.
Issue #69 — first-class evidence fields in public JSON output.

Run: pytest tests/unit/test_finding_evidence_metadata.py -x -q
"""

# These tests will FAIL until TASK-01 and TASK-02 are implemented.
# That is expected — write the test first, then implement.
#
# from scanner.models import Finding, Severity
#
# def make_finding(**kwargs) -> Finding:
#     defaults = dict(rule_id="bawbel-test", ave_id="AVE-2026-00001",
#                     title="t", description="t",
#                     severity=Severity.HIGH, aivss_score=8.0,
#                     line=1, match="test", engine="pattern")
#     return Finding(**{**defaults, **kwargs})
#
# def test_finding_has_confidence_field():
#     f = make_finding()
#     assert f.confidence == 0.0
#     assert f.derived is False
#     assert f.evidence_stage == "static_detection"
#
# def test_finding_to_dict_includes_confidence():
#     f = make_finding(confidence=0.85)
#     d = f.to_dict()
#     assert "confidence" in d
#     assert d["confidence"] == 0.85
#
# def test_aivss_and_confidence_are_separate():
#     f = make_finding(aivss_score=8.0, confidence=0.85)
#     d = f.to_dict()
#     assert d["aivss_score"] == 8.0
#     assert d["confidence"] == 0.85
#     assert d["aivss_score"] != d["confidence"]
