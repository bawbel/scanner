"""
Tests for evidence/confidence metadata fields on Finding.
Issue #69 — first-class evidence fields seeded from AVE_META.

Run: pytest tests/unit/test_finding_evidence_metadata.py -x -q

Evidence lifecycle:
  1. AVE_META[ave_id].confidence_baseline → Finding.confidence (set by _make_finding)
  2. FP pipeline (score_confidence) seeds from that baseline, applies context deltas
  3. Toxic flow confidence = min(confidence) across contributing findings
"""

from pathlib import Path

import pytest

from scanner.ave_meta import AVE_META, EveMeta, get_ave_meta
from scanner.models import Finding, Severity
from scanner.core.fp_pipeline import score_confidence
from scanner.scanner import scan

MALICIOUS = Path("tests/fixtures/skills/malicious/malicious_skill.md")


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="test-rule",
        ave_id="AVE-2026-00001",
        title="Test finding",
        description="desc",
        severity=Severity.HIGH,
        aivss_score=7.0,
        engine="pattern",
        line=5,
        match="test match string",
    )
    return Finding(**{**defaults, **kwargs})


# ── AVE_META table tests ───────────────────────────────────────────────────────


class TestAveMeta:
    def test_known_ave_id_returns_correct_baseline(self):
        meta = get_ave_meta("AVE-2026-00001", "pattern")
        assert isinstance(meta, EveMeta)
        assert meta.confidence_baseline == 0.83
        assert meta.evidence_kind == "multi_engine"
        assert meta.detection_stage == "static_detection"
        assert meta.detection_layer == "content"

    def test_all_51_records_present(self):
        expected_ids = [f"AVE-2026-{i:05d}" for i in range(1, 52)]
        for ave_id in expected_ids:
            assert ave_id in AVE_META, f"{ave_id} missing from AVE_META"

    def test_llm_engine_fallback_uses_semantic_inference(self):
        meta = get_ave_meta(None, "llm")
        assert meta.confidence_baseline == 0.52
        assert meta.evidence_kind == "semantic_inference"

    def test_unknown_id_llm_fallback(self):
        meta = get_ave_meta("AVE-2026-99999", "llm")
        assert meta.confidence_baseline == 0.52
        assert meta.evidence_kind == "semantic_inference"

    def test_static_engine_fallback_uses_multi_engine(self):
        meta = get_ave_meta(None, "pattern")
        assert meta.confidence_baseline == 0.75
        assert meta.evidence_kind == "multi_engine"

    def test_static_engine_fallback_for_yara(self):
        meta = get_ave_meta(None, "yara")
        assert meta.confidence_baseline == 0.75

    def test_all_confidence_baselines_in_range(self):
        for ave_id, meta in AVE_META.items():
            assert (
                0.0 < meta.confidence_baseline <= 1.0
            ), f"{ave_id}: confidence_baseline {meta.confidence_baseline} out of range"

    def test_all_evidence_kinds_are_valid(self):
        valid = {
            "multi_engine",
            "tool_description_pattern",
            "behavioral_pattern",
            "semantic_inference",
            "file_type_mismatch",
            "config_schema",
        }
        for ave_id, meta in AVE_META.items():
            assert (
                meta.evidence_kind in valid
            ), f"{ave_id}: unknown evidence_kind '{meta.evidence_kind}'"

    def test_all_detection_stages_are_valid(self):
        for ave_id, meta in AVE_META.items():
            assert meta.detection_stage in {
                "static_detection",
                "runtime_observed",
            }, f"{ave_id}: unknown detection_stage '{meta.detection_stage}'"

    def test_all_detection_layers_are_valid(self):
        valid = {"content", "server_card", "runtime", "registry_metadata"}
        for ave_id, meta in AVE_META.items():
            assert (
                meta.detection_layer in valid
            ), f"{ave_id}: unknown detection_layer '{meta.detection_layer}'"


# ── Finding model field tests ──────────────────────────────────────────────────


class TestFindingEvidenceFields:
    def test_finding_has_confidence_field(self):
        f = _make_finding()
        assert hasattr(f, "confidence")

    def test_finding_has_evidence_kind_field(self):
        f = _make_finding()
        assert hasattr(f, "evidence_kind")

    def test_finding_has_detection_stage_field(self):
        f = _make_finding()
        assert hasattr(f, "detection_stage")

    def test_finding_has_detection_layer_field(self):
        f = _make_finding()
        assert hasattr(f, "detection_layer")

    def test_evidence_fields_default_to_none_or_zero(self):
        f = _make_finding()
        assert f.confidence == 0.0
        assert f.evidence_kind is None
        assert f.detection_stage is None
        assert f.detection_layer is None

    def test_evidence_fields_accept_values(self):
        f = _make_finding(
            confidence=0.83,
            evidence_kind="multi_engine",
            detection_stage="static_detection",
            detection_layer="content",
        )
        assert f.confidence == 0.83
        assert f.evidence_kind == "multi_engine"
        assert f.detection_stage == "static_detection"
        assert f.detection_layer == "content"

    def test_aivss_score_and_confidence_are_separate_fields(self):
        """aivss_score is severity (0–10), confidence is certainty (0–1)."""
        f = _make_finding(aivss_score=8.0, confidence=0.85)
        assert f.aivss_score == 8.0
        assert f.confidence == 0.85
        assert f.aivss_score != f.confidence


# ── FP pipeline seeds from baseline ───────────────────────────────────────────


class TestFpPipelineSeeding:
    def test_score_confidence_seeds_from_baseline_not_one(self):
        """FP pipeline must start from finding.confidence, not hardcoded 1.0."""
        low_baseline = _make_finding(confidence=0.52, ave_id=None)
        high_baseline = _make_finding(confidence=0.99, ave_id=None)
        path = Path("tests/fixtures/skills/malicious/malicious_skill.md")
        lines = [""] * 30  # no negation context

        low_score = score_confidence(low_baseline, lines, path, [])
        high_score = score_confidence(high_baseline, lines, path, [])

        assert (
            low_score < high_score
        ), f"FP pipeline ignores baseline: low={low_score}, high={high_score}"

    def test_score_confidence_zero_baseline_falls_back_to_one(self):
        """confidence=0.0 means unset — pipeline falls back to 1.0 seed."""
        f_zero = _make_finding(confidence=0.0, ave_id=None)
        f_high = _make_finding(confidence=0.99, ave_id=None)
        path = Path("tests/fixtures/skills/malicious/malicious_skill.md")
        lines = [""] * 30

        score_zero = score_confidence(f_zero, lines, path, [])
        score_high = score_confidence(f_high, lines, path, [])

        # Both should be near-max since seed is 1.0 and 0.99 respectively
        assert (
            abs(score_zero - score_high) < 0.05
        ), f"zero baseline should behave close to 1.0 seed: {score_zero} vs {score_high}"

    def test_score_confidence_output_in_range(self):
        for baseline in (0.52, 0.65, 0.75, 0.83, 0.90, 0.98, 1.0):
            f = _make_finding(confidence=baseline, ave_id=None)
            result = score_confidence(
                f,
                [""] * 30,
                Path("tests/fixtures/skills/malicious/malicious_skill.md"),
                [],
            )
            assert 0.0 <= result <= 1.0, f"score {result} out of [0,1] for baseline {baseline}"


# ── Integration: scan() seeds Finding.confidence from AVE_META ────────────────


class TestScanSeedsConfidence:
    @pytest.fixture(scope="class")
    def findings(self):
        result = scan(str(MALICIOUS))
        return {f.rule_id: f for f in result.findings}

    def test_external_fetch_seeded_from_multi_engine_baseline(self, findings):
        """AVE-2026-00001 baseline=0.83; with context bonuses, final > 0.83."""
        f = findings["bawbel-external-fetch"]
        assert f.evidence_kind == "multi_engine"
        assert f.detection_stage == "static_detection"
        assert f.confidence > 0.83  # FP pipeline adds bonuses

    def test_hidden_instruction_seeded_from_tool_description_baseline(self, findings):
        """AVE-2026-00010 baseline=0.65; final confidence reflects that lower starting point."""
        f = findings["bawbel-hidden-instruction"]
        assert f.evidence_kind == "tool_description_pattern"
        assert f.detection_stage == "static_detection"
        # Should be above threshold (0.60 for skill profile)
        assert f.confidence >= 0.60

    def test_all_active_findings_have_evidence_fields_populated(self, findings):
        for rule_id, f in findings.items():
            assert f.confidence > 0.0, f"confidence=0 on {rule_id}"
            assert f.evidence_kind is not None, f"evidence_kind=None on {rule_id}"
            assert f.detection_stage is not None, f"detection_stage=None on {rule_id}"
            assert f.detection_layer is not None, f"detection_layer=None on {rule_id}"

    def test_all_active_findings_confidence_in_range(self, findings):
        for rule_id, f in findings.items():
            assert (
                0.0 <= f.confidence <= 1.0
            ), f"confidence {f.confidence} out of [0,1] on {rule_id}"


# ── Toxic flow confidence = min of contributors ───────────────────────────────


class TestToxicFlowConfidence:
    @pytest.fixture(scope="class")
    def scan_result(self):
        return scan(str(MALICIOUS))

    def test_toxic_flows_have_confidence(self, scan_result):
        assert scan_result.toxic_flows, "expected toxic flows on malicious fixture"
        for tf in scan_result.toxic_flows:
            assert hasattr(tf, "confidence")

    def test_toxic_flow_confidence_is_min_of_contributors(self, scan_result):
        # detect_toxic_flows runs before the FP pipeline, so tf.confidence
        # is seeded from AVE baselines (not post-FP values). Compare against
        # AVE_META baselines, not scan_result.findings[i].confidence.
        for tf in scan_result.toxic_flows:
            baselines = [AVE_META[aid].confidence_baseline for aid in tf.ave_ids if aid in AVE_META]
            if baselines:
                expected_min = round(min(baselines), 2)
                assert abs(tf.confidence - expected_min) < 1e-9, (
                    f"flow '{tf.flow_id}' confidence {tf.confidence} != "
                    f"min of AVE baselines {expected_min}"
                )

    def test_toxic_flow_confidence_in_range(self, scan_result):
        for tf in scan_result.toxic_flows:
            assert (
                0.0 <= tf.confidence <= 1.0
            ), f"toxic flow '{tf.flow_id}' confidence {tf.confidence} out of [0,1]"

    def test_toxic_flow_confidence_in_to_dict(self, scan_result):
        for tf in scan_result.toxic_flows:
            d = tf.to_dict()
            assert "confidence" in d
            assert d["confidence"] == round(tf.confidence, 2)
