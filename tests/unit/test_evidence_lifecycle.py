"""
Tests for the full evidence confidence lifecycle.
Issue #71 — lifecycle from AVE baseline through FP pipeline to meta-analyzer.

Lifecycle:
  1. Engine fires → Finding.confidence = AVE_META[ave_id].confidence_baseline
  2. FP-2 (negation context)  → suppress immediately if doc-example signal found
  3. FP-3 (score_confidence)  → adjust ± based on file context
  4. Threshold check          → suppress if confidence < profile threshold
  5. FP-4 (meta-analyzer)     → LLM reclassifies medium-confidence findings
  6. ToxicFlow.confidence     → min(contributing finding baselines)

Run: pytest tests/unit/test_evidence_lifecycle.py -x -q
"""

import os
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.ave_meta import AVE_META, get_ave_meta
from scanner.core.fp_pipeline import confidence_band, run_fp_pipeline, score_confidence
from scanner.engines.meta_analyzer import run_meta_analysis
from scanner.models import Finding, Severity

# ── Helpers ────────────────────────────────────────────────────────────────────

_FAKE_LITELLM = types.ModuleType("litellm")


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


def _run_meta_with_verdicts(findings: list, verdicts: list) -> list:
    """Run meta-analyzer with a patched _call_llm and a fake litellm module."""
    with (
        patch.dict("sys.modules", {"litellm": _FAKE_LITELLM}),
        patch("scanner.engines.meta_analyzer._call_llm", return_value=verdicts),
        patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-meta-key"}),
    ):
        return run_meta_analysis(findings, "mock content", "/fake/test.md")


# ── confidence_band utility ────────────────────────────────────────────────────


class TestConfidenceBand:
    """confidence_band() maps scores to human-readable tiers."""

    def test_high_band_at_and_above_0_80(self):
        assert confidence_band(0.80) == "high"
        assert confidence_band(0.90) == "high"
        assert confidence_band(1.00) == "high"

    def test_medium_band_between_0_55_and_0_79(self):
        assert confidence_band(0.55) == "medium"
        assert confidence_band(0.70) == "medium"
        assert confidence_band(0.79) == "medium"

    def test_low_band_below_0_55(self):
        assert confidence_band(0.54) == "low"
        assert confidence_band(0.35) == "low"
        assert confidence_band(0.00) == "low"

    def test_band_boundaries_are_exclusive_at_top(self):
        """0.80 is high; 0.79... is still medium."""
        assert confidence_band(0.799) == "medium"
        assert confidence_band(0.800) == "high"

    def test_all_baselines_have_valid_band(self):
        for ave_id, meta in AVE_META.items():
            band = confidence_band(meta.confidence_baseline)
            assert band in {
                "high",
                "medium",
                "low",
            }, f"{ave_id}: unexpected band '{band}' for baseline {meta.confidence_baseline}"


# ── Stage 1: Baseline seeding ─────────────────────────────────────────────────


class TestBaselineSeeding:
    """Confidence seeds from the AVE_META lookup at detection time."""

    def test_known_ave_id_seeds_correct_baseline(self):
        meta = get_ave_meta("AVE-2026-00001", "pattern")
        f = _make_finding(confidence=meta.confidence_baseline)
        assert f.confidence == 0.83

    def test_llm_engine_seeds_lower_baseline_than_static(self):
        static_meta = get_ave_meta("AVE-2026-00001", "pattern")
        llm_meta = get_ave_meta(None, "llm")
        assert llm_meta.confidence_baseline < static_meta.confidence_baseline

    def test_unknown_id_static_engine_falls_back_to_0_75(self):
        meta = get_ave_meta("AVE-2099-99999", "pattern")
        assert meta.confidence_baseline == 0.75


# ── Stage 2: FP-2 negation context ────────────────────────────────────────────


class TestFp2NegationContext:
    """FP-2 suppresses findings in documentation examples before confidence scoring."""

    def test_negation_prefix_suppresses_finding(self):
        f = _make_finding(line=2, confidence=0.99)
        result = run_fp_pipeline([f], Path("skill.md"), "bad example:\nmatch text")
        assert f not in result
        assert f.suppressed is True
        assert "negation_context" in (f.suppression_reason or "")

    def test_clean_preceding_line_does_not_suppress(self):
        f = _make_finding(line=2, confidence=0.99)
        result = run_fp_pipeline([f], Path("skill.md"), "normal context:\nmatch text")
        assert f in result
        assert not f.suppressed

    def test_negation_at_line_one_is_not_triggered(self):
        """Line 1 has no preceding line — negation check must not error."""
        f = _make_finding(line=1, confidence=0.99)
        result = run_fp_pipeline([f], Path("skill.md"), "match text")
        assert f in result


# ── Stage 3: FP-3 confidence scoring adjustments ──────────────────────────────


class TestFp3ConfidenceAdjustments:
    """FP-3 applies context-based deltas to the AVE baseline."""

    def test_early_line_adds_bonus(self):
        """Lines ≤ 30 in non-docs path get +0.15 bonus."""
        f = _make_finding(line=5, confidence=0.60, ave_id=None)
        lines = [""] * 30
        score = score_confidence(f, lines, Path("random.txt"), [])
        # +0.15 early-line (no skill name, no agreement, no short match penalty)
        assert score == pytest.approx(0.60 + 0.15, abs=1e-9)

    def test_docs_path_applies_penalty(self):
        """Files in docs/ segment get -0.35 penalty."""
        f = _make_finding(line=3, confidence=0.90, ave_id=None)
        lines = [""] * 30
        docs_score = score_confidence(f, lines, Path("/proj/docs/guide.md"), [])
        plain_score = score_confidence(f, lines, Path("/proj/guide.md"), [])
        assert docs_score < plain_score

    def test_multi_engine_agreement_adds_bonus(self):
        """Same AVE ID from two engines → +0.25."""
        f1 = _make_finding(engine="pattern", ave_id="AVE-2026-00001", line=35, confidence=0.60)
        f2 = _make_finding(
            engine="yara", ave_id="AVE-2026-00001", rule_id="yara-rule", line=35, confidence=0.60
        )
        lines = [""] * 34 + ["| match |"]  # table penalty keeps us off the ceiling
        solo = score_confidence(f1, lines, Path("file.md"), [f1])
        agreed = score_confidence(f1, lines, Path("file.md"), [f1, f2])
        assert agreed > solo

    def test_skill_file_name_adds_bonus(self):
        """Filename exactly matches skill names list → +0.15."""
        f = _make_finding(line=35, confidence=0.60, ave_id=None)
        lines = [""] * 34 + ["| match |"]  # table penalty
        skill_score = score_confidence(f, lines, Path("skill.md"), [])
        random_score = score_confidence(f, lines, Path("random.txt"), [])
        assert skill_score > random_score

    def test_high_aivss_score_adds_bonus(self):
        """aivss_score ≥ 9.0 → +0.05."""
        f_high = _make_finding(line=35, confidence=0.60, aivss_score=9.5, ave_id=None)
        f_low = _make_finding(line=35, confidence=0.60, aivss_score=7.0, ave_id=None)
        lines = [""] * 34 + ["| match |"]
        high_score = score_confidence(f_high, lines, Path("file.md"), [])
        low_score = score_confidence(f_low, lines, Path("file.md"), [])
        assert high_score > low_score

    def test_output_always_in_range(self):
        """All adjustments combined must never produce a value outside [0.0, 1.0]."""
        for baseline in (0.0, 0.35, 0.52, 0.75, 0.99, 1.0):
            f = _make_finding(confidence=baseline, ave_id=None)
            result = score_confidence(f, [""] * 30, Path("skill.md"), [])
            assert 0.0 <= result <= 1.0, f"baseline={baseline} produced out-of-range score {result}"


# ── Stage 4: Threshold suppression ────────────────────────────────────────────


class TestThresholdSuppression:
    """Findings below the profile threshold are suppressed before meta-analysis."""

    def test_finding_below_docs_threshold_is_suppressed(self):
        """docs/ profile threshold is 0.85 — low-confidence finding is suppressed."""
        f = _make_finding(line=None, confidence=0.30, ave_id=None)
        result = run_fp_pipeline([f], Path("/proj/docs/guide.md"), "match text")
        assert f not in result
        assert f.suppressed is True
        assert "low_confidence" in (f.suppression_reason or "")

    def test_suppression_reason_includes_profile_name(self):
        f = _make_finding(line=None, confidence=0.30, ave_id=None)
        run_fp_pipeline([f], Path("/proj/docs/guide.md"), "match text")
        assert "documentation" in (f.suppression_reason or "")

    def test_skill_profile_has_lower_threshold_than_docs(self):
        """skill profile (0.60) is more permissive than documentation (0.85)."""
        f_skill = _make_finding(line=None, confidence=0.70, ave_id=None)
        f_docs = _make_finding(line=None, confidence=0.70, ave_id=None)
        skill_result = run_fp_pipeline([f_skill], Path("skill.md"), "match text")
        docs_result = run_fp_pipeline([f_docs], Path("/proj/docs/guide.md"), "match text")
        assert f_skill in skill_result
        assert f_docs not in docs_result


# ── Stage 5: FP-4 meta-analyzer ───────────────────────────────────────────────


class TestMetaAnalyzerLifecycle:
    """FP-4 LLM reviews medium-confidence findings and reclassifies them."""

    def test_real_verdict_boosts_confidence(self):
        f = _make_finding(confidence=0.65)
        verdicts = [{"rule_id": "test-rule", "verdict": "real", "reason": "direct instruction"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert result[0].confidence == pytest.approx(min(1.0, 0.65 + 0.15))

    def test_false_positive_verdict_suppresses_finding(self):
        f = _make_finding(confidence=0.65)
        verdicts = [{"rule_id": "test-rule", "verdict": "false_positive", "reason": "doc example"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert result[0].suppressed is True
        assert "meta_analyzer_fp" in (result[0].suppression_reason or "")

    def test_needs_review_verdict_reduces_confidence(self):
        f = _make_finding(confidence=0.65)
        verdicts = [{"rule_id": "test-rule", "verdict": "needs_review", "reason": "ambiguous"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert result[0].confidence == pytest.approx(max(0.0, 0.65 - 0.05))

    def test_real_verdict_capped_at_1_0(self):
        """0.92 + 0.15 = 1.07 — must be clamped to 1.0."""
        f = _make_finding(confidence=0.92)
        verdicts = [{"rule_id": "test-rule", "verdict": "real", "reason": "clear match"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert result[0].confidence <= 1.0

    def test_needs_review_floored_at_0_0(self):
        """0.02 - 0.05 = -0.03 — must be clamped to 0.0."""
        f = _make_finding(confidence=0.02)
        verdicts = [{"rule_id": "test-rule", "verdict": "needs_review", "reason": "ambiguous"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert result[0].confidence >= 0.0

    def test_meta_analyzer_only_sends_medium_confidence_to_llm(self):
        """Findings outside [META_MIN, META_MAX] are not sent to the LLM."""
        high = _make_finding(rule_id="high-conf", confidence=0.95)
        low = _make_finding(rule_id="low-conf", confidence=0.10)
        medium = _make_finding(rule_id="medium-conf", confidence=0.65)

        with (
            patch.dict("sys.modules", {"litellm": _FAKE_LITELLM}),
            patch("scanner.engines.meta_analyzer._call_llm") as mock_llm,
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}),
        ):
            mock_llm.return_value = [
                {"rule_id": "medium-conf", "verdict": "real", "reason": "match"}
            ]
            run_meta_analysis([high, low, medium], "content", "/test.md")

        sent = {f.rule_id for f in mock_llm.call_args[0][0]}
        assert "medium-conf" in sent
        assert "high-conf" not in sent
        assert "low-conf" not in sent

    def test_meta_analyzer_skips_when_no_medium_confidence(self):
        """No medium-confidence findings → LLM is not called at all."""
        high = _make_finding(confidence=0.95)
        with (
            patch.dict("sys.modules", {"litellm": _FAKE_LITELLM}),
            patch("scanner.engines.meta_analyzer._call_llm") as mock_llm,
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}),
        ):
            run_meta_analysis([high], "content", "/test.md")
        mock_llm.assert_not_called()

    def test_meta_analyzer_skips_when_no_provider_configured(self):
        """No LLM provider key → findings returned unchanged."""
        f = _make_finding(confidence=0.65)
        original = f.confidence
        no_keys = {
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY": "",
            "GEMINI_API_KEY": "",
            "MISTRAL_API_KEY": "",
            "GROQ_API_KEY": "",
            "BAWBEL_LLM_MODEL": "",
        }
        with (
            patch.dict("sys.modules", {"litellm": _FAKE_LITELLM}),
            patch.dict(os.environ, no_keys),
        ):
            result = run_meta_analysis([f], "content", "/test.md")
        assert result[0].confidence == original
        assert not result[0].suppressed

    def test_meta_analyzer_skips_when_disabled(self):
        """BAWBEL_META_ANALYZER_ENABLED=false → findings returned unchanged."""
        f = _make_finding(confidence=0.65)
        with patch("scanner.engines.meta_analyzer.META_ANALYZER_ENABLED", False):
            result = run_meta_analysis([f], "content", "/test.md")
        assert result[0].confidence == 0.65
        assert not result[0].suppressed

    def test_meta_analyzer_handles_none_from_llm(self):
        """If _call_llm returns None (parse error), findings are unchanged."""
        f = _make_finding(confidence=0.65)
        with (
            patch.dict("sys.modules", {"litellm": _FAKE_LITELLM}),
            patch("scanner.engines.meta_analyzer._call_llm", return_value=None),
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}),
        ):
            result = run_meta_analysis([f], "content", "/test.md")
        assert result[0].confidence == 0.65
        assert not result[0].suppressed

    def test_meta_analyzer_ignores_unknown_rule_id_verdicts(self):
        """Verdicts for rule_ids not in the findings list are silently dropped."""
        f = _make_finding(confidence=0.65)
        verdicts = [{"rule_id": "completely-different", "verdict": "false_positive", "reason": "x"}]
        result = _run_meta_with_verdicts([f], verdicts)
        assert not result[0].suppressed
        assert result[0].confidence == 0.65


# ── Stage 6: ToxicFlow confidence ─────────────────────────────────────────────


class TestToxicFlowLifecycle:
    """ToxicFlow.confidence = min(contributing finding baselines at detection time)."""

    def test_chain_confidence_equals_min_of_baselines(self):
        from scanner.core.toxic_flows.detector import detect_toxic_flows

        # AVE-2026-00003: 0.83, AVE-2026-00026: 0.88 → min = 0.83
        f1 = _make_finding(
            rule_id="cred-read",
            ave_id="AVE-2026-00003",
            confidence=AVE_META["AVE-2026-00003"].confidence_baseline,
            engine="pattern",
        )
        f2 = _make_finding(
            rule_id="exfil",
            ave_id="AVE-2026-00026",
            confidence=AVE_META["AVE-2026-00026"].confidence_baseline,
            engine="yara",
        )
        flows = detect_toxic_flows([f1, f2])
        cred_flow = next((fl for fl in flows if fl.flow_id == "credential-exfiltration"), None)
        if cred_flow:
            expected = round(
                min(
                    AVE_META["AVE-2026-00003"].confidence_baseline,
                    AVE_META["AVE-2026-00026"].confidence_baseline,
                ),
                2,
            )
            assert cred_flow.confidence == pytest.approx(expected)

    def test_chain_confidence_in_range(self):
        from scanner.core.toxic_flows.detector import detect_toxic_flows

        f1 = _make_finding(
            rule_id="cred",
            ave_id="AVE-2026-00003",
            confidence=0.83,
            engine="pattern",
        )
        f2 = _make_finding(
            rule_id="exfil",
            ave_id="AVE-2026-00026",
            confidence=0.88,
            engine="yara",
        )
        for flow in detect_toxic_flows([f1, f2]):
            assert 0.0 <= flow.confidence <= 1.0

    def test_single_ave_id_can_trigger_flow_via_dual_capabilities(self):
        """AVE-2026-00003 has both credential-read AND data-exfil.
        With a second finding present (required minimum), it forms a flow alone."""
        from scanner.core.toxic_flows.detector import detect_toxic_flows

        f1 = _make_finding(ave_id="AVE-2026-00003", confidence=0.83, engine="pattern")
        # Second finding needed to clear len(findings) >= 2 guard; no capability of its own
        f2 = _make_finding(rule_id="padding", ave_id=None, confidence=0.60, engine="pattern")
        flows = detect_toxic_flows([f1, f2])
        flow_ids = {fl.flow_id for fl in flows}
        assert "credential-exfiltration" in flow_ids
