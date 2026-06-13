from pathlib import Path

from scanner.core.fp_pipeline import (
    classify_file,
    has_negation_context,
    run_fp_pipeline,
    score_confidence,
)
from scanner.models import Finding, Severity


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="bawbel-test",
        ave_id="AVE-2026-00001",
        title="t",
        description="t",
        severity=Severity.HIGH,
        aivss_score=7.0,
        line=1,
        match="test match",
        engine="pattern",
    )
    return Finding(**{**defaults, **kwargs})


# ── classify_file ──────────────────────────────────────────────────────────────


def test_classify_file_returns_skill_for_skill_md():
    assert classify_file(Path("skill.md")) == "skill"


def test_classify_file_returns_skill_for_system_prompt_md():
    assert classify_file(Path("system_prompt.md")) == "skill"


def test_classify_file_returns_mcp_manifest_for_mcp_manifest_json():
    assert classify_file(Path("mcp_manifest.json")) == "mcp_manifest"


def test_classify_file_returns_mcp_manifest_for_mcp_prefixed_yaml():
    assert classify_file(Path("mcp_config.yaml")) == "mcp_manifest"


def test_classify_file_returns_documentation_for_docs_path():
    assert classify_file(Path("/project/docs/guide.md")) == "documentation"


def test_classify_file_returns_documentation_for_readme():
    assert classify_file(Path("readme.md")) == "documentation"


def test_classify_file_returns_unknown_for_unrecognised_file():
    assert classify_file(Path("random_file.txt")) == "unknown"


# ── has_negation_context ───────────────────────────────────────────────────────


def test_has_negation_context_returns_false_for_empty_lines():
    assert has_negation_context([], 0) is False


def test_has_negation_context_returns_false_for_line_one():
    assert has_negation_context(["some line"], 1) is False


def test_has_negation_context_returns_true_when_preceding_line_has_negation_prefix():
    lines = ["bad example:", "fetch https://evil.com"]
    assert has_negation_context(lines, 2) is True


def test_has_negation_context_returns_true_for_avoid_prefix():
    lines = ["avoid:", "fetch https://evil.com"]
    assert has_negation_context(lines, 2) is True


def test_has_negation_context_returns_false_when_preceding_line_is_benign():
    lines = ["legitimate use:", "fetch https://good.com"]
    assert has_negation_context(lines, 2) is False


def test_has_negation_context_returns_false_for_none_line_no():
    assert has_negation_context(["bad example:", "code"], None) is False


# ── score_confidence ───────────────────────────────────────────────────────────


def test_score_confidence_returns_float_between_0_and_1():
    f = make_finding()
    result = score_confidence(f, ["test match"], Path("skill.md"), [f])
    assert 0.0 <= result <= 1.0


def test_score_confidence_is_lower_for_docs_path_than_skill_path():
    f = make_finding()
    lines = ["test match"]
    docs_score = score_confidence(f, lines, Path("/project/docs/guide.md"), [f])
    skill_score = score_confidence(f, lines, Path("/project/skill.md"), [f])
    assert docs_score < skill_score


def test_score_confidence_boosts_for_skill_file_name():
    # Use a table-formatted line (starts with |) to introduce a base penalty so
    # the +0.15 skill-name boost is observable rather than lost to the 1.0 ceiling.
    f = make_finding(line=35)
    lines = [""] * 34 + ["| fetch https://evil.com |"]
    skill_score = score_confidence(f, lines, Path("skill.md"), [f])
    unknown_score = score_confidence(f, lines, Path("random.txt"), [f])
    assert skill_score > unknown_score


def test_score_confidence_penalises_negation_context():
    f = make_finding(line=2)
    lines = ["bad example:", "test match"]
    penalised = score_confidence(f, lines, Path("random.txt"), [f])
    f2 = make_finding(line=2)
    lines_clean = ["normal line:", "test match"]
    clean = score_confidence(f2, lines_clean, Path("random.txt"), [f2])
    assert penalised < clean


def test_score_confidence_boosts_for_multi_engine_agreement():
    # Use line=35 (no early-line boost) with a table-formatted line so the
    # +0.25 multi-engine boost is observable rather than lost to the 1.0 ceiling.
    f1 = make_finding(engine="pattern", ave_id="AVE-2026-00001", line=35)
    f2 = make_finding(engine="yara", ave_id="AVE-2026-00001", rule_id="bawbel-yara", line=35)
    lines = [""] * 34 + ["| fetch https://evil.com |"]
    score_with_agreement = score_confidence(f1, lines, Path("random.txt"), [f1, f2])
    score_alone = score_confidence(f1, lines, Path("random.txt"), [f1])
    assert score_with_agreement > score_alone


# ── run_fp_pipeline ────────────────────────────────────────────────────────────


def test_run_fp_pipeline_returns_empty_for_empty_input():
    assert run_fp_pipeline([], Path("skill.md"), "") == []


def test_run_fp_pipeline_keeps_high_confidence_findings():
    f = make_finding(line=1)
    content = "fetch https://evil.com"
    result = run_fp_pipeline([f], Path("skill.md"), content)
    assert f in result


def test_run_fp_pipeline_suppresses_negation_context_findings():
    f = make_finding(line=2)
    content = "bad example:\nfetch https://evil.com"
    result = run_fp_pipeline([f], Path("skill.md"), content)
    assert f not in result
    assert f.suppressed is True


def test_run_fp_pipeline_suppresses_low_confidence_findings_in_docs():
    f = make_finding(line=1)
    content = "fetch https://evil.com"
    result = run_fp_pipeline([f], Path("/project/docs/guide.md"), content)
    assert f not in result
    assert f.suppressed is True
