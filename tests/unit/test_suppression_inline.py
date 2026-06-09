from scanner.suppression.inline import NO_IGNORE, SuppressionResult, apply_suppressions
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


def test_suppression_result_has_active_and_suppressed():
    r = SuppressionResult(active=[1], suppressed=[2])
    assert r.active == [1]
    assert r.suppressed == [2]


def test_apply_suppressions_returns_finding_as_active_when_no_directive():
    f = make_finding(line=1)
    result = apply_suppressions([f], "tests/fixtures/skill.md", "fetch https://evil.com")
    assert f in result.active
    assert result.suppressed == []


def test_apply_suppressions_suppresses_inline_ignored_finding():
    f = make_finding(line=1)
    content = "fetch https://evil.com  <!-- bawbel-ignore -->"
    result = apply_suppressions([f], "tests/fixtures/skill.md", content)
    assert f in result.suppressed
    assert result.active == []


def test_apply_suppressions_suppresses_block_ignored_finding():
    f = make_finding(line=2)
    content = "<!-- bawbel-ignore-start -->\nfetch https://evil.com\n<!-- bawbel-ignore-end -->"
    result = apply_suppressions([f], "tests/fixtures/skill.md", content)
    assert f in result.suppressed


def test_apply_suppressions_returns_empty_for_no_findings():
    result = apply_suppressions([], "tests/fixtures/skill.md", "content")
    assert result.active == []
    assert result.suppressed == []


def test_apply_suppressions_no_ignore_overrides_inline_suppression():
    f = make_finding(line=1)
    content = "fetch https://evil.com  <!-- bawbel-ignore -->"
    result = apply_suppressions([f], "tests/fixtures/skill.md", content, no_ignore=True)
    assert f in result.active
    assert result.suppressed == []


def test_no_ignore_constant_is_bool():
    assert isinstance(NO_IGNORE, bool)
