from scanner.core.dedup import deduplicate
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
        match="test",
        engine="pattern",
    )
    return Finding(**{**defaults, **kwargs})


def test_deduplicate_empty_list_returns_empty():
    assert deduplicate([]) == []


def test_deduplicate_single_finding_returns_single():
    f = make_finding()
    assert deduplicate([f]) == [f]


def test_deduplicate_removes_exact_duplicate_rule_id():
    f = make_finding()
    assert len(deduplicate([f, f])) == 1


def test_deduplicate_keeps_highest_severity_for_same_rule_id():
    low = make_finding(rule_id="bawbel-test", severity=Severity.LOW, aivss_score=2.0)
    high = make_finding(rule_id="bawbel-test", severity=Severity.HIGH, aivss_score=7.0)
    result = deduplicate([low, high])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


def test_deduplicate_keeps_distinct_rule_ids():
    f1 = make_finding(rule_id="bawbel-rule-a", ave_id=None)
    f2 = make_finding(rule_id="bawbel-rule-b", ave_id=None)
    assert len(deduplicate([f1, f2])) == 2


def test_deduplicate_cross_engine_keeps_pattern_over_yara_for_same_ave_id():
    pattern = make_finding(rule_id="bawbel-pattern", ave_id="AVE-2026-00001", engine="pattern")
    yara = make_finding(rule_id="bawbel-yara", ave_id="AVE-2026-00001", engine="yara")
    result = deduplicate([yara, pattern])
    assert len(result) == 1
    assert result[0].engine == "pattern"


def test_deduplicate_preserves_finding_with_no_ave_id():
    f1 = make_finding(rule_id="bawbel-no-ave", ave_id=None)
    f2 = make_finding(rule_id="bawbel-with-ave", ave_id="AVE-2026-00001")
    result = deduplicate([f1, f2])
    assert len(result) == 2
