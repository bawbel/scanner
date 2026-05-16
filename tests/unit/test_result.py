"""
Unit tests for scanner.models.result.ScanResult
"""

from scanner.models.finding import Finding, Severity
from scanner.models.result import ScanResult


def make_finding(rule_id="bawbel-test", severity=Severity.HIGH, aivss_score=7.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        ave_id=None,
        title="Test",
        description="Test",
        severity=severity,
        aivss_score=aivss_score,
    )


def make_result(
    file_path="/tmp/skill.md", findings=None, error=None  # nosec B108  # noqa: S108
) -> ScanResult:
    return ScanResult(
        file_path=file_path,
        component_type="skill",
        findings=findings or [],
        error=error,
    )


class TestScanResultProperties:

    def test_is_clean_no_findings(self):
        r = make_result()
        assert r.is_clean is True

    def test_is_clean_false_with_findings(self):
        r = make_result(findings=[make_finding()])
        assert r.is_clean is False

    def test_is_clean_false_with_error(self):
        r = make_result(error="E001: something wrong")
        assert r.is_clean is False

    def test_has_error_true(self):
        r = make_result(error="E001: fail")
        assert r.has_error is True

    def test_has_error_false(self):
        r = make_result()
        assert r.has_error is False

    def test_max_severity_none_when_clean(self):
        r = make_result()
        assert r.max_severity is None

    def test_max_severity_returns_highest(self):
        r = make_result(
            findings=[
                make_finding(severity=Severity.LOW, aivss_score=3.0),
                make_finding(severity=Severity.CRITICAL, aivss_score=9.5),
                make_finding(severity=Severity.MEDIUM, aivss_score=5.0),
            ]
        )
        assert r.max_severity == Severity.CRITICAL

    def test_risk_score_zero_when_clean(self):
        r = make_result()
        assert r.risk_score == 0.0

    def test_risk_score_is_max_aivss(self):
        r = make_result(
            findings=[
                make_finding(aivss_score=5.0),
                make_finding(aivss_score=9.2),
                make_finding(aivss_score=7.0),
            ]
        )
        assert r.risk_score == 9.2

    def test_findings_by_severity_structure(self):
        r = make_result(
            findings=[
                make_finding(severity=Severity.HIGH, aivss_score=7.0),
                make_finding(severity=Severity.MEDIUM, aivss_score=5.0),
            ]
        )
        by_sev = r.findings_by_severity
        assert isinstance(by_sev, dict)
        assert len(by_sev["HIGH"]) == 1
        assert len(by_sev["MEDIUM"]) == 1
        assert len(by_sev["CRITICAL"]) == 0

    def test_findings_by_severity_all_keys_present(self):
        r = make_result()
        keys = set(r.findings_by_severity.keys())
        assert keys == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_toxic_flows_default_empty(self):
        r = make_result()
        assert r.toxic_flows == []


class TestScanResultToDict:

    def test_to_dict_keys(self):
        r = make_result()
        d = r.to_dict()
        for key in (
            "file_path",
            "component_type",
            "risk_score",
            "max_severity",
            "scan_time_ms",
            "findings",
        ):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_file_path(self):
        r = make_result(file_path="/tmp/skill.md")  # nosec B108  # noqa: S108
        assert r.to_dict()["file_path"] == "/tmp/skill.md"  # nosec B108  # noqa: S108

    def test_to_dict_findings_empty(self):
        r = make_result()
        assert r.to_dict()["findings"] == []

    def test_to_dict_findings_have_aivss(self):
        r = make_result(findings=[make_finding(aivss_score=8.0)])
        d = r.to_dict()
        assert d["findings"][0]["aivss_score"] == 8.0

    def test_to_dict_toxic_flows_empty(self):
        r = make_result()
        assert r.to_dict().get("toxic_flows", []) == []
