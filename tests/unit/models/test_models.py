"""
Unit tests for scanner/models/

Tests Finding, ScanResult, and Severity in isolation.
"""

from scanner.models import Finding, ScanResult, Severity, SEVERITY_SCORES


class TestSeverity:
    """Severity enum behaviour."""

    def test_values_are_strings(self):
        for s in Severity:
            assert isinstance(s.value, str)

    def test_all_values_in_scores(self):
        for s in Severity:
            assert s.value in SEVERITY_SCORES

    def test_ordering_is_correct(self):
        assert SEVERITY_SCORES["CRITICAL"] > SEVERITY_SCORES["HIGH"]
        assert SEVERITY_SCORES["HIGH"] > SEVERITY_SCORES["MEDIUM"]
        assert SEVERITY_SCORES["MEDIUM"] > SEVERITY_SCORES["LOW"]
        assert SEVERITY_SCORES["LOW"] > SEVERITY_SCORES["INFO"]

    def test_str_comparison(self):
        """Severity extends str — can compare to string literals."""
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"

    def test_json_serialisable(self):
        import json

        result = json.dumps({"severity": Severity.HIGH})
        assert '"HIGH"' in result


class TestFinding:
    """Finding dataclass field validation."""

    def _make(self, **kwargs) -> Finding:
        defaults = dict(
            rule_id="test-rule",
            ave_id=None,
            title="Test finding",
            description="Test description",
            severity=Severity.HIGH,
            cvss_ai=7.5,
            line=1,
            match="matched text",
            engine="pattern",
            owasp=["ASI01"],
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_creates_successfully(self):
        f = self._make()
        assert f.rule_id == "test-rule"
        assert f.severity == Severity.HIGH

    def test_ave_id_can_be_none(self):
        f = self._make(ave_id=None)
        assert f.ave_id is None

    def test_line_can_be_none(self):
        f = self._make(line=None)
        assert f.line is None

    def test_match_can_be_none(self):
        f = self._make(match=None)
        assert f.match is None

    def test_owasp_defaults_to_empty_list(self):
        f = self._make(owasp=[])
        assert f.owasp == []

    def test_severity_value(self):
        f = self._make(severity=Severity.CRITICAL)
        assert f.severity.value == "CRITICAL"


class TestScanResult:
    """ScanResult computed properties."""

    def _make_finding(self, severity: Severity, cvss: float) -> Finding:
        return Finding(
            rule_id=f"rule-{severity.value.lower()}",
            ave_id=None,
            title="Test",
            description="Test",
            severity=severity,
            cvss_ai=cvss,
            line=None,
            match=None,
            engine="pattern",
            owasp=[],
        )

    def test_is_clean_with_no_findings_no_error(self):
        r = ScanResult(file_path="/f.md", component_type="skill")
        assert r.is_clean is True

    def test_is_clean_false_with_findings(self):
        f = self._make_finding(Severity.HIGH, 7.0)
        r = ScanResult(file_path="/f.md", component_type="skill", findings=[f])
        assert r.is_clean is False

    def test_is_clean_false_with_error(self):
        r = ScanResult(file_path="/f.md", component_type="skill", error="E003: ...")
        assert r.is_clean is False

    def test_has_error_true(self):
        r = ScanResult(file_path="/f.md", component_type="skill", error="E003")
        assert r.has_error is True

    def test_has_error_false(self):
        r = ScanResult(file_path="/f.md", component_type="skill")
        assert r.has_error is False

    def test_max_severity_none_when_no_findings(self):
        r = ScanResult(file_path="/f.md", component_type="skill")
        assert r.max_severity is None

    def test_max_severity_returns_highest(self):
        findings = [
            self._make_finding(Severity.LOW, 2.0),
            self._make_finding(Severity.CRITICAL, 9.4),
            self._make_finding(Severity.HIGH, 7.0),
        ]
        r = ScanResult(file_path="/f.md", component_type="skill", findings=findings)
        assert r.max_severity == Severity.CRITICAL

    def test_risk_score_zero_when_no_findings(self):
        r = ScanResult(file_path="/f.md", component_type="skill")
        assert r.risk_score == 0.0

    def test_risk_score_returns_max_cvss(self):
        findings = [
            self._make_finding(Severity.LOW, 2.0),
            self._make_finding(Severity.HIGH, 8.5),
        ]
        r = ScanResult(file_path="/f.md", component_type="skill", findings=findings)
        assert r.risk_score == 8.5

    def test_scan_time_defaults_zero(self):
        r = ScanResult(file_path="/f.md", component_type="skill")
        assert r.scan_time_ms == 0
