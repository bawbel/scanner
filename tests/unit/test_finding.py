"""
Unit tests for scanner.models.finding.Finding
"""

from scanner.models import SEVERITY_SCORES, Severity
from scanner.models.finding import Finding


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="bawbel-test",
        ave_id=None,
        title="Test Finding",
        description="A test finding.",
        severity=Severity.HIGH,
        aivss_score=7.0,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestFindingFields:

    def test_required_fields_set(self):
        f = make_finding()
        assert f.rule_id == "bawbel-test"
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.aivss_score == 7.0

    def test_default_engine_is_pattern(self):
        f = make_finding()
        assert f.engine == "pattern"

    def test_default_line_is_none(self):
        f = make_finding()
        assert f.line is None

    def test_default_not_suppressed(self):
        f = make_finding()
        assert f.suppressed is False
        assert f.suppression_reason is None

    def test_owasp_default_empty(self):
        f = make_finding()
        assert f.owasp == []

    def test_owasp_mcp_default_empty(self):
        f = make_finding()
        assert f.owasp_mcp == []

    def test_piranha_url_default_none(self):
        f = make_finding()
        assert f.piranha_url is None

    def test_aivss_spec_version_default(self):
        f = make_finding()
        assert f.aivss_spec_version == "0.8"

    def test_custom_fields(self):
        f = make_finding(
            ave_id="AVE-2026-00001",
            line=42,
            match="some matched text",
            engine="yara",
            owasp=["ASI01"],
            owasp_mcp=["MCP01"],
            piranha_url="https://api.piranha.bawbel.io/records/AVE-2026-00001",
        )
        assert f.ave_id == "AVE-2026-00001"
        assert f.line == 42
        assert f.match == "some matched text"
        assert f.engine == "yara"
        assert f.owasp == ["ASI01"]
        assert f.owasp_mcp == ["MCP01"]
        assert f.piranha_url == "https://api.piranha.bawbel.io/records/AVE-2026-00001"


class TestFindingToAivssDict:

    def test_returns_dict(self):
        f = make_finding()
        d = f.to_aivss_dict()
        assert isinstance(d, dict)

    def test_has_aivss_score_key(self):
        f = make_finding(aivss_score=8.5)
        d = f.to_aivss_dict()
        assert "aivss_score" in d
        assert d["aivss_score"] == 8.5

    def test_has_spec_version(self):
        f = make_finding()
        d = f.to_aivss_dict()
        assert d.get("spec_version") == "0.8"

    def test_score_in_valid_range(self):
        for score in [0.0, 5.0, 7.5, 10.0]:
            f = make_finding(aivss_score=score)
            d = f.to_aivss_dict()
            assert 0.0 <= d["aivss_score"] <= 10.0


class TestSeverity:

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_scores_ordered(self):
        assert SEVERITY_SCORES["CRITICAL"] > SEVERITY_SCORES["HIGH"]
        assert SEVERITY_SCORES["HIGH"] > SEVERITY_SCORES["MEDIUM"]
        assert SEVERITY_SCORES["MEDIUM"] > SEVERITY_SCORES["LOW"]
        assert SEVERITY_SCORES["LOW"] > SEVERITY_SCORES["INFO"]

    def test_all_severities_in_scores(self):
        for sev in Severity:
            assert sev.value in SEVERITY_SCORES
