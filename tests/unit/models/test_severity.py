"""
Unit tests for scanner.models.severity — structural placement tests.

Verify that Severity, SEVERITY_SCORES, calc_aivss, severity_from_aivss,
and DEFAULT_AARF are importable from scanner.models.severity as their
canonical module path.
"""

from scanner.models.severity import (
    DEFAULT_AARF,
    SEVERITY_SCORES,
    Severity,
    calc_aivss,
    severity_from_aivss,
)


def test_severity_importable_from_severity_module():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"


def test_severity_scores_importable_from_severity_module():
    assert SEVERITY_SCORES["CRITICAL"] > SEVERITY_SCORES["HIGH"]
    assert SEVERITY_SCORES["HIGH"] > SEVERITY_SCORES["MEDIUM"]


def test_calc_aivss_importable_from_severity_module():
    score = calc_aivss(cvss_base=8.0, aarf=DEFAULT_AARF)
    assert 0.0 <= score <= 10.0


def test_severity_from_aivss_importable_from_severity_module():
    assert severity_from_aivss(9.5) == Severity.CRITICAL
    assert severity_from_aivss(7.0) == Severity.HIGH


def test_default_aarf_importable_from_severity_module():
    assert "autonomy" in DEFAULT_AARF
    assert len(DEFAULT_AARF) == 10
