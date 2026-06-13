from scanner.core.scoring import calc_aivss, severity_from_aivss
from scanner.models import Severity

_DEFAULT_AARF = {
    "autonomy": 0.5,
    "tool_use": 0.5,
    "multi_agent": 0.0,
    "non_determinism": 0.5,
    "self_modification": 0.0,
    "dynamic_identity": 0.0,
    "persistent_memory": 0.0,
    "natural_language_input": 1.0,
    "data_access": 0.5,
    "external_dependencies": 0.0,
}


def test_calc_aivss_returns_float():
    result = calc_aivss(7.0, _DEFAULT_AARF, 0.75, 1.0)
    assert isinstance(result, float)


def test_calc_aivss_clamps_result_to_0_to_10():
    result = calc_aivss(10.0, {k: 1.0 for k in _DEFAULT_AARF}, 1.0, 1.0)
    assert 0.0 <= result <= 10.0


def test_calc_aivss_returns_zero_for_zero_inputs():
    result = calc_aivss(0.0, {k: 0.0 for k in _DEFAULT_AARF}, 0.0, 1.0)
    assert result == 0.0


def test_calc_aivss_higher_cvss_base_yields_higher_score():
    low = calc_aivss(3.0, _DEFAULT_AARF, 0.75, 1.0)
    high = calc_aivss(9.0, _DEFAULT_AARF, 0.75, 1.0)
    assert high > low


def test_severity_from_aivss_critical_at_9_and_above():
    assert severity_from_aivss(9.0) == Severity.CRITICAL
    assert severity_from_aivss(10.0) == Severity.CRITICAL


def test_severity_from_aivss_high_between_7_and_9():
    assert severity_from_aivss(7.0) == Severity.HIGH
    assert severity_from_aivss(8.9) == Severity.HIGH


def test_severity_from_aivss_medium_between_4_and_7():
    assert severity_from_aivss(4.0) == Severity.MEDIUM
    assert severity_from_aivss(6.9) == Severity.MEDIUM


def test_severity_from_aivss_low_for_positive_below_4():
    assert severity_from_aivss(0.1) == Severity.LOW
    assert severity_from_aivss(3.9) == Severity.LOW


def test_severity_from_aivss_info_for_zero():
    assert severity_from_aivss(0.0) == Severity.INFO
