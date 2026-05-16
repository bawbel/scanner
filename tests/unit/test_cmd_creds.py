"""
Unit tests for scanner.cli.cmd_creds.

Tests the filter functions directly. CLI integration tests
are in test_scanner.py::TestCredsCommand.
"""

from scanner.cli.cmd_creds import (
    CREDENTIAL_AVE_IDS,
    CREDENTIAL_RULE_IDS,
    _is_cred_finding,
)
from scanner.models.finding import Finding, Severity


def make_finding(rule_id="bawbel-hardcoded-credential", ave_id="AVE-2026-00047"):
    return Finding(
        rule_id=rule_id,
        ave_id=ave_id,
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        aivss_score=7.8,
        engine="pattern",
    )


class TestIsCredFinding:

    def test_matches_hardcoded_credential_rule(self):
        assert (
            _is_cred_finding(
                make_finding(rule_id="bawbel-hardcoded-credential", ave_id="AVE-2026-00047")
            )
            is True
        )

    def test_does_not_match_external_fetch(self):
        assert (
            _is_cred_finding(make_finding(rule_id="bawbel-external-fetch", ave_id="AVE-2026-00001"))
            is False
        )

    def test_matches_by_ave_id_00047(self):
        assert _is_cred_finding(make_finding(rule_id="other-rule", ave_id="AVE-2026-00047")) is True

    def test_does_not_match_ave_id_00001(self):
        assert (
            _is_cred_finding(make_finding(rule_id="other-rule", ave_id="AVE-2026-00001")) is False
        )

    def test_does_not_match_unrelated_rule(self):
        assert (
            _is_cred_finding(make_finding(rule_id="bawbel-goal-override", ave_id="AVE-2026-00007"))
            is False
        )

    def test_does_not_match_none_ave_id(self):
        assert _is_cred_finding(make_finding(rule_id="bawbel-goal-override", ave_id=None)) is False

    def test_all_credential_rule_ids_match(self):
        for rule_id in CREDENTIAL_RULE_IDS:
            f = make_finding(rule_id=rule_id, ave_id=None)
            assert _is_cred_finding(f) is True, f"Expected match for {rule_id}"

    def test_all_credential_ave_ids_match(self):
        for ave_id in CREDENTIAL_AVE_IDS:
            f = make_finding(rule_id="other-rule", ave_id=ave_id)
            assert _is_cred_finding(f) is True, f"Expected match for {ave_id}"

    def test_delegation_rule_does_not_match(self):
        assert (
            _is_cred_finding(
                make_finding(rule_id="bawbel-unsafe-delegation", ave_id="AVE-2026-00048")
            )
            is False
        )
