"""
Unit tests for scanner.cli.cmd_chain.

Tests the filter functions directly. CLI integration tests
are in test_scanner.py::TestChainCommand.
"""

from scanner.cli.cmd_chain import (
    DELEGATION_AVE_IDS,
    DELEGATION_RULE_IDS,
    _is_delegation_finding,
)
from scanner.cli.cmd_creds import CREDENTIAL_RULE_IDS
from scanner.models.finding import Finding, Severity


def make_finding(rule_id="bawbel-unsafe-delegation", ave_id="AVE-2026-00048"):
    return Finding(
        rule_id=rule_id,
        ave_id=ave_id,
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        aivss_score=8.2,
        engine="pattern",
    )


class TestIsDelegationFinding:

    def test_matches_unsafe_delegation_rule(self):
        assert (
            _is_delegation_finding(
                make_finding(rule_id="bawbel-unsafe-delegation", ave_id="AVE-2026-00048")
            )
            is True
        )

    def test_matches_a2a_injection_rule(self):
        assert (
            _is_delegation_finding(
                make_finding(rule_id="bawbel-a2a-injection", ave_id="AVE-2026-00009")
            )
            is True
        )

    def test_matches_subagent_exfil_rule(self):
        assert (
            _is_delegation_finding(
                make_finding(rule_id="bawbel-subagent-exfil", ave_id="AVE-2026-00012")
            )
            is True
        )

    def test_matches_by_ave_id_00048(self):
        assert (
            _is_delegation_finding(make_finding(rule_id="other-rule", ave_id="AVE-2026-00048"))
            is True
        )

    def test_matches_by_ave_id_00009(self):
        assert (
            _is_delegation_finding(make_finding(rule_id="other-rule", ave_id="AVE-2026-00009"))
            is True
        )

    def test_matches_by_ave_id_00012(self):
        assert (
            _is_delegation_finding(make_finding(rule_id="other-rule", ave_id="AVE-2026-00012"))
            is True
        )

    def test_does_not_match_unrelated_rule(self):
        assert (
            _is_delegation_finding(
                make_finding(rule_id="bawbel-goal-override", ave_id="AVE-2026-00007")
            )
            is False
        )

    def test_does_not_match_credential_rule(self):
        assert (
            _is_delegation_finding(
                make_finding(rule_id="bawbel-hardcoded-credential", ave_id="AVE-2026-00047")
            )
            is False
        )

    def test_does_not_match_none_ave_id(self):
        assert (
            _is_delegation_finding(make_finding(rule_id="bawbel-goal-override", ave_id=None))
            is False
        )

    def test_all_delegation_rule_ids_match(self):
        for rule_id in DELEGATION_RULE_IDS:
            f = make_finding(rule_id=rule_id, ave_id=None)
            assert _is_delegation_finding(f) is True, f"Expected match for {rule_id}"

    def test_all_delegation_ave_ids_match(self):
        for ave_id in DELEGATION_AVE_IDS:
            f = make_finding(rule_id="other-rule", ave_id=ave_id)
            assert _is_delegation_finding(f) is True, f"Expected match for {ave_id}"

    def test_no_overlap_with_credential_rules(self):
        overlap = CREDENTIAL_RULE_IDS & DELEGATION_RULE_IDS
        assert (
            overlap == frozenset()
        ), f"Unexpected overlap between creds and chain rules: {overlap}"
