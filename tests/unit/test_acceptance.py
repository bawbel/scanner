"""
Unit tests for scanner.models.acceptance.

Covers:
  - AcceptedFinding construction and validation
  - parse_expiry() — relative and ISO formats
  - days_until_expiry, is_expired, is_expiring_soon
  - to_dict() output shape
"""

from datetime import date, timedelta

import pytest

from scanner.models.acceptance import (
    AcceptedFinding,
    SUPPRESSION_TYPE_FALSE_POSITIVE,
    SUPPRESSION_TYPE_ACCEPTED_RISK,
    parse_expiry,
)


# ── parse_expiry ──────────────────────────────────────────────────────────────


class TestParseExpiry:

    def test_iso_date(self):
        result = parse_expiry("2026-08-08")
        assert result == date(2026, 8, 8)

    def test_days_relative(self):
        result = parse_expiry("90d")
        assert result == date.today() + timedelta(days=90)

    def test_days_relative_with_space(self):
        result = parse_expiry("30 days")
        assert result == date.today() + timedelta(days=30)

    def test_months_relative(self):
        result = parse_expiry("3m")
        assert result == date.today() + timedelta(days=90)

    def test_years_relative(self):
        result = parse_expiry("1y")
        assert result == date.today() + timedelta(days=365)

    def test_invalid_iso_raises(self):
        with pytest.raises((ValueError, TypeError)):
            parse_expiry("not-a-date")


# ── AcceptedFinding construction ──────────────────────────────────────────────


class TestAcceptedFindingConstruction:

    def test_false_positive_minimal(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00002",
            rule_id=None,
            line=27,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_FALSE_POSITIVE,
            reason="Documentation example, not active code",
        )
        assert af.ave_id == "AVE-2026-00002"
        assert af.suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE
        assert af.expires_at is None
        assert af.is_expired is False

    def test_accepted_risk_with_expiry(self):
        future = date.today() + timedelta(days=90)
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=14,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="Legitimate API key read",
            expires_at=future,
        )
        assert af.suppression_type == SUPPRESSION_TYPE_ACCEPTED_RISK
        assert af.is_expired is False
        assert af.days_until_expiry == 90

    def test_invalid_suppression_type_raises(self):
        with pytest.raises(ValueError):
            AcceptedFinding(
                ave_id="AVE-2026-00001",
                rule_id=None,
                line=1,
                file_path="/skill.md",
                suppression_type="invalid-type",
                reason="reason",
            )

    def test_rule_id_instead_of_ave_id(self):
        af = AcceptedFinding(
            ave_id=None,
            rule_id="bawbel-external-fetch",
            line=5,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_FALSE_POSITIVE,
            reason="Internal endpoint",
        )
        assert af.rule_id == "bawbel-external-fetch"
        assert af.ave_id is None


# ── Expiry logic ──────────────────────────────────────────────────────────────


class TestExpiryLogic:

    def test_not_expired_future(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="r",
            expires_at=date.today() + timedelta(days=30),
        )
        assert af.is_expired is False
        assert af.days_until_expiry == 30

    def test_expired_past(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="r",
            expires_at=date.today() - timedelta(days=1),
        )
        assert af.is_expired is True
        assert af.days_until_expiry == -1

    def test_expiring_soon_within_14_days(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="r",
            expires_at=date.today() + timedelta(days=7),
        )
        assert af.is_expiring_soon is True

    def test_not_expiring_soon_far_future(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="r",
            expires_at=date.today() + timedelta(days=90),
        )
        assert af.is_expiring_soon is False

    def test_false_positive_never_expires(self):
        af = AcceptedFinding(
            ave_id="AVE-2026-00002",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_FALSE_POSITIVE,
            reason="r",
        )
        assert af.expires_at is None
        assert af.days_until_expiry is None
        assert af.is_expiring_soon is False
        assert af.is_expired is False


# ── to_dict ───────────────────────────────────────────────────────────────────


class TestAcceptedFindingToDict:

    def test_to_dict_shape(self):
        future = date.today() + timedelta(days=30)
        af = AcceptedFinding(
            ave_id="AVE-2026-00003",
            rule_id=None,
            line=14,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_ACCEPTED_RISK,
            reason="Legitimate API key",
            reviewer="chaksaray",
            reviewed_at=date.today(),
            expires_at=future,
        )
        d = af.to_dict()
        assert d["ave_id"] == "AVE-2026-00003"
        assert d["suppression_type"] == SUPPRESSION_TYPE_ACCEPTED_RISK
        assert d["reason"] == "Legitimate API key"
        assert d["reviewer"] == "chaksaray"
        assert d["days_until_expiry"] == 30
        assert d["is_expired"] is False
        assert d["is_expiring_soon"] is False

    def test_to_dict_is_json_serialisable(self):
        import json

        af = AcceptedFinding(
            ave_id="AVE-2026-00001",
            rule_id=None,
            line=1,
            file_path="/skill.md",
            suppression_type=SUPPRESSION_TYPE_FALSE_POSITIVE,
            reason="test",
        )
        result = json.dumps(af.to_dict())
        assert "AVE-2026-00001" in result
