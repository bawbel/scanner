"""
Bawbel Scanner - Acceptance dataclass models.

AcceptedFinding represents a justified suppression record - either a
false_positive declaration or an accepted_risk with an optional expiry.

These are separate from Finding.suppressed because:
  - They have explicit human metadata (reviewer, reason, reviewed date)
  - Accepted risks have expiry dates that resurface the finding
  - They feed anonymous FP signals to PiranhaDB
  - They must appear in their own accepted_findings array in JSON output
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Optional

SUPPRESSION_TYPE_FALSE_POSITIVE = "false_positive"
SUPPRESSION_TYPE_ACCEPTED_RISK = "accepted_risk"

VALID_SUPPRESSION_TYPES = frozenset(
    {
        SUPPRESSION_TYPE_FALSE_POSITIVE,
        SUPPRESSION_TYPE_ACCEPTED_RISK,
    }
)


@dataclass
class AcceptedFinding:
    """
    A justified suppression record for one finding on one line.

    Created from either:
      a) Parsing inline bawbel-accept / bawbel-ignore-with-metadata comments
      b) The `bawbel accept` CLI command which writes the comment to disk

    The canonical storage is the comment in the source file.
    .bawbel-accepted.json is a generated cache, not the source of truth.
    """

    # -- Which finding is accepted -------------------------------------------
    ave_id: Optional[str]  # AVE ID, or None
    rule_id: Optional[str]  # rule_id if no AVE ID
    line: Optional[int]  # 1-indexed line number, or None = whole file
    file_path: str  # resolved absolute path

    # -- Acceptance metadata (required) --------------------------------------
    suppression_type: str  # "false_positive" | "accepted_risk"
    reason: str  # human-readable justification

    # -- Audit metadata (optional) -------------------------------------------
    reviewer: Optional[str] = None  # GitHub handle or name
    reviewed_at: Optional[date] = None  # date reviewed

    # -- Expiry (accepted_risk only) -----------------------------------------
    expires_at: Optional[date] = None  # None = never expires

    # -- FP reporting ---------------------------------------------------------
    report_to_piranha: bool = False  # if True, send anonymous FP signal

    # -- Runtime (set during scan, not stored) --------------------------------
    is_expired: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.suppression_type not in VALID_SUPPRESSION_TYPES:
            raise ValueError(
                f"Invalid suppression_type: {self.suppression_type!r}. "
                f"Must be one of: {sorted(VALID_SUPPRESSION_TYPES)}"
            )
        # Compute is_expired at creation time
        if self.expires_at is not None and self.suppression_type == SUPPRESSION_TYPE_ACCEPTED_RISK:
            self.is_expired = date.today() > self.expires_at

    @property
    def days_until_expiry(self) -> Optional[int]:
        """
        Days until this accepted risk expires.
        Returns None if no expiry is set.
        Returns 0 if today is the expiry date.
        Returns negative if already expired.
        """
        if self.expires_at is None:
            return None
        return (self.expires_at - date.today()).days

    @property
    def is_expiring_soon(self) -> bool:
        """True if expires within 14 days (configurable via WARN_EXPIRY_WITHIN)."""
        d = self.days_until_expiry
        if d is None:
            return False
        return 0 <= d <= 14

    def to_dict(self) -> dict:
        """Serialise to JSON-compatible dict for accepted_findings in ScanResult."""
        return {
            "ave_id": self.ave_id,
            "rule_id": self.rule_id,
            "line": self.line,
            "file_path": self.file_path,
            "suppression_type": self.suppression_type,
            "reason": self.reason,
            "reviewer": self.reviewer,
            "reviewed_at": str(self.reviewed_at) if self.reviewed_at else None,
            "expires_at": str(self.expires_at) if self.expires_at else None,
            "days_until_expiry": self.days_until_expiry,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon,
        }


def parse_expiry(value: str) -> date:
    """
    Parse an expiry string into a date.

    Accepts:
      - ISO date:    "2026-08-08"
      - Relative:    "90d" / "90 days" / "3m" / "3 months" / "1y"

    Returns:
        date object
    """
    v = value.strip().lower()

    # Relative: Nd, N days, Nm, N months, Ny
    if v.endswith("d") or "day" in v:
        n = int("".join(c for c in v if c.isdigit()))
        return date.today() + timedelta(days=n)
    if v.endswith("m") or "month" in v:
        n = int("".join(c for c in v if c.isdigit()))
        return date.today() + timedelta(days=n * 30)
    if v.endswith("y") or "year" in v:
        n = int("".join(c for c in v if c.isdigit()))
        return date.today() + timedelta(days=n * 365)

    # ISO date
    return date.fromisoformat(v)
