"""
Bawbel Scanner - Justified suppression parser and enforcer.

Handles:
  J1: bawbel-accept and extended bawbel-ignore inline comment parsing
  J4: accepted_findings population in ScanResult
  J5: Expiry enforcement - re-surfaces expired accepted_risk findings
  J6: CI warning hook for expiring acceptances

Inline syntax supported:

  Simple false positive (no metadata required):
    content  <!-- bawbel-ignore: AVE-2026-00002
                  reason: Documentation example
                  reviewer: chaksaray reviewed: 2026-05-08 -->

  Multi-line false positive:
    <!-- bawbel-ignore: AVE-2026-00002
         reason: Documentation showing a bad example, not active code
         reviewer: chaksaray
         reviewed: 2026-05-08
    -->

  Accepted risk with expiry:
    <!-- bawbel-accept: AVE-2026-00003
         reason: Legitimately reads ANTHROPIC_API_KEY for authorized calls
         reviewer: chaksaray
         reviewed: 2026-05-08
         expires: 2026-08-08
    -->

The key distinction:
  bawbel-ignore  = false positive (not dangerous, suppress permanently)
  bawbel-accept  = accepted risk  (real but intentional, may expire)

Both forms support the full metadata block. The keyword determines suppression_type.
"""

from __future__ import annotations

import re
from datetime import date

from scanner.models.acceptance import AcceptedFinding, parse_expiry
from scanner.models.acceptance import (
    SUPPRESSION_TYPE_FALSE_POSITIVE,
    SUPPRESSION_TYPE_ACCEPTED_RISK,
)
from scanner.models.finding import Finding
from scanner.utils import get_logger

log = get_logger(__name__)

# ── Pattern for multi-line acceptance blocks ──────────────────────────────────
# Matches <!-- bawbel-ignore: ... --> or <!-- bawbel-accept: ... --> blocks
# spanning one or more lines. Also matches single-line variants.

_ACCEPT_BLOCK_RE = re.compile(
    r"(?:<!--|#|//)\s*(bawbel-accept|bawbel-ignore):\s*([\w\-]+)(.*?)(?:-->|$)",
    re.DOTALL | re.IGNORECASE,
)

# Field extraction patterns (applied to the metadata block)
_REASON_RE = re.compile(r"reason\s*:\s*(.+?)(?=reviewer:|reviewed:|expires:|$)", re.DOTALL | re.I)
_REVIEWER_RE = re.compile(r"reviewer\s*:\s*(\S+)", re.I)
_REVIEWED_RE = re.compile(r"reviewed\s*:\s*(\S+)", re.I)
_EXPIRES_RE = re.compile(r"expires\s*:\s*(\S+)", re.I)
_REPORT_RE = re.compile(r"report", re.I)


def _extract_metadata(block: str) -> dict:
    """Extract metadata fields from a bawbel-accept / bawbel-ignore metadata block."""
    meta: dict = {}

    m = _REASON_RE.search(block)
    if m:
        meta["reason"] = " ".join(m.group(1).strip().split())  # normalise whitespace

    m = _REVIEWER_RE.search(block)
    if m:
        meta["reviewer"] = m.group(1).strip()

    m = _REVIEWED_RE.search(block)
    if m:
        try:
            meta["reviewed_at"] = date.fromisoformat(m.group(1).strip())
        except ValueError:
            log.debug("Could not parse reviewed date: %s", m.group(1))

    m = _EXPIRES_RE.search(block)
    if m:
        try:
            meta["expires_at"] = parse_expiry(m.group(1).strip())
        except (ValueError, TypeError):
            log.debug("Could not parse expires value: %s", m.group(1))

    meta["report_to_piranha"] = bool(_REPORT_RE.search(block))

    return meta


def parse_accepted_findings(
    content: str,
    file_path: str,
) -> list[AcceptedFinding]:
    """
    Parse all bawbel-accept and extended bawbel-ignore comments from file content.

    Returns a list of AcceptedFinding objects. Empty list if none found.
    """
    results: list[AcceptedFinding] = []
    lines = content.splitlines()

    # Build a line-indexed string so we can find line numbers
    # We scan line by line, assembling multi-line blocks when we see <!--
    i = 0
    while i < len(lines):
        line = lines[i]

        # Quick check - does this line start an acceptance comment?
        stripped = line.strip().lower()
        is_accept = "bawbel-accept:" in stripped
        is_ignore_with_meta = "bawbel-ignore:" in stripped and (
            "reason:" in stripped or (i + 1 < len(lines) and "reason:" in lines[i + 1].lower())
        )

        if not (is_accept or is_ignore_with_meta):
            i += 1
            continue

        # Collect all lines until --> or non-comment line
        block_lines = [line]
        j = i + 1
        while j < len(lines):
            next_line = lines[j]
            block_lines.append(next_line)
            if "-->" in next_line or (
                next_line.strip()
                and not next_line.strip().startswith(("#", "//", "*", "<!--"))
                and "reason:" not in next_line.lower()
                and "reviewer:" not in next_line.lower()
                and "reviewed:" not in next_line.lower()
                and "expires:" not in next_line.lower()
            ):
                break
            j += 1

        block = "\n".join(block_lines)

        for m in _ACCEPT_BLOCK_RE.finditer(block):
            keyword = m.group(1).lower()  # bawbel-accept | bawbel-ignore
            id_str = m.group(2).strip()  # AVE-2026-NNNNN or rule-id
            metadata = m.group(3)

            suppression_type = (
                SUPPRESSION_TYPE_ACCEPTED_RISK
                if keyword == "bawbel-accept"
                else SUPPRESSION_TYPE_FALSE_POSITIVE
            )

            meta = _extract_metadata(metadata)
            reason = meta.get("reason", "")

            # Only create a justified suppression if reason is present
            if not reason:
                log.debug(
                    "Skipping justified suppression without reason: id=%s line=%d",
                    id_str,
                    i + 1,
                )
                i = j
                continue

            ave_id = id_str if id_str.startswith("AVE-") else None
            rule_id = id_str if not id_str.startswith("AVE-") else None

            try:
                af = AcceptedFinding(
                    ave_id=ave_id,
                    rule_id=rule_id,
                    line=i + 1,  # 1-indexed line of the comment
                    file_path=file_path,
                    suppression_type=suppression_type,
                    reason=reason,
                    reviewer=meta.get("reviewer"),
                    reviewed_at=meta.get("reviewed_at"),
                    expires_at=meta.get("expires_at"),
                    report_to_piranha=meta.get("report_to_piranha", False),
                )
                results.append(af)
                log.debug(
                    "Parsed accepted finding: type=%s id=%s line=%d",
                    suppression_type,
                    id_str,
                    i + 1,
                )
            except ValueError as e:
                log.warning("Could not create AcceptedFinding: %s", type(e).__name__)

        i = j

    return results


def apply_justified_suppressions(
    findings: list[Finding],
    accepted_list: list[AcceptedFinding],
    file_path: str,
) -> tuple[list[Finding], list[Finding], list[AcceptedFinding]]:
    """
    Apply justified suppressions (bawbel-accept / extended bawbel-ignore) to findings.

    Handles J5: expired accepted risks are NOT suppressed - they resurface as active.

    Returns:
        (active_findings, suppressed_findings, updated_accepted_list)

    Updated accepted_list has is_expired set correctly for use in JSON output.
    """
    if not accepted_list:
        return list(findings), [], accepted_list

    active: list[Finding] = []
    suppressed: list[Finding] = []

    # Build lookup: (ave_id or rule_id) -> AcceptedFinding
    af_by_ave: dict[str, AcceptedFinding] = {}
    af_by_rule: dict[str, AcceptedFinding] = {}
    for af in accepted_list:
        if af.ave_id:
            af_by_ave[af.ave_id] = af
        if af.rule_id:
            af_by_rule[af.rule_id] = af

    for f in findings:
        af = af_by_ave.get(f.ave_id or "") or af_by_rule.get(f.rule_id)

        if af is None:
            active.append(f)
            continue

        # J5: expired accepted risks resurface
        if af.is_expired:
            log.warning(
                "Accepted risk expired - finding resurfaced: id=%s expired=%s",
                af.ave_id or af.rule_id,
                str(af.expires_at),
            )
            f.suppression_reason = (
                f"accepted_risk_expired (was accepted by {af.reviewer or 'unknown'} "
                f"on {af.reviewed_at}, expired {af.expires_at})"
            )
            active.append(f)
            continue

        # Still valid - suppress
        f.suppressed = True
        type_label = (
            "false_positive"
            if af.suppression_type == SUPPRESSION_TYPE_FALSE_POSITIVE
            else "accepted_risk"
        )
        reviewer = af.reviewer or "unknown"
        f.suppression_reason = f"{type_label} ({reviewer}: {af.reason[:60]})"
        suppressed.append(f)

    return active, suppressed, accepted_list


def check_expiring_soon(
    accepted_list: list[AcceptedFinding],
    warn_within: int = 14,
) -> list[AcceptedFinding]:
    """
    J6: Return accepted findings that expire within warn_within days.

    Used by `bawbel accept --expiring-soon` and the CI exit-code-1 check.
    """
    return [
        af
        for af in accepted_list
        if af.suppression_type == SUPPRESSION_TYPE_ACCEPTED_RISK
        and af.days_until_expiry is not None
        and 0 <= af.days_until_expiry <= warn_within
    ]


def send_fp_signal(af: AcceptedFinding, engine: str, confidence: float, match_hash: str) -> bool:
    """
    J8: Send anonymous false positive signal to PiranhaDB.

    Sends only: AVE ID, engine, confidence score, hash of match context.
    Never sends file content, file path, or match text.

    Returns True if signal sent successfully, False otherwise.
    Skips silently if report_to_piranha is False.
    """
    if not af.report_to_piranha:
        return False

    import urllib.request
    import json
    import os

    piranha_url = os.environ.get(
        "BAWBEL_PIRANHA_URL",
        "https://api.piranha.bawbel.io",
    )
    endpoint = f"{piranha_url}/feedback/false-positive"

    payload = {
        "ave_id": af.ave_id,
        "rule_id": af.rule_id,
        "engine": engine,
        "confidence": round(confidence, 3),
        "match_hash": match_hash,  # SHA-256 of match context, no content
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "bawbel-scanner/1.2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310  # noqa: S310
            status = resp.status
            log.debug("FP signal sent: ave_id=%s status=%d", af.ave_id, status)
            return status == 200
    except Exception as e:  # nosec B110
        log.debug("FP signal failed: type=%s", type(e).__name__)
        return False
