"""
Bawbel Scanner - recommendation.

One value that says what a scan recommends, for a caller that builds a gate. It is computed
from the lists the exit code and the risk score already use (`findings` and `toxic_flows`), so
a suppressed or accepted finding changes it exactly as it changes them.

    ALLOW   no findings and no toxic flows
    REVIEW  findings or toxic flows present, none blocking
    BLOCK   a finding at or above the --fail-on-severity threshold, or a CRITICAL toxic flow
    None    the scan failed, or the command did not compute one

"Blocking" is the test `bawbel scan --fail-on-severity` already applies for exit code 2. With no
threshold, no finding is blocking. The exit code is not derived from this value and is not
changed by it: it collapses ALLOW and REVIEW to 0, and a CRITICAL toxic flow alone makes the
recommendation BLOCK while the exit code stays 0. A caller that wants the distinction reads
`recommendation` from the JSON output.

ALLOW says nothing about what no engine looked at, and it does not consider whether an engine
did not run (`engines_degraded` and `--require-engines` carry that).

Pure function, no I/O, never raises.
"""

from __future__ import annotations

from typing import Iterable, Optional

from scanner.models.severity import SEVERITY_SCORES

ALLOW = "ALLOW"
REVIEW = "REVIEW"
BLOCK = "BLOCK"

# Weakest to strongest. The position is the rank used to find the worst of several.
RECOMMENDATIONS = (ALLOW, REVIEW, BLOCK)

_CRITICAL = "CRITICAL"


def _value(severity) -> str:
    """The string form of a Severity (an enum) or of a plain string."""
    return str(getattr(severity, "value", severity)).upper()


def recommend(result, fail_on_severity: Optional[str] = None) -> Optional[str]:
    """
    What this scan result recommends.

    What: ALLOW, REVIEW or BLOCK for one ScanResult, or None if the scan failed.
    Why:  `--fail-on-severity` is a knob. A gate needs one value and a stated contract.
    How:  BLOCK if a finding scores at or above the threshold (the exit code 2 test) or a toxic
          flow is CRITICAL. Otherwise REVIEW if anything is present, else ALLOW.

    Args:
        result: a ScanResult (anything with .error, .findings and .toxic_flows).
        fail_on_severity: "critical" | "high" | "medium" | "low", any case, or None. An
            unrecognised value is treated as no threshold.
    """
    if result.error is not None:
        return None

    threshold = SEVERITY_SCORES.get(str(fail_on_severity).upper()) if fail_on_severity else None
    if threshold is not None:
        worst = max(
            (SEVERITY_SCORES.get(_value(f.severity), 0) for f in result.findings), default=0
        )
        if result.findings and worst >= threshold:
            return BLOCK
    if any(_value(getattr(tf, "severity", "")) == _CRITICAL for tf in result.toxic_flows):
        return BLOCK
    if result.findings or result.toxic_flows:
        return REVIEW
    return ALLOW


def worst_recommendation(recommendations: Iterable[Optional[str]]) -> Optional[str]:
    """
    The strongest of several recommendations, for a run that scanned several files.

    None if there are none, or if any one is None: a file whose scan failed has no
    recommendation, and the run must not read as ALLOW because the others were.
    """
    items = list(recommendations)
    if not items or any(item not in RECOMMENDATIONS for item in items):
        return None
    return max(items, key=RECOMMENDATIONS.index)
