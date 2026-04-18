"""
Bawbel Scanner — Semgrep detection engine (Stage 1c).

Requires semgrep CLI. Skips silently if not installed.
Rules file: scanner/rules/semgrep/ave_rules.yaml

To add new Semgrep rules: edit ave_rules.yaml only.
No Python code changes needed.
"""

from pathlib import Path

from scanner.messages import Errors, Logs  # noqa: F401
from scanner.models import Finding, Severity
from scanner.utils import (  # noqa: F401
    Timer,
    get_logger,
    parse_cvss,
    parse_json_safe,
    parse_severity,
    run_subprocess,
    truncate_match,
)

log = get_logger(__name__)

SEMGREP_RULES_PATH = Path(__file__).parent.parent / "rules" / "semgrep" / "ave_rules.yaml"
MAX_SCAN_TIMEOUT_SEC = 30
MAX_MATCH_LENGTH = 80

# Semgrep severity → AVE severity
_SEV_MAP: dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def run_semgrep_scan(file_path: str) -> list[Finding]:
    """
    Run Semgrep rules against the component file.

    Requires semgrep CLI — skips silently if not installed.
    All rule metadata is read from the YAML rules file.

    Args:
        file_path: Resolved absolute path to the component file

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []

    # ── Check rules file ──────────────────────────────────────────────────────
    if not SEMGREP_RULES_PATH.exists():
        log.warning(Logs.RULES_MISSING, "semgrep", SEMGREP_RULES_PATH)
        return findings

    # ── Run semgrep via safe subprocess ───────────────────────────────────────
    log.debug(Logs.ENGINE_START, "semgrep", file_path)

    with Timer() as t:
        stdout, err = run_subprocess(
            args=["semgrep", "--config", str(SEMGREP_RULES_PATH), "--json", "--quiet", file_path],
            timeout=MAX_SCAN_TIMEOUT_SEC,
            label="semgrep",
        )

    if stdout is None:
        # Tool not installed — already logged in run_subprocess
        return findings

    if err:
        log.warning(Logs.ENGINE_ERROR, "semgrep", file_path, err)
        return findings

    # ── Parse output ──────────────────────────────────────────────────────────
    data, parse_err = parse_json_safe(stdout, label="semgrep")
    if parse_err or not data:
        log.warning(Logs.ENGINE_ERROR, "semgrep", file_path, parse_err)
        return findings

    # ── Map results to Findings ───────────────────────────────────────────────
    for r in data.get("results", []):
        try:
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            msg = extra.get("message", r.get("check_id", ""))
            sev_raw = extra.get("severity", "WARNING")
            sev_str = _SEV_MAP.get(sev_raw, "MEDIUM")

            findings.append(
                Finding(
                    rule_id=r.get("check_id", "semgrep-unknown"),
                    ave_id=meta.get("ave_id") or None,
                    title=msg.split(".")[0][:MAX_MATCH_LENGTH],
                    description=msg,
                    severity=Severity(sev_str),
                    cvss_ai=parse_cvss(meta.get("cvss_ai_score", 5.0)),
                    line=r.get("start", {}).get("line"),
                    match=truncate_match(extra.get("lines", ""), MAX_MATCH_LENGTH),
                    engine="semgrep",
                    owasp=meta.get("owasp_mapping", []),
                )
            )
            log.debug(
                Logs.FINDING_DETECTED,
                r.get("check_id", ""),
                sev_str,
                "semgrep",
                r.get("start", {}).get("line"),
            )

        except Exception as e:  # nosec B110 — bad result, skip and continue
            log.warning(
                "Semgrep result parse error: check_id=%s error_type=%s",
                r.get("check_id", "unknown"),
                type(e).__name__,
            )
            continue

    log.debug(Logs.ENGINE_COMPLETE, "semgrep", len(findings), t.elapsed_ms)
    return findings
