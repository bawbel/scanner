"""
Bawbel Scanner — Semgrep detection engine (Stage 1c).

Requires semgrep CLI. Skips silently if not installed.
Rules file: scanner/rules/semgrep/ave_rules.yaml

To add new Semgrep rules: edit ave_rules.yaml only.
No Python code changes needed.
"""

import re
from pathlib import Path

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import (
    Timer,
    get_logger,
    parse_cvss,
    parse_json_safe,
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

# Strip "AVE-2026-XXXXX [SEV score] " or "[SEV] " prefix from messages
_MSG_PREFIX = re.compile(
    r"^(?:AVE-\d{4}-\d{5}\s+)?" r"\[(?:CRITICAL|HIGH|MEDIUM|LOW)(?:\s+[\d.]+)?\]\s*",
    re.IGNORECASE,
)


def _clean_title(msg: str) -> str:
    """
    Extract a clean human-readable title from a semgrep message.

    Strips AVE/severity prefix then takes the first sentence.
    Splits on '. ' not '.' to avoid cutting decimal numbers like 8.4.
    """
    stripped = _MSG_PREFIX.sub("", msg).strip()
    parts = stripped.split(". ")
    return parts[0][:MAX_MATCH_LENGTH]


def _match_from_file(file_path: str, line_no: int) -> str:
    """
    Read the actual matched line from the source file.

    semgrep's extra.lines field returns content from the rules YAML itself
    when scanning generic-language files — not the scanned file.
    Reading the source file directly is always correct.
    """
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        if 1 <= line_no <= len(lines):
            return truncate_match(lines[line_no - 1].strip(), MAX_MATCH_LENGTH)
    except OSError:
        pass
    return ""


def run_semgrep_scan(file_path: str) -> list[Finding]:
    """
    Run Semgrep rules against the component file.

    Requires semgrep CLI — skips silently if not installed.
    All rule metadata (severity, ave_id, owasp) is read from ave_rules.yaml.

    Args:
        file_path: Resolved absolute path to the component file

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []

    if not SEMGREP_RULES_PATH.exists():
        log.warning(Logs.RULES_MISSING, "semgrep", SEMGREP_RULES_PATH)
        return findings

    log.debug(Logs.ENGINE_START, "semgrep", file_path)

    with Timer() as t:
        stdout, err = run_subprocess(
            args=[
                "semgrep",
                "--config",
                str(SEMGREP_RULES_PATH),
                "--json",
                "--quiet",
                file_path,
            ],
            timeout=MAX_SCAN_TIMEOUT_SEC,
            label="semgrep",
        )

    if stdout is None:
        return findings

    if err:
        log.warning(Logs.ENGINE_ERROR, "semgrep", file_path, err)
        return findings

    data, parse_err = parse_json_safe(stdout, label="semgrep")
    if parse_err or not data:
        log.warning(Logs.ENGINE_ERROR, "semgrep", file_path, parse_err)
        return findings

    for r in data.get("results", []):
        try:
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            msg = extra.get("message", r.get("check_id", ""))
            sev_raw = extra.get("severity", "WARNING")
            sev_str = _SEV_MAP.get(sev_raw, "MEDIUM")
            line_no = r.get("start", {}).get("line")

            # Read match text from source file — extra.lines is unreliable
            # for generic-language rules (returns rule file content, not skill)
            match_text = _match_from_file(file_path, line_no) if line_no else ""

            findings.append(
                Finding(
                    rule_id=r.get("check_id", "semgrep-unknown"),
                    ave_id=meta.get("ave_id") or None,
                    title=_clean_title(msg),
                    description=msg,
                    severity=Severity(sev_str),
                    cvss_ai=parse_cvss(meta.get("cvss_ai_score", 5.0)),
                    line=line_no,
                    match=match_text,
                    engine="semgrep",
                    owasp=meta.get("owasp_mapping", []),
                )
            )
            log.debug(
                Logs.FINDING_DETECTED,
                r.get("check_id", ""),
                sev_str,
                "semgrep",
                line_no,
            )

        except Exception as e:  # nosec B110  # noqa: S110
            log.warning(
                "Semgrep result parse error: check_id=%s error_type=%s",
                r.get("check_id", "unknown"),
                type(e).__name__,
            )
            continue

    log.debug(Logs.ENGINE_COMPLETE, "semgrep", len(findings), t.elapsed_ms)
    return findings
