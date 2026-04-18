"""
Bawbel Scanner — YARA detection engine (Stage 1b).

Requires yara-python. Skips silently if not installed.
Rules file: scanner/rules/yara/ave_rules.yar

To add new YARA rules: edit ave_rules.yar only.
No Python code changes needed.
"""

from pathlib import Path
from typing import Optional

from scanner.messages import Errors, Logs  # noqa: F401
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger, parse_cvss, parse_severity, truncate_match

log = get_logger(__name__)

YARA_RULES_PATH = Path(__file__).parent.parent / "rules" / "yara" / "ave_rules.yar"
MAX_MATCH_LENGTH = 80


def run_yara_scan(file_path: str) -> list[Finding]:
    """
    Run YARA rules against the component file.

    Requires yara-python — skips silently if not installed.
    All rule metadata (severity, ave_id, owasp) is read from the
    YARA meta: block — no Python code changes needed to add rules.

    Args:
        file_path: Resolved absolute path to the component file

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []

    # ── Check optional dependency ─────────────────────────────────────────────
    try:
        import yara  # optional
    except ImportError:
        log.info(Logs.ENGINE_UNAVAILABLE, "yara")
        return findings

    # ── Check rules file ──────────────────────────────────────────────────────
    if not YARA_RULES_PATH.exists():
        log.warning(Logs.RULES_MISSING, "yara", YARA_RULES_PATH)
        return findings

    # ── Compile and scan ──────────────────────────────────────────────────────
    log.debug(Logs.ENGINE_START, "yara", file_path)

    with Timer() as t:
        try:
            rules = yara.compile(str(YARA_RULES_PATH))
            matches = rules.match(file_path)

        except yara.SyntaxError as e:
            # Log type only — rule text may reveal detection IP
            log.error(Logs.ENGINE_ERROR, "yara", file_path, type(e).__name__)
            log.debug("YARA syntax error detail: %s", e)
            return findings

        except Exception as e:  # nosec B110 — optional engine, broad catch intentional
            log.error(Logs.ENGINE_ERROR, "yara", file_path, type(e).__name__)
            return findings

    # ── Map matches to Findings ───────────────────────────────────────────────
    for match in matches:
        meta = match.meta or {}
        severity_str = parse_severity(meta.get("severity", "HIGH"))

        # Build match snippet safely — YARA strings may be binary
        match_text: Optional[str] = None
        if match.strings:
            try:
                first_string = match.strings[0]
                raw = getattr(first_string, "instances", [])
                match_text = str(raw[0])[:MAX_MATCH_LENGTH] if raw else None
            except Exception:  # nosec B110
                match_text = None

        findings.append(
            Finding(
                rule_id=match.rule,
                ave_id=meta.get("ave_id") or None,
                title=meta.get("description", match.rule)[:MAX_MATCH_LENGTH],
                description=meta.get("description", "YARA rule matched"),
                severity=Severity(severity_str),
                cvss_ai=parse_cvss(meta.get("cvss_ai", 7.0)),
                line=None,
                match=truncate_match(match_text, MAX_MATCH_LENGTH),
                engine="yara",
                owasp=[s.strip() for s in meta.get("owasp", "").split(",") if s.strip()],
            )
        )
        log.debug(
            Logs.FINDING_DETECTED,
            match.rule,
            severity_str,
            "yara",
            None,
        )

    log.debug(Logs.ENGINE_COMPLETE, "yara", len(findings), t.elapsed_ms)
    return findings
