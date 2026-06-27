"""
Bawbel Scanner - YARA detection engine (Stage 1b).

Requires yara-python. Skips silently if not installed.
Rules file: scanner/rules/yara/ave_rules.yar

To add new YARA rules: edit ave_rules.yar only.
No Python code changes needed.
"""

import contextlib
import os
import tempfile
from pathlib import Path
from typing import Optional

from scanner.ave_meta import get_ave_meta
from scanner.messages import Errors, Logs  # noqa: F401
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger, parse_cvss, parse_severity, truncate_match

log = get_logger(__name__)

YARA_RULES_PATH = Path(__file__).parent.parent / "rules" / "yara" / "ave_rules.yar"
MAX_MATCH_LENGTH = 80


def run_yara_scan(
    file_path: str,
    stripped_content: Optional[str] = None,
) -> list[Finding]:
    """
    Run YARA rules against the component file.

    Requires yara-python - skips silently if not installed.
    All rule metadata (severity, ave_id, owasp) is read from the
    YARA meta: block - no Python code changes needed to add rules.

    Args:
        file_path:        Resolved absolute path to the component file.
        stripped_content: Pre-processed content with code fences blanked.
                          When provided, YARA scans this content instead
                          of the raw file, reducing FP from doc examples.
                          Line numbers still map to the original file
                          because blanked lines preserve line count.

    Returns:
        List of Findings, may be empty
    """
    findings: list[Finding] = []

    try:
        import yara  # optional
    except ImportError:
        log.info(Logs.ENGINE_UNAVAILABLE, "yara")
        return findings

    if not YARA_RULES_PATH.exists():
        log.warning(Logs.RULES_MISSING, "yara", YARA_RULES_PATH)
        return findings

    log.debug(Logs.ENGINE_START, "yara", file_path)

    # If stripped_content provided, write to a temp file so YARA scans
    # de-fenced content while line numbers stay accurate
    tmp_path = None
    scan_target = file_path

    if stripped_content is not None:
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".md", prefix="bawbel_yara_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(stripped_content)
            scan_target = tmp_path
        except OSError as e:
            log.warning("YARA: could not write temp file, scanning original - %s", e)
            tmp_path = None
            scan_target = file_path

    with Timer() as t:
        try:
            rules = yara.compile(str(YARA_RULES_PATH))

            # Use data= to avoid YARA treating special characters in the path
            # (e.g. [ ] * ?) as glob wildcards
            path_obj = Path(scan_target)
            file_data = path_obj.read_bytes()
            matches = rules.match(data=file_data)

        except yara.SyntaxError as e:
            log.error(Logs.ENGINE_ERROR, "yara", file_path, type(e).__name__)
            log.debug("YARA syntax error detail: %s", e)
            if tmp_path:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
            return findings

        except Exception as e:  # nosec B110
            log.error(Logs.ENGINE_ERROR, "yara", file_path, type(e).__name__)
            if tmp_path:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
            return findings

    if tmp_path:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)

    for match in matches:
        meta = match.meta or {}
        severity_str = parse_severity(meta.get("severity", "HIGH"))

        match_text: Optional[str] = None
        if match.strings:
            try:
                first_string = match.strings[0]
                raw = getattr(first_string, "instances", [])
                match_text = str(raw[0])[:MAX_MATCH_LENGTH] if raw else None
            except Exception:  # nosec B110
                match_text = None

        ave_id = meta.get("ave_id") or None
        piranha_url = f"https://api.piranha.bawbel.io/records/{ave_id}" if ave_id else None
        ave_meta = get_ave_meta(ave_id, "yara")

        findings.append(
            Finding(
                rule_id=match.rule,
                ave_id=ave_id,
                title=meta.get("description", match.rule)[:MAX_MATCH_LENGTH],
                description=meta.get("description", "YARA rule matched"),
                severity=Severity(severity_str),
                aivss_score=parse_cvss(meta.get("aivss", 7.0)),
                line=None,
                match=truncate_match(match_text, MAX_MATCH_LENGTH),
                engine="yara",
                owasp=[s.strip() for s in meta.get("owasp", "").split(",") if s.strip()],
                owasp_mcp=[s.strip() for s in meta.get("owasp_mcp", "").split(",") if s.strip()],
                piranha_url=piranha_url,
                confidence=ave_meta.confidence_baseline,
                evidence_kind=ave_meta.evidence_kind,
                detection_stage=ave_meta.detection_stage,
                detection_layer=ave_meta.detection_layer,
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
