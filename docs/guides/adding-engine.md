# Adding a Detection Engine

Each engine is a separate file in `scanner/engines/`. Adding one requires
changes to exactly three files — nothing else.

---

## The Three Files

| File | Change |
|---|---|
| `scanner/engines/my_engine.py` | Create — implement the engine |
| `scanner/engines/__init__.py` | Register — add import + export |
| `scanner/scanner.py` | Wire — add one line in Step 5 |

---

## Step 1 — Create the engine file

```python
# scanner/engines/my_engine.py
"""
Bawbel Scanner — My detection engine (Stage X).

Requires [dependency]. Skips silently if not installed.
"""

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger, parse_cvss, parse_severity, truncate_match

log = get_logger(__name__)
MAX_MATCH_LENGTH = 80


def run_myengine_scan(file_path: str) -> list[Finding]:
    """
    Run [engine] against the component file.
    Never raises. Returns [] if dependency missing or error occurs.
    """
    findings: list[Finding] = []

    # 1. Check optional dependency
    try:
        import mylib
    except ImportError:
        log.info(Logs.ENGINE_UNAVAILABLE, "myengine")
        return findings

    log.debug(Logs.ENGINE_START, "myengine", file_path)

    with Timer() as t:
        try:
            raw = mylib.scan(file_path)
        except Exception as e:  # nosec B110
            log.error(Logs.ENGINE_ERROR, "myengine", file_path, type(e).__name__)
            return findings

    for r in raw:
        try:
            findings.append(Finding(
                rule_id     = f"myengine-{r.id}",
                ave_id      = r.ave_id or None,
                title       = r.title[:MAX_MATCH_LENGTH],
                description = r.description,
                severity    = Severity(parse_severity(r.severity)),
                cvss_ai     = parse_cvss(r.score),
                line        = r.line,
                match       = truncate_match(r.match, MAX_MATCH_LENGTH),
                engine      = "myengine",
                owasp       = r.owasp or [],
            ))
        except Exception as e:  # nosec B110
            log.warning("result error: engine=myengine type=%s", type(e).__name__)
            continue

    log.debug(Logs.ENGINE_COMPLETE, "myengine", len(findings), t.elapsed_ms)
    return findings
```

## Step 2 — Register in `__init__.py`

```python
# scanner/engines/__init__.py
from scanner.engines.pattern        import run_pattern_scan
from scanner.engines.yara_engine    import run_yara_scan
from scanner.engines.semgrep_engine import run_semgrep_scan
from scanner.engines.my_engine      import run_myengine_scan  # ← add

__all__ = [
    "run_pattern_scan",
    "run_yara_scan",
    "run_semgrep_scan",
    "run_myengine_scan",   # ← add
]
```

## Step 3 — Wire into `scanner.py`

```python
# scanner/scanner.py — Step 5
findings.extend(run_pattern_scan(content))
findings.extend(run_yara_scan(str(path)))
findings.extend(run_semgrep_scan(str(path)))
findings.extend(run_myengine_scan(str(path)))  # ← add here
```

---

## Step 4 — Write tests

```python
# tests/unit/engines/test_my_engine.py
from scanner.engines.my_engine import run_myengine_scan

def test_engine_returns_list_on_clean_file(tmp_path):
    f = tmp_path / "skill.md"
    f.write_text("# Clean\n")
    result = run_myengine_scan(str(f))
    assert isinstance(result, list)

def test_engine_never_raises_on_bad_input():
    result = run_myengine_scan("/nonexistent/file.md")
    assert isinstance(result, list)
```

---

## Full Guide

See `.claude/skills/add-engine.md` for the complete guide including
the security checklist, dependency management, and verification steps.
