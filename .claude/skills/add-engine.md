---
name: add-engine
description: >
  Run this when asked to add a new detection engine, integrate a new scanning
  tool, or add a new analysis stage.
  Triggers: "add a new engine", "integrate X scanner", "add Stage 2", "add LLM analysis".
---

# Add Detection Engine

Human guide: `docs/guides/adding-engine.md` — do not duplicate it here.
This file is AI execution instructions only.

---

## Three files change — nothing else

| File | Action |
|---|---|
| `scanner/engines/<n>_engine.py` | Create |
| `scanner/engines/__init__.py` | Register |
| `scanner/scanner.py` | Wire — one line in Step 5 |

---

## Step 1 — Create `scanner/engines/<n>_engine.py`

Non-negotiable contract — every line is required:

```python
from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger, parse_cvss, parse_severity, truncate_match

log = get_logger(__name__)


def run_<n>_scan(file_path: str) -> list[Finding]:
    findings: list[Finding] = []

    # Dependency check — ImportError means not installed, skip silently
    try:
        import <dep>
    except ImportError:
        log.info(Logs.ENGINE_UNAVAILABLE, "<n>")
        return findings

    # Rules file check
    if not RULES_PATH.exists():
        log.warning(Logs.RULES_MISSING, "<n>", RULES_PATH)
        return findings

    log.debug(Logs.ENGINE_START, "<n>", file_path)

    with Timer() as t:
        try:
            raw = <dep>.scan(file_path)
        except <SpecificError> as e:
            log.error(Logs.ENGINE_ERROR, "<n>", file_path, type(e).__name__)
            log.debug("detail: %s", e)       # full detail at DEBUG only
            return findings
        except Exception as e:               # nosec B110
            log.error(Logs.ENGINE_ERROR, "<n>", file_path, type(e).__name__)
            return findings

    for r in raw:
        try:
            findings.append(Finding(
                rule_id     = "<n>-" + r.rule_id,
                ave_id      = r.ave_id or None,
                title       = r.title[:80],
                description = r.description,
                severity    = Severity(parse_severity(r.severity)),
                cvss_ai     = parse_cvss(r.score),
                line        = r.line,
                match       = truncate_match(r.match, 80),
                engine      = "<n>",
                owasp       = r.owasp or [],
            ))
        except Exception as e:               # nosec B110
            log.warning("parse error: engine=<n> error_type=%s", type(e).__name__)
            continue

    log.debug(Logs.ENGINE_COMPLETE, "<n>", len(findings), t.elapsed_ms)
    return findings
```

## Step 2 — Register in `scanner/engines/__init__.py`

```python
from scanner.engines.<n>_engine import run_<n>_scan

__all__ = [..., "run_<n>_scan"]
```

## Step 3 — Wire in `scanner/scanner.py` Step 5

```python
findings.extend(run_pattern_scan(content))
findings.extend(run_yara_scan(str(path)))
findings.extend(run_semgrep_scan(str(path)))
findings.extend(run_<n>_scan(str(path)))    # ← add here
# Future: findings.extend(run_llm_scan(content))
```

## Step 4 — Security checklist before commit

```
[x] Function returns [] on all failures — never raises
[x] ImportError caught separately from Exception
[x] type(e).__name__ at ERROR/WARNING — never str(e)
[x] run_subprocess() used if engine is a CLI tool — never subprocess.run() directly
[x] No shell=True
[x] Timer() wraps the scan call
[x] All Finding fields use parse_cvss() and parse_severity()
[x] match always goes through truncate_match(text, 80)
[x] All log messages use Logs.ENGINE_* constants
```

## Step 5 — Write three tests

```python
def test_<n>_detects_target(self, tmp_path): ...          # happy path
def test_<n>_skips_if_not_installed(self, tmp_path, monkeypatch): ...  # ImportError
def test_<n>_handles_engine_error(self, tmp_path, monkeypatch): ...    # runtime error
```

## Step 6 — Verify and commit

```bash
python -m pytest tests/ -q
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# must still be: 2 findings, CRITICAL 9.4
bandit -r scanner/ cli.py config/ -f screen   # 0 issues
git commit -m "feat(scanner): add <n> detection engine (Stage X)"
```

## Step 7 — Update `.claude/architecture.md`

Add the new engine to the pipeline diagram.
