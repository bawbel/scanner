# API Reference — Engines

Each detection engine lives in `scanner/engines/` as a separate file.

---

## Engine Contract

Every engine function MUST follow this contract:

```python
def run_X_scan(file_path: str) -> list[Finding]:
    """
    Run [engine] against the component file.

    Args:
        file_path: Resolved absolute path to the component file

    Returns:
        list[Finding] — may be empty, NEVER None

    Guarantees:
        - Never raises under any circumstance
        - Returns [] if dependency not installed
        - Returns [] if rules file missing
        - Logs errors at ERROR level, never raises them
        - Uses Timer() for elapsed time
        - Uses Logs.ENGINE_* for all log messages
    """
```

---

## Current Engines

### Stage 1a — Pattern Engine (`engines/pattern.py`)

- **Dependency:** None — stdlib only
- **Always runs:** Yes
- **Rules:** `PATTERN_RULES` list in `pattern.py`
- **Add rules:** Add to `PATTERN_RULES` — no other changes

```python
from scanner.engines.pattern import run_pattern_scan, PATTERN_RULES
findings = run_pattern_scan(file_content_string)
```

### Stage 1b — YARA Engine (`engines/yara_engine.py`)

- **Dependency:** `yara-python` (optional)
- **Always runs:** No — skips silently if not installed
- **Rules:** `scanner/rules/yara/ave_rules.yar`
- **Add rules:** Edit `ave_rules.yar` — no Python changes

```python
from scanner.engines.yara_engine import run_yara_scan
findings = run_yara_scan(resolved_file_path_string)
```

### Stage 1c — Semgrep Engine (`engines/semgrep_engine.py`)

- **Dependency:** `semgrep` CLI (optional)
- **Always runs:** No — skips silently if not installed
- **Rules:** `scanner/rules/semgrep/ave_rules.yaml`
- **Add rules:** Edit `ave_rules.yaml` — no Python changes

```python
from scanner.engines.semgrep_engine import run_semgrep_scan
findings = run_semgrep_scan(resolved_file_path_string)
```

---

## Planned Engines

| Engine | Stage | File | Status |
|---|---|---|---|
| LLM semantic analysis | 2 | `engines/llm_engine.py` | Planned v0.2.0 |
| Behavioral sandbox | 3 | `engines/sandbox_engine.py` | Planned v1.0.0 |

---

## Adding a New Engine

See `.claude/skills/add-engine.md` for the complete step-by-step guide.

Summary:
1. Create `scanner/engines/my_engine.py` following the contract above
2. Register in `scanner/engines/__init__.py`
3. Add one line in `scanner/scanner.py` Step 5
4. Write tests in `tests/unit/engines/test_my_engine.py`

---

## Engine Registry

`scanner/engines/__init__.py` exports all active engines:

```python
from scanner.engines import run_pattern_scan, run_yara_scan, run_semgrep_scan
```

To disable an engine temporarily: comment out its import in `__init__.py`.
