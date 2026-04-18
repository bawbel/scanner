# API Reference — Utils

All utility classes live in `scanner/utils.py`.
Import via module-level function aliases — do not instantiate classes directly.

---

## Logger

Structured logging factory. All loggers are namespaced under `bawbel.`.

```python
from scanner.utils import get_logger

log = get_logger(__name__)

log.debug("detail: value=%s", value)           # DEBUG — full detail, dev only
log.info("lifecycle: event=%s", event)          # INFO — scan start/complete
log.warning("degraded: reason=%s", code)        # WARNING — engine missing, skipped
log.error("failed: type=%s", type(e).__name__)  # ERROR — type only, never message
```

**Log level:** controlled by `BAWBEL_LOG_LEVEL` env var (default: `WARNING`).

**Security rule:** Never use `str(e)` at WARNING or above. Use `type(e).__name__`.

---

## PathValidator

Safe path resolution and validation.

```python
from scanner.utils import resolve_path, is_safe_path

# Resolve raw string to Path
path, err = resolve_path("/some/path.md")
if err:
    return error_result(err)

# Validate resolved path
safe, err = is_safe_path(path)
if not safe:
    return error_result(err)
```

**Checks performed by `resolve_path()`:**
- Valid path string
- Not a symlink (checked BEFORE resolve — prevents symlink attacks)
- Successfully resolves to absolute path

**Checks performed by `is_safe_path()`:**
- Not a symlink (double-check on resolved path)
- Exists on disk
- Is a regular file (not a directory or device)
- Within `MAX_FILE_SIZE_BYTES`

---

## FileReader

Safe text file reading.

```python
from scanner.utils import read_file_safe

content, err = read_file_safe(path)
if err:
    return error_result(err)
```

Always uses `encoding="utf-8", errors="ignore"` — malicious files may contain
invalid UTF-8 sequences to trigger exceptions.

---

## SubprocessRunner

Safe external tool execution.

```python
from scanner.utils import run_subprocess

stdout, err = run_subprocess(
    args    = ["semgrep", "--config", rules_path, "--json", file_path],
    timeout = 30,
    label   = "semgrep",
)

if stdout is None and err is None:
    # Tool not installed — skip silently
    return []

if err:
    log.warning("engine failed: %s", err)
    return []
```

**Security guarantees:**
- Args always a list — never `shell=True`
- Timeout always enforced
- stderr logged at DEBUG only — never returned to caller
- `FileNotFoundError` → `(None, None)` — caller skips silently

---

## JsonParser

Safe JSON parsing.

```python
from scanner.utils import parse_json_safe

data, err = parse_json_safe(raw_output, label="semgrep")
if err or not data:
    return []
```

Empty input returns `(None, None)` — not an error.

---

## TextSanitiser

String validation and truncation.

```python
from scanner.utils import parse_severity, parse_cvss, truncate_match

severity = parse_severity("HIGH")        # "HIGH"
severity = parse_severity("invalid")     # "HIGH" (fallback)

score = parse_cvss(9.4)                  # 9.4
score = parse_cvss("bad")                # 5.0 (fallback)
score = parse_cvss(99.9)                 # 10.0 (clamped)

match = truncate_match("long text...", 80)  # max 80 chars, stripped
match = truncate_match(None, 80)            # None
```

---

## Timer

Elapsed-time context manager.

```python
from scanner.utils import Timer

with Timer() as t:
    do_work()

print(f"Took {t.elapsed_ms}ms")
```

Used in all engine functions to measure and log scan time.
