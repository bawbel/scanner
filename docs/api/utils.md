# API Reference - Utils

```python
from scanner.utils import (
    get_logger,
    resolve_path,
    is_safe_path,
    read_file_safe,
    run_subprocess,
    parse_json_safe,
    parse_severity,
    parse_cvss,
    truncate_match,
    Timer,
)
```

---

## Logging

```python
get_logger(name: str) -> logging.Logger
```

Returns a namespaced logger under `bawbel.<name>`. Log level controlled by
`BAWBEL_LOG_LEVEL` env var (default: `WARNING`).

```python
log = get_logger(__name__)
log.debug("detail: value=%s", value)
log.warning("skipped: reason=%s", code)
log.error("failed: type=%s", type(e).__name__)
```

**Security rule:** never log file content, match strings, or exception messages at
WARNING or above. Use `type(e).__name__` not `str(e)`.

---

## Path handling

```python
resolve_path(file_path: str) -> tuple[Path | None, str | None]
```

Safely resolve a path string. Checks: valid string, not a symlink (before resolve).

```python
is_safe_path(path: Path) -> tuple[bool, str | None]
```

Validate a resolved path. Checks: not a symlink, exists, is a file, within size limit.

```python
path, err = resolve_path("/path/to/skill.md")
if err:
    return ScanResult(error=err, ...)

ok, err = is_safe_path(path)
if not ok:
    return ScanResult(error=err, ...)
```

---

## File reading

```python
read_file_safe(path: Path) -> tuple[str | None, str | None]
```

Read a text file safely with encoding fallback. Always uses `errors="ignore"` to
prevent malformed UTF-8 from crashing the scanner.

```python
content, err = read_file_safe(path)
if err:
    return ScanResult(error=err, ...)
```

---

## Subprocess

```python
run_subprocess(
    args: list[str],
    timeout: int,
    label: str,
) -> tuple[str | None, str | None]
```

Run an external command safely. Always uses a list (never shell=True), always enforces timeout.

Returns `(None, None)` if tool is not installed — callers skip silently.

```python
stdout, err = run_subprocess(["semgrep", "--version"], timeout=5, label="semgrep")
if stdout is None and err is None:
    # semgrep not installed - skip
    return []
```

---

## JSON parsing

```python
parse_json_safe(raw: str, label: str = "json") -> tuple[dict | list | None, str | None]
```

Parse JSON without raising. Returns `(None, None)` for empty input.

```python
data, err = parse_json_safe(stdout, label="semgrep")
if err or data is None:
    return []
```

---

## Validation helpers

```python
parse_severity(severity_str: str, fallback: str = "HIGH") -> str
```

Normalise a severity string. Returns `fallback` for unrecognised values.

```python
parse_cvss(raw: object, fallback: float = 5.0) -> float
```

Parse and clamp a score to 0.0-10.0. Used for AIVSS scores. Does not compute AIVSS —
that logic is in `finding.py`.

```python
truncate_match(text: str | None, max_len: int) -> str | None
```

Truncate and strip a match string. Apply to all `match` fields before storing in a Finding.

---

## Timer

```python
with Timer() as t:
    do_work()
log.debug("took %dms", t.elapsed_ms)
```

Context manager for elapsed time measurement.
