# API Reference — Messages

All strings — error messages, log messages, and UI text — live in `scanner/messages.py`.

**Rule:** Never define a string inline in scanner.py, engine files, or cli.py.
Always import from `messages.py`.

---

## Errors (user-facing)

Returned in `ScanResult.error`. Stable error codes — never change or reuse.

```python
from scanner.messages import Errors

Errors.INVALID_PATH        # "E001: Invalid file path provided."
Errors.PATH_RESOLVE_FAILED # "E002: Could not resolve the provided path."
Errors.FILE_NOT_FOUND      # "E003: File not found: {name}"
Errors.NOT_A_FILE          # "E004: Path is not a regular file: {name}"
Errors.SYMLINK_REJECTED    # "E005: Symlinks are not scanned..."
Errors.FILE_TOO_LARGE      # "E006: File too large ({size_kb}KB)..."
Errors.CANNOT_STAT_FILE    # "E007: Could not read file metadata."
Errors.CANNOT_READ_FILE    # "E008: Could not read file content."
Errors.YARA_SCAN_FAILED    # "E011: YARA scan failed."
Errors.SEMGREP_PARSE_FAILED # "E012: Could not parse scanner output."
Errors.SEMGREP_TIMEOUT     # "E013: Scan timed out after {timeout}s."
Errors.RULES_FILE_MISSING  # "E020: Required rules file is missing."
```

**Security rules for Errors:**
- No exception detail (`str(e)`)
- No absolute paths (use `path.name` — basename only)
- No library names or versions
- Format params use `{name}`, `{size_kb}` etc. — never `{path}` (full path)

---

## Logs (internal structured messages)

Used with the `logging` module. `%s` format — never f-strings in log calls.

```python
from scanner.messages import Logs

# Scan lifecycle
Logs.SCAN_START     # "Scan started: path=%s component_type=%s size_kb=%d"
Logs.SCAN_COMPLETE  # "Scan complete: path=%s findings=%d risk=%.1f time_ms=%d"
Logs.SCAN_ERROR     # "Scan error: path=%s error=%s"
Logs.SCAN_SKIPPED   # "Scan skipped: path=%s reason=%s"

# Engine lifecycle
Logs.ENGINE_START       # "Engine started: engine=%s path=%s"
Logs.ENGINE_COMPLETE    # "Engine complete: engine=%s findings=%d time_ms=%d"
Logs.ENGINE_ERROR       # "Engine error: engine=%s path=%s error=%s"
Logs.ENGINE_UNAVAILABLE # "Engine unavailable (not installed): engine=%s"

# Findings
Logs.FINDING_DETECTED   # "Finding detected: rule_id=%s severity=%s engine=%s line=%s"
Logs.FINDING_DEDUPED    # "Finding deduplicated: rule_id=%s kept_severity=%s"
Logs.DEDUP_COMPLETE     # "Deduplication complete: before=%d after=%d"

# Path validation
Logs.SYMLINK_REJECTED   # "Symlink rejected: path=%s"
Logs.FILE_TOO_LARGE     # "File too large, skipping: path=%s size_kb=%d max_kb=%d"
Logs.COMPONENT_TYPE     # "Component type detected: path=%s type=%s ext=%s"
```

---

## Info (UI strings)

Shown in the terminal by `cli.py`.

```python
from scanner.messages import Info

Info.CLEAN_COMPONENT     # "No vulnerabilities found"
Info.CLEAN_DESCRIPTION   # "This component passed all AVE checks."
Info.REPORT_COMING_SOON  # "Full A-BOM report generation coming in v0.2.0"
Info.NO_FILES_FOUND      # "No scannable files found in: {path}"
```

---

## Adding a New Message

1. Add to the appropriate class in `scanner/messages.py`
2. For `Errors`: assign a new sequential E-code
3. For `Logs`: use `%s` format — never f-string
4. Import and use — never inline the string

```python
# ── messages.py ──────────────────────────────────────────────────────────────
class Errors:
    MY_NEW_ERROR = "E021: Something went wrong with {name}."

# ── usage ─────────────────────────────────────────────────────────────────────
from scanner.messages import Errors
return None, Errors.MY_NEW_ERROR.format(name=path.name)
```
