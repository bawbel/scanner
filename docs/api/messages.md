# API Reference - Messages

```python
from scanner.messages import Errors, Logs, Info
```

All user-facing strings live in `scanner/messages.py`. Never inline strings in `scanner.py`,
engines, or CLI modules.

---

## Errors

User-facing error messages returned in `ScanResult.error`.

**Security rules:**
- Never include exception details (`str(e)`) - leaks stack info
- Never include absolute internal paths
- Never include Python or library versions
- File paths use basename only, never absolute paths
- Error codes are stable - do not rename without updating docs

### Path / file validation

| Code | Message |
|---|---|
| `E001` | `Invalid file path provided.` |
| `E002` | `Could not resolve the provided path.` |
| `E003` | `File not found: {name}` |
| `E004` | `Path is not a regular file: {name}` |
| `E005` | `Symlinks are not scanned for security reasons.` |
| `E006` | `File too large ({size_kb}KB) - maximum is {max_mb}MB.` |
| `E007` | `Could not read file metadata.` |
| `E008` | `Could not read file content.` |

### Engine errors

| Code | Message |
|---|---|
| `E010` | `YARA rule compilation failed. Check rule syntax.` |
| `E011` | `YARA scan failed.` |
| `E012` | `Could not parse scanner output.` |
| `E013` | `Scan timed out after {timeout}s.` |

### Rules

| Code | Message |
|---|---|
| `E020` | `Required rules file is missing. Re-install the scanner.` |

### Usage

```python
from scanner.messages import Errors

return ScanResult(
    file_path=str(path),
    component_type="unknown",
    error=Errors.FILE_NOT_FOUND.format(name=path.name),
)
```

---

## Logs

Structured log messages for use with `get_logger()`. Use `%s` formatting, not f-strings.

```python
from scanner.messages import Logs

log.info(Logs.SCAN_START, path, component_type, size_kb)
log.info(Logs.ENGINE_COMPLETE, "pattern", len(findings), t.elapsed_ms)
```

### Scan lifecycle

```python
Logs.SCAN_START     = "Scan started: path=%s component_type=%s size_kb=%d"
Logs.SCAN_COMPLETE  = "Scan complete: path=%s findings=%d risk=%.1f time_ms=%d"
Logs.SCAN_ERROR     = "Scan error: path=%s error=%s"
```

### Engine lifecycle

```python
Logs.ENGINE_UNAVAILABLE = "Engine unavailable (not installed): engine=%s"
Logs.ENGINE_START       = "Engine started: engine=%s path=%s"
Logs.ENGINE_COMPLETE    = "Engine complete: engine=%s findings=%d time_ms=%d"
Logs.ENGINE_ERROR       = "Engine error: engine=%s path=%s error=%s"
```

### Finding

```python
Logs.FINDING_DETECTED = "Finding detected: rule_id=%s severity=%s engine=%s line=%s"
```

---

## Info

Informational strings for the UI.

```python
Info.CLEAN_COMPONENT   = "No vulnerabilities found"
Info.CLEAN_DESCRIPTION = "This component passed all AVE checks."
```
