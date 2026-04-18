# API Reference — ScanResult

`ScanResult` is the complete output of a single `scan()` call.

---

## Import

```python
from scanner import ScanResult
```

---

## Fields

| Field | Type | Stable | Description |
|---|---|---|---|
| `file_path` | `str` | ✅ | Resolved absolute path of the scanned file |
| `component_type` | `str` | ✅ | `"skill"` / `"mcp"` / `"prompt"` / `"unknown"` |
| `findings` | `list[Finding]` | ✅ | Sorted by severity — highest first |
| `scan_time_ms` | `int` | ✅ | Elapsed scan time in milliseconds |
| `error` | `Optional[str]` | ✅ | Error code string if scan failed, else `None` |

---

## Computed Properties

| Property | Type | Description |
|---|---|---|
| `is_clean` | `bool` | `True` only if no findings AND no error |
| `has_error` | `bool` | `True` if scan failed with an error |
| `max_severity` | `Optional[Severity]` | Highest severity, or `None` if no findings |
| `risk_score` | `float` | Highest CVSS-AI score, or `0.0` if no findings |

---

## Usage Patterns

```python
result = scan("./skill.md")

# ── Pattern 1: Simple clean/error/findings check ──────────────────────────
if result.has_error:
    print(f"Scan failed: {result.error}")
elif result.is_clean:
    print("Clean")
else:
    print(f"{len(result.findings)} findings, risk {result.risk_score:.1f}")

# ── Pattern 2: CI/CD gate ─────────────────────────────────────────────────
THRESHOLD = {"CRITICAL": 4, "HIGH": 3}
from scanner import SEVERITY_SCORES
if result.max_severity and SEVERITY_SCORES[result.max_severity.value] >= THRESHOLD["HIGH"]:
    sys.exit(2)

# ── Pattern 3: Filter by severity ────────────────────────────────────────
critical = [f for f in result.findings if f.severity.value == "CRITICAL"]

# ── Pattern 4: JSON serialisation ────────────────────────────────────────
import json
output = {
    "file_path":      result.file_path,
    "component_type": result.component_type,
    "risk_score":     result.risk_score,
    "max_severity":   result.max_severity.value if result.max_severity else None,
    "findings":       [{"rule_id": f.rule_id, "severity": f.severity.value}
                       for f in result.findings],
}
print(json.dumps(output))
```

---

## Error Codes

When `has_error` is `True`, `error` contains a stable error code:

| Code | Meaning |
|---|---|
| `E001` | Invalid file path |
| `E002` | Path could not be resolved |
| `E003` | File not found |
| `E004` | Path is not a file |
| `E005` | Symlink rejected |
| `E006` | File too large |
| `E007` | Could not read file metadata |
| `E008` | Could not read file content |
| `E012` | Scanner output parse error |
| `E013` | Scan timed out |
| `E020` | Rules file missing |

---

## Notes

- `scan()` **never raises** — error conditions always return `ScanResult(error=...)`
- `is_clean` is `False` when `has_error` is `True` — a failed scan is not clean
- `findings` is always sorted by severity descending — index 0 is always the worst
