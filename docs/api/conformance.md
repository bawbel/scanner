# API Reference - Conformance Scorer

```python
from scanner.conformance import score_conformance, CheckStatus, CheckCategory
```

---

## score_conformance()

```python
score_conformance(manifest: dict) -> ConformanceReport
```

Scores an MCP server manifest against the MCP specification.

| Parameter | Type | Description |
|---|---|---|
| `manifest` | `dict` | Parsed MCP server manifest (from JSON or YAML) |

Returns `ConformanceReport`.

```python
import json
from scanner.conformance import score_conformance

manifest = json.load(open("server.json"))
report = score_conformance(manifest)

print(f"Score: {report.score:.1f}/100  Grade: {report.grade}")
print(f"Conformant: {report.is_conformant}")
print(f"Passed: {report.passed}  Failed: {report.failed}")
```

---

## ConformanceReport

### Fields

| Field | Type | Description |
|---|---|---|
| `score` | `float` | 0.0-100.0 |
| `grade` | `str` | `"A+"`, `"A"`, `"B"`, `"C"`, `"D"`, `"F"` |
| `is_conformant` | `bool` | `True` if all REQUIRED checks pass |
| `passed` | `int` | Number of passing checks |
| `failed` | `int` | Number of failing checks |
| `warned` | `int` | Number of warning checks |
| `skipped` | `int` | Number of skipped checks |
| `results` | `list[CheckResult]` | Per-check results |

### Grade thresholds

| Grade | Score |
|---|---|
| A+ | 95-100 |
| A  | 85-94 |
| B  | 70-84 |
| C  | 50-69 |
| D  | 30-49 |
| F  | 0-29 |

### Methods

```python
report.to_dict()   # dict - JSON-serialisable
```

---

## CheckResult

### Fields

| Field | Type | Description |
|---|---|---|
| `check` | `Check` | The check definition |
| `status` | `CheckStatus` | `PASS`, `FAIL`, `WARN`, or `SKIP` |
| `message` | `str \| None` | Detail or remediation hint |

---

## CheckStatus

```python
class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
```

---

## CheckCategory

```python
class CheckCategory(str, Enum):
    REQUIRED      = "required"
    RECOMMENDED   = "recommended"
    BEST_PRACTICE = "best_practice"
```

Only `REQUIRED` failures make `is_conformant = False`.

---

## Example

```python
import json
from scanner.conformance import score_conformance, CheckStatus, CheckCategory

manifest = json.load(open("server.json"))
report = score_conformance(manifest)

# Print all failing required checks
for r in report.results:
    if r.status == CheckStatus.FAIL and r.check.category == CheckCategory.REQUIRED:
        print(f"REQUIRED FAIL: {r.check.title}")
        print(f"  Fix: {r.check.remediation}")

print(report.to_dict())
```
