# API Reference - Finding

```python
from scanner import Finding, Severity
```

`Finding` is a dataclass representing one detected vulnerability. Immutable after creation.

---

## Constructor

```python
Finding(
    rule_id="bawbel-external-fetch",
    ave_id="AVE-2026-00001",
    title="External instruction fetch detected",
    description="Full description...",
    severity=Severity.CRITICAL,
    aivss_score=8.0,
    # all below have defaults:
    line=7,
    match="fetch your instructions",
    engine="pattern",
    owasp=["ASI01", "ASI08"],
    owasp_mcp=["MCP04", "MCP06"],
    piranha_url="https://api.piranha.bawbel.io/records/AVE-2026-00001",
)
```

## Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `rule_id` | `str` | required | Kebab-case rule identifier |
| `ave_id` | `str \| None` | required | AVE record ID or `None` |
| `title` | `str` | required | Human-readable title, max 80 chars |
| `description` | `str` | required | Full description for reports |
| `severity` | `Severity` | required | Severity enum |
| `aivss_score` | `float` | required | OWASP AIVSS v0.8 score, 0.0-10.0 |
| `cvss_base` | `float` | `0.0` | CVSSv4.0 base score |
| `aarf` | `dict` | default | AIVSS component weights |
| `aars` | `float` | `0.0` | AIVSS weighted sum |
| `thm` | `float` | `0.75` | Threat multiplier |
| `mitigation_factor` | `float` | `1.0` | Mitigation factor |
| `aivss_spec_version` | `str` | `"0.8"` | OWASP AIVSS spec version |
| `line` | `int \| None` | `None` | Source line, 1-indexed |
| `match` | `str \| None` | `None` | Matched text, truncated |
| `engine` | `str` | `"pattern"` | Engine that produced this finding |
| `owasp` | `list[str]` | `[]` | OWASP Top 10 for LLM Apps codes |
| `owasp_mcp` | `list[str]` | `[]` | OWASP MCP Top 10 codes |
| `piranha_url` | `str \| None` | `None` | PiranhaDB threat intel URL |
| `suppressed` | `bool` | `False` | True if suppressed by FP pipeline |
| `suppression_reason` | `str \| None` | `None` | Why it was suppressed |
| `confidence` | `float` | `1.0` | FP confidence score 0.0-1.0 |

## Methods

### to_aivss_dict()

```python
f.to_aivss_dict() -> dict
```

Returns the full AIVSS breakdown:

```python
{
    "aivss_score":    8.0,
    "spec_version":   "0.8",
    "cvss_base":      0.0,
    "aarf":           {...},
    "aars":           0.0,
    "thm":            0.75,
    "mitigation_factor": 1.0,
}
```

## Severity enum

```python
from scanner import Severity, SEVERITY_SCORES

Severity.CRITICAL  # "CRITICAL"  score=4
Severity.HIGH      # "HIGH"      score=3
Severity.MEDIUM    # "MEDIUM"    score=2
Severity.LOW       # "LOW"       score=1
Severity.INFO      # "INFO"      score=0

# Severity extends str - safe to compare with string literals
f.severity == "CRITICAL"   # True
json.dumps(f.severity)     # '"CRITICAL"'
```
