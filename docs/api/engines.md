# API Reference - Engines

All engine functions follow the same contract:

```python
def run_<engine>_scan(file_path: str, ...) -> list[Finding]:
```

- Never raise — return `[]` on error or missing dependency
- Never access the network directly
- Log warnings at `WARNING` level, details at `DEBUG`
- Engine field on every returned Finding is set to the engine name

---

## Pattern engine

```python
from scanner.engines.pattern import run_pattern_scan, PATTERN_RULES
```

```python
run_pattern_scan(content: str) -> list[Finding]
```

| Parameter | Type | Description |
|---|---|---|
| `content` | `str` | Full file content as a string |

```python
from scanner.engines.pattern import run_pattern_scan, PATTERN_RULES

print(f"{len(PATTERN_RULES)} rules loaded")

findings = run_pattern_scan(open("skill.md").read())
for f in findings:
    print(f.rule_id, f.line, f.aivss_score)
```

`PATTERN_RULES` is a `list[dict]`. Each dict has:

| Key | Type | Description |
|---|---|---|
| `rule_id` | `str` | Kebab-case identifier |
| `ave_id` | `str \| None` | AVE record ID |
| `title` | `str` | Human-readable title |
| `description` | `str` | Full description |
| `severity` | `Severity` | Severity enum |
| `aivss_score` | `float` | AIVSS score |
| `owasp` | `list[str]` | OWASP codes |
| `owasp_mcp` | `list[str]` | OWASP MCP codes |
| `patterns` | `list[str]` | Regex patterns |

---

## YARA engine

```python
from scanner.engines.yara_engine import run_yara_scan, YARA_RULES_PATH
```

```python
run_yara_scan(
    file_path: str,
    stripped_content: Optional[str] = None,
) -> list[Finding]
```

| Parameter | Type | Description |
|---|---|---|
| `file_path` | `str` | Path to the file to scan |
| `stripped_content` | `str \| None` | Pre-processed content with code fences blanked. When provided, YARA scans this instead of the raw file. Line numbers still map to the original. |

```python
from scanner.engines.yara_engine import run_yara_scan

findings = run_yara_scan("/path/to/skill.md")
# Returns [] silently if yara-python is not installed
```

---

## Semgrep engine

```python
from scanner.engines.semgrep_engine import run_semgrep_scan, SEMGREP_RULES_PATH
```

```python
run_semgrep_scan(
    file_path: str,
    stripped_content: Optional[str] = None,
) -> list[Finding]
```

```python
from scanner.engines.semgrep_engine import run_semgrep_scan

findings = run_semgrep_scan("/path/to/skill.md")
# Returns [] silently if semgrep CLI is not installed
```

---

## LLM engine

```python
from scanner.engines.llm_engine import run_llm_scan, _parse_findings, _resolve_model
```

```python
run_llm_scan(content: str) -> list[Finding]
```

```python
from scanner.engines.llm_engine import run_llm_scan, _resolve_model

model = _resolve_model()    # None if no key set
print(f"Active model: {model}")

findings = run_llm_scan(open("skill.md").read())
# Returns [] silently if litellm not installed or no API key
```

`_parse_findings(raw: str) -> list[Finding]` — parses the LLM JSON response. Accepts both `aivss_score` and `aivss` keys for backwards compatibility.

---

## Magika engine

```python
from scanner.engines.magika_engine import run_magika_scan
```

```python
run_magika_scan(file_path: str) -> list[Finding]
```

```python
from scanner.engines.magika_engine import run_magika_scan

findings = run_magika_scan("/path/to/skill.md")
# Returns [] silently if magika is not installed
# Returns [] if content type is benign (markdown, yaml, json, text)
# Returns Finding(AVE-2026-00024) if content type is dangerous (ELF, PE32, pickle, etc.)
```

---

## Sandbox engine

```python
from scanner.engines.sandbox_engine import (
    run_sandbox_scan,
    is_docker_available,
    SANDBOX_ENABLED,
)
```

```python
run_sandbox_scan(file_path: str) -> list[Finding]
```

```python
from scanner.engines.sandbox_engine import run_sandbox_scan, is_docker_available, SANDBOX_ENABLED

if not SANDBOX_ENABLED:
    print("Set BAWBEL_SANDBOX_ENABLED=true to enable Stage 3")
elif not is_docker_available():
    print("Docker not running")
else:
    findings = run_sandbox_scan("/path/to/skill.md")
```

---

## Meta-analyzer

```python
from scanner.engines.meta_analyzer import run_meta_analysis
```

```python
run_meta_analysis(
    findings: list[Finding],
    content: str,
    file_path: str,
) -> list[Finding]
```

Takes the findings from static engines and returns a possibly smaller list after
LLM-based false-positive classification. Only called when LLM is configured and
there are medium-confidence findings.

```python
from scanner.engines.meta_analyzer import run_meta_analysis

# Called internally by scanner.py after all static engines run
# Rarely needed to call directly - use scan() instead
filtered = run_meta_analysis(findings, content, file_path)
```
