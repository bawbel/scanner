# Adding a Detection Engine

---

## Engine contract

Every engine must:

1. Return `list[Finding]` — never raise, return `[]` on error or missing dependency
2. Set `finding.engine` to a short identifier string
3. Skip silently if its dependency is not installed
4. Log warnings at `WARNING`, details at `DEBUG`
5. Never access the network directly from the engine function

---

## Step 1: Create the engine file

Create `scanner/engines/my_engine.py`:

```python
"""
Bawbel Scanner - My Engine (Stage X).

What this engine does and what it detects.
"""

from typing import Optional
from scanner.models import Finding, Severity
from scanner.utils import get_logger

log = get_logger(__name__)

ENGINE_NAME = "my-engine"


def run_my_scan(
    file_path: str,
    stripped_content: Optional[str] = None,
) -> list[Finding]:
    """
    Run my engine against a component file.

    Args:
        file_path:        Resolved path to the file.
        stripped_content: Content with code fences blanked (optional).

    Returns:
        List of Findings, may be empty.
    """
    findings: list[Finding] = []

    # Check dependency is installed
    try:
        import my_dependency
    except ImportError:
        log.info("Engine unavailable (not installed): engine=%s", ENGINE_NAME)
        return findings

    log.debug("Engine started: engine=%s path=%s", ENGINE_NAME, file_path)

    try:
        # ... run detection ...
        pass
    except Exception as e:  # nosec B110
        log.error("Engine error: engine=%s error_type=%s", ENGINE_NAME, type(e).__name__)
        return findings

    return findings
```

---

## Step 2: Export from engines package

Add to `scanner/engines/__init__.py`:

```python
from scanner.engines.my_engine import run_my_scan
```

---

## Step 3: Register in scanner.py

In `scanner/scanner.py`, add to the scan loop:

```python
from scanner.engines.my_engine import run_my_scan

# Inside scan():
findings.extend(run_my_scan(str(path), stripped))
```

---

## Step 4: Show in bawbel version

In `scanner/cli/cmd_version.py`, add a status block:

```python
try:
    import my_dependency
    console.print(
        f"  [bold #1DB894]✓[/]  My Engine   [dim]v{my_dependency.__version__}  ·  active[/]"
    )
except ImportError:
    console.print(
        "  [dim]✗  My Engine   not installed  ·  "
        'pip install "bawbel-scanner\\[my-engine]"[/]'
    )
```

---

## Step 5: Add pyproject.toml optional dependency

In `pyproject.toml`:

```toml
[project.optional-dependencies]
my-engine = ["my-dependency>=1.0"]
all = [
    "yara-python",
    "semgrep",
    "litellm",
    "magika",
    "my-dependency>=1.0",   # add here
]
```

---

## Step 6: Write tests

In `tests/unit/engines/test_my_engine.py`:

```python
from scanner.engines.my_engine import run_my_scan

def test_returns_list_on_empty():
    assert run_my_scan("/tmp/empty.md") == []

def test_detects_known_pattern(tmp_path):
    f = tmp_path / "skill.md"
    f.write_text("content that my engine detects\n")
    findings = run_my_scan(str(f))
    assert findings
    assert findings[0].engine == "my-engine"

def test_skips_silently_without_dependency(monkeypatch):
    import sys
    with monkeypatch.context() as m:
        m.setitem(sys.modules, "my_dependency", None)
        result = run_my_scan("/tmp/any.md")
        assert result == []
```

---

## Finding fields

Every Finding returned by your engine must set:

```python
Finding(
    rule_id="my-engine-rule-id",    # kebab-case, unique
    ave_id="AVE-2026-XXXXX",        # or None
    title="Short title",
    description="Full description",
    severity=Severity.HIGH,
    aivss_score=7.5,
    line=line_number,               # or None
    match=matched_text,             # or None, truncate to MAX_MATCH_LENGTH
    engine="my-engine",             # must match ENGINE_NAME
    owasp=["ASI01"],
    owasp_mcp=["MCP04"],
    piranha_url=f"https://api.piranha.bawbel.io/records/{ave_id}",
)
```
