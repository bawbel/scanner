# Configuration — Bawbel Scanner

All configuration is controlled via environment variables.
No config files required.

---

## Environment Variables

### Logging

| Variable | Default | Description |
|---|---|---|
| `BAWBEL_LOG_LEVEL` | `WARNING` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

```bash
# Silent (default — production)
bawbel scan ./skill.md

# Lifecycle events only
BAWBEL_LOG_LEVEL=INFO bawbel scan ./skill.md

# Full debug output (development)
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./skill.md
```

### Security Limits

| Variable | Default | Description |
|---|---|---|
| `BAWBEL_MAX_FILE_SIZE_MB` | `10` | Skip files larger than N megabytes |
| `BAWBEL_SCAN_TIMEOUT_SEC` | `30` | Subprocess timeout for YARA/Semgrep |

```bash
# Allow larger files
BAWBEL_MAX_FILE_SIZE_MB=50 bawbel scan ./large-skill.md

# Shorter timeout for CI
BAWBEL_SCAN_TIMEOUT_SEC=10 bawbel scan ./skills/
```

### Stage 2: LLM Semantic Analysis (optional)

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables LLM analysis via Claude |
| `OPENAI_API_KEY` | — | Alternative LLM provider |
| `BAWBEL_LLM_MODEL` | `claude-sonnet-4-20250514` | LLM model to use |
| `BAWBEL_LLM_MAX_TOKENS` | `1000` | Max tokens per LLM call |
| `BAWBEL_LLM_TIMEOUT_SEC` | `60` | LLM call timeout |

Stage 2 is disabled by default. Set an API key to enable it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
bawbel scan ./skill.md   # now runs semantic analysis
```

### Stage 3: Behavioral Sandbox (future)

| Variable | Default | Description |
|---|---|---|
| `BAWBEL_SANDBOX_ENABLED` | `false` | Enable behavioral sandbox (v1.0) |
| `BAWBEL_SANDBOX_TIMEOUT_SEC` | `120` | Sandbox execution timeout |

---

## bawbel.yml (project config file)

Create a `bawbel.yml` in your project root to configure scans permanently:

```yaml
# bawbel.yml
version: "1"

scan:
  recursive: true
  fail_on_severity: high
  component_types:
    - skill
    - mcp
    - prompt

output:
  format: sarif
  file: bawbel-results.sarif

llm:
  enabled: false          # set true to enable Stage 2
  provider: anthropic
  model: claude-sonnet-4-20250514
```

---

## Checking Available Engines

```bash
python3 -c "
try:
    import yara
    print('✓ yara-python — Stage 1b enabled')
except ImportError:
    print('✗ yara-python — install: pip install yara-python')

import subprocess
r = subprocess.run(['semgrep', '--version'], capture_output=True)
if r.returncode == 0:
    print('✓ semgrep — Stage 1c enabled')
else:
    print('✗ semgrep — install: pip install semgrep')

import os
if os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('OPENAI_API_KEY'):
    print('✓ LLM key set — Stage 2 enabled')
else:
    print('✗ No LLM key — Stage 2 disabled')
"
```
