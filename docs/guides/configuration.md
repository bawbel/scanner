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

Stage 2 uses [LiteLLM](https://docs.litellm.ai) — works with any LLM provider.
Install first: `pip install "bawbel-scanner[llm]"`

| Variable | Default | Description |
|---|---|---|
| `BAWBEL_LLM_MODEL` | auto-detected | LiteLLM model string — any provider |
| `BAWBEL_LLM_MAX_CHARS` | `8000` | Max content chars sent to LLM |
| `BAWBEL_LLM_TIMEOUT` | `30` | LLM call timeout in seconds |
| `BAWBEL_LLM_ENABLED` | `true` | Set `false` to disable Stage 2 |

Provider API keys — set whichever you use:

| Key | Default model |
|---|---|
| `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |
| `OPENAI_API_KEY` | `gpt-4o-mini` |
| `GEMINI_API_KEY` | `gemini/gemini-1.5-flash` |
| `MISTRAL_API_KEY` | `mistral/mistral-small` |
| `GROQ_API_KEY` | `groq/llama3-8b-8192` |

Stage 2 activates as soon as `litellm` is installed and a key (or model) is set:

```bash
# Anthropic
pip install "bawbel-scanner[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
bawbel scan ./skill.md

# OpenAI
export OPENAI_API_KEY=sk-...
bawbel scan ./skill.md

# Local Ollama (no API key needed)
export BAWBEL_LLM_MODEL=ollama/mistral
bawbel scan ./skill.md

# Explicit model override (any LiteLLM model string)
export BAWBEL_LLM_MODEL=gemini/gemini-1.5-flash
export GEMINI_API_KEY=...
bawbel scan ./skill.md
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
  enabled: false          # set true to enable Stage 2 (requires bawbel-scanner[llm])
  model: claude-haiku-4-5 # any LiteLLM model string
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

try:
    import litellm
    from scanner.engines.llm_engine import _resolve_model
    model = _resolve_model()
    if model:
        print(f'✓ LLM Stage 2 enabled — model={model}')
    else:
        print('✗ LLM installed but no model set — set BAWBEL_LLM_MODEL or a provider API key')
except ImportError:
    print('✗ litellm not installed — pip install "bawbel-scanner[llm]"')
"
```
