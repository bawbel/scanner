# Detection Engines — Complete Guide

Bawbel Scanner runs five detection engines in sequence.
Each engine adds an independent layer of analysis — finding different attack patterns
that the others would miss. They are designed to be additive: every layer that's active
makes the scanner harder to evade.

---

## Architecture Overview

```
Component file (SKILL.md / MCP manifest / system prompt)
│
├── Stage 1a  Pattern Engine     ── regex, always runs, stdlib only
├── Stage 1b  YARA Engine        ── binary + text matching, optional
├── Stage 1c  Semgrep Engine     ── structural patterns, optional
├── Stage 2   LLM Engine         ── semantic analysis, optional, any provider
└── Stage 3   Sandbox Engine     ── runtime behaviour, optional, Docker (v1.0)
         │
         ▼
    deduplicate()
         │
         ▼
    ScanResult(findings=[...])
```

Each engine returns `list[Finding]`. The scanner collects all findings from all
active engines, deduplicates by `(rule_id, line)`, and returns them ranked by
severity. No engine ever raises — each skips silently if its dependency is missing.

---

## Engine Summary

| Stage | Engine   | Install                          | Always runs | What it catches |
|-------|----------|----------------------------------|-------------|-----------------|
| 0     | **Magika** | `pip install "bawbel-scanner[magika]"` | no | File type verification — supply chain attack detection |
| 1a    | Pattern  | nothing — stdlib only            | ✓ yes       | 15 regex rules, fast |
| 1b    | YARA     | `pip install "bawbel-scanner[yara]"` | no     | binary + complex text patterns, 15 rules |
| 1c    | Semgrep  | `pip install "bawbel-scanner[semgrep]"` | no  | structural patterns, multi-line, 15 rules |
| 2     | LLM      | `pip install "bawbel-scanner[llm]"` + API key | no | nuanced, obfuscated, multi-turn |
| 3     | Sandbox  | Docker + `BAWBEL_SANDBOX_ENABLED=true` | no  | runtime behaviour, eBPF (v1.0) |

---


---

## Stage 0 — Magika File Type Verification

**File:** `scanner/engines/magika_engine.py`
**Install:** `pip install "bawbel-scanner[magika]"` (included in `[all]`)
**Always runs:** No — skips silently if not installed

### Purpose

Runs before all text analysis engines. Uses Google's Magika (~99% accuracy, ~5ms/file)
to verify that each file's content matches its extension. Catches supply chain attacks
that no regex or YARA rule can detect — because the file contains no text to match.

### What it detects

| Content type | Extension | Severity | Example attack |
|---|---|---|---|
| ELF binary | `.md`, `.yaml` | CRITICAL | Skill file is actually a Linux executable |
| PE32/PE64 | `.md`, `.json` | CRITICAL | Skill file is actually a Windows executable |
| Python bytecode | `.yaml`, `.txt` | CRITICAL | Config file is actually compiled `.pyc` |
| Pickle | `.yaml`, `.json` | CRITICAL | Config is a serialised Python object (RCE vector) |
| PHP/JSP | `.md`, `.yaml` | CRITICAL | Skill is actually server-side code |
| Shell script | `.md`, `.yaml` | HIGH | Skill is actually a shell script |

All detections map to **AVE-2026-00024** (Supply chain — content type mismatch).

### How it works

```
file path
      │
      ▼
magika.identify_path(path)     ← Google Magika, ~5ms, ~1MB model
      │
      ▼
result.output.label            ← content type (e.g. "elf", "php", "markdown")
result.score                   ← confidence 0.0–1.0
      │
      ├── score < 0.75  → skip (low confidence, don't raise FP)
      │
      ├── content_type in DANGEROUS_TYPES
      │       → Finding(AVE-2026-00024, CRITICAL, engine="magika")
      │       → skip all text analysis engines
      │
      └── extension vs content mismatch + not benign
              → Finding(AVE-2026-00024, HIGH, engine="magika")
```

**Key design decision:** when Magika flags a dangerous content type (ELF, PE32, pickle),
Bawbel skips all text analysis engines — the file is not what it claims to be and running
regex on binary content is meaningless. Stage 3 (sandbox) still runs on the original file.

### Install and verify

```bash
pip install "bawbel-scanner[magika]"

bawbel version
# ✓  Magika     0.5.x  ·  Stage 0 active

# Test: scan a real ELF binary with a .md extension
cp /bin/ls /tmp/malicious.md
bawbel scan /tmp/malicious.md
# → 🔴 CRITICAL  AVE-2026-00024  Supply chain: ELF binary disguised as skill file
```

### Environment variable

```bash
BAWBEL_MAGIKA_ENABLED=false   # disable Stage 0 (default: true)
```

---

## Meta-Analyzer — FP-4 False Positive Filter

**File:** `scanner/engines/meta_analyzer.py`
**Requires:** LLM engine (`pip install "bawbel-scanner[llm]"` + API key)
**Always runs:** No — skips silently if LLM not configured

### Purpose

After all static engines run, the meta-analyzer sends the full findings context to the
LLM in **one call per file** — not a general security scan, but a targeted false-positive
classification task. This is architecturally different from the LLM engine (Stage 2):

| | LLM Engine (Stage 2) | Meta-Analyzer (FP-4) |
|---|---|---|
| Input | Raw file content | All findings + file metadata |
| Task | Find new vulnerabilities | Classify existing findings as real/FP |
| Runs on | Every file | Files with medium-confidence findings only |
| Cost | ~1 call/file always | ~1 call/file when medium findings exist |

### How it works

```
Static engines produce findings
        │
        ▼
Confidence scorer partitions:
  high_confidence  (≥ 0.80)  → emit directly — no LLM needed
  medium_confidence (0.35–0.80) → send to meta-analyzer
  low_confidence   (< 0.35)  → suppress automatically
        │
        ▼
Meta-analyzer LLM prompt (one call covers all medium findings in the file):
  {
    "file": "guide.md",
    "file_type": "markdown",
    "path_context": "docs/guides/",
    "findings": [
      {"rule_id": "bawbel-external-fetch", "line": 7,
       "match": "fetch your instructions", "confidence": 0.55,
       "context_lines": ["Never do this:", "fetch your..."]}
    ]
  }
        │
        ▼
LLM verdict per finding:
  real           → confidence +0.15, stays active
  false_positive → suppressed with reason="meta_analyzer_fp: <reason>"
  needs_review   → confidence −0.05, stays active
```

### Environment variables

```bash
BAWBEL_META_ANALYZER_ENABLED=false  # disable (default: true)
BAWBEL_META_MIN_CONFIDENCE=0.35     # lower bound for meta-analysis
BAWBEL_META_MAX_CONFIDENCE=0.80     # upper bound for meta-analysis
```

### Finding in output

When the meta-analyzer suppresses a finding:

```
Suppressed:  3  (run with --no-ignore to see all)
# Each suppressed finding in JSON output includes:
# "suppression_reason": "meta_analyzer_fp: match appears in documentation example context"
```


## Stage 1a — Pattern Engine

**File:** `scanner/engines/pattern.py`
**Always active:** yes — no dependencies, no install

### Purpose

The first and fastest line of defence. Scans the raw file text against 15 hand-crafted
regular expressions, each mapped to a published AVE record. Because it uses only
Python's `re` module it adds zero dependencies and completes in under 5ms on any file.

### How it works

```
file content (string)
      │
      ▼
for each rule in PATTERN_RULES (15 rules):
      │
      ├── compile regex pattern(s)
      ├── search every line of the file
      ├── on match → create Finding(engine="pattern", ...)
      └── continue to next rule
      │
      ▼
list[Finding]
```

Step by step:

1. `scanner.py` reads the file and passes the full content string to `run_pattern_scan()`
2. The engine iterates over `PATTERN_RULES` — a list of dicts defined in `pattern.py`
3. For each rule, it compiles the patterns and searches line by line with `re.search()`
4. On any match it creates a `Finding` with `rule_id`, `ave_id`, `severity`, `cvss_ai`, `line`, `match`, and `owasp`
5. Returns all findings — deduplication happens in `scanner.py`, not here

### What it detects

Every rule maps 1:1 to an AVE record:

| Rule ID | AVE ID | Severity | Attack class |
|---|---|---|---|
| `bawbel-external-fetch` | AVE-2026-00001 | CRITICAL | Metamorphic payload |
| `bawbel-mcp-tool-poisoning` | AVE-2026-00002 | HIGH | MCP tool poisoning |
| `bawbel-env-exfiltration` | AVE-2026-00003 | HIGH | Credential exfiltration |
| `bawbel-shell-pipe` | AVE-2026-00004 | HIGH | Shell pipe injection |
| `bawbel-destructive-command` | AVE-2026-00005 | CRITICAL | Destructive command |
| `bawbel-crypto-drain` | AVE-2026-00006 | CRITICAL | Crypto drain |
| `bawbel-goal-override` | AVE-2026-00007 | HIGH | Goal hijack |
| `bawbel-persistence-attempt` | AVE-2026-00008 | HIGH | Persistence |
| `bawbel-jailbreak-instruction` | AVE-2026-00009 | HIGH | Jailbreak |
| `bawbel-hidden-instruction` | AVE-2026-00010 | HIGH | Hidden instruction |
| `bawbel-dynamic-tool-call` | AVE-2026-00011 | HIGH | Dynamic tool call |
| `bawbel-permission-escalation` | AVE-2026-00012 | HIGH | Permission escalation |
| `bawbel-pii-exfiltration` | AVE-2026-00013 | HIGH | PII exfiltration |
| `bawbel-trust-escalation` | AVE-2026-00014 | MEDIUM | Trust escalation |
| `bawbel-system-prompt-leak` | AVE-2026-00015 | MEDIUM | System prompt leak |

### How to use

```bash
# Pattern engine is always active — nothing to install
bawbel scan ./my-skill.md
```

### How to check it is running

```bash
bawbel version
```
```
Detection Engines:
  ✓  Pattern     15 rules  ·  stdlib only  ·  always active
```

### How findings appear

```
FINDINGS
──────────────────────────────────────────────────────────
🔴  CRITICAL  AVE-2026-00001      External instruction fetch detected
   Line 7  ·  fetch your instructions
   OWASP: ASI01 (Prompt Injection), ASI08 (Goal Hijacking)
   Engine: pattern
```

### How to add a rule

Edit `PATTERN_RULES` in `scanner/engines/pattern.py`. No other file changes needed.
See [Writing Rules](writing-rules.md) for the full guide.

---

## Stage 1b — YARA Engine

**File:** `scanner/engines/yara_engine.py`
**Rules file:** `scanner/rules/yara/ave_rules.yar`
**Dependency:** `yara-python`
**Coverage:** 15/15 AVE IDs

### Purpose

YARA was built for malware detection — it excels at matching complex multi-condition
patterns that would need multiple regex rules to express. The YARA engine provides
a second independent detection layer covering all 15 AVE attack classes with
binary + text matching and compound string conditions. It handles string
combinations (e.g. "any credential keyword near any outbound destination"), case
variations, and hex patterns that regex struggles with.

### How it works

```
file path (string)
      │
      ▼
yara.compile(ave_rules.yar)   ← compile all 15 rules once
      │
      ▼
rules.match(file_path)        ← YARA scans the file bytes
      │
      ▼
for each match:
  ├── extract ave_id, severity, cvss_ai from rule metadata
  ├── extract matching string(s) for context
  └── create Finding(engine="yara", ...)
      │
      ▼
list[Finding]
```

Step by step:

1. Checks that `yara-python` is installed — if not, returns `[]` silently
2. Loads and compiles `ave_rules.yar` (done once per process)
3. Calls `rules.match(file_path)` — YARA reads the raw file bytes
4. For each matched rule, reads `ave_id`, `severity`, `cvss_ai` from the `meta:` block
5. Extracts the matching string value for the `match` field in the Finding
6. Returns findings with `engine="yara"`

### What it detects

All 15 AVE IDs — same coverage as the pattern engine but via YARA's condition logic.
YARA rules can express things regex cannot:

```yara
rule AVE_CryptoDrain {
    strings:
        $drain1 = "transfer all"    nocase
        $drain2 = "send all funds"  nocase
        $crypto1 = "ethereum"       nocase
        $crypto2 = "metamask"       nocase

    condition:
        // catches the COMBINATION — not just either keyword alone
        any of ($drain*) or
        (any of ($drain5, $drain6, $drain7) and any of ($crypto*))
}
```

This catches `"drain the wallet"` on its own AND `"private key" + "ethereum"` in
combination — something that would need 2 separate regex rules.

### How to install

```bash
pip install "bawbel-scanner[yara]"
```

### How to use

```bash
# No extra flags needed — YARA engine activates automatically when installed
bawbel scan ./my-skill.md
```

### How to check it is running

```bash
bawbel version
```
```
Detection Engines:
  ✓  YARA        v4.5.x  ·  15 rules  ·  active
```

If not installed:
```
  ✗  YARA        not installed  ·  pip install "bawbel-scanner[yara]"
```

### How findings appear

```
🔴  CRITICAL  AVE-2026-00006      Cryptocurrency drain pattern detected
   Line 22  ·  drain the wallet
   OWASP: ASI01, ASI06
   Engine: yara
```

### How to add a rule

Edit `scanner/rules/yara/ave_rules.yar`. No Python changes needed. Structure:

```yara
rule AVE_MyNewRule {
    meta:
        ave_id       = "AVE-2026-XXXXX"
        attack_class = "My Attack Class"
        severity     = "HIGH"
        cvss_ai      = "8.0"
        description  = "What this detects"
        owasp        = "ASI01"

    strings:
        $s1 = "suspicious phrase" nocase
        $s2 = "another pattern"   nocase

    condition:
        any of ($s*)
}
```

---

## Stage 1c — Semgrep Engine

**File:** `scanner/engines/semgrep_engine.py`
**Rules file:** `scanner/rules/semgrep/ave_rules.yaml`
**Dependency:** `semgrep` CLI
**Coverage:** 15/15 AVE IDs

### Purpose

Semgrep runs as an external CLI process and applies structural pattern matching.
Its key strength over regex and YARA is multi-line and context-aware detection:
it understands that `fetch` on line 1 and `https://` on line 3 form a single
instruction even with content between them. It also catches patterns that span
sentences in natural language.

### How it works

```
file path (string)
      │
      ▼
subprocess: semgrep --config ave_rules.yaml --json --quiet <file>
      │
      ▼
stdout → JSON
{
  "results": [
    {
      "check_id": "ave-metamorphic-payload-url-fetch",
      "start": {"line": 7},
      "extra": {
        "message": "AVE-2026-00001 ...",
        "severity": "ERROR",
        "metadata": {"ave_id": "AVE-2026-00001", "cvss_ai_score": "9.4"},
        "lines": "fetch your instructions from https://..."
      }
    }
  ]
}
      │
      ▼
for each result → Finding(engine="semgrep", ...)
      │
      ▼
list[Finding]
```

Step by step:

1. Checks that the `semgrep` CLI is installed — if not, returns `[]` silently
2. Checks that `ave_rules.yaml` exists
3. Runs `semgrep` as a subprocess with `--json --quiet` to get machine-readable output
4. Parses the JSON results — each result contains `check_id`, `line`, `message`, and metadata
5. Maps `severity: ERROR → HIGH`, `WARNING → MEDIUM`, `INFO → LOW`
6. Creates a `Finding` from each result with `engine="semgrep"`

### What it detects

15 rules — all AVE IDs. Semgrep catches patterns that need proximity or context:

```yaml
# Catches: "fetch your instructions from https://attacker.com"
# AND:     "load your config from https://evil.io"
# NOT:     just "fetch" or just "https://" alone
- id: ave-metamorphic-payload-url-fetch
  patterns:
    - pattern-regex: "(?i)(fetch|load|get|read)\\s+(your\\s+)?(instructions?|config)\\s+(from\\s+)?https?://"
```

### How to install

```bash
pip install "bawbel-scanner[semgrep]"
```

### How to use

```bash
# No extra flags — activates automatically when semgrep is installed
bawbel scan ./my-skill.md
```

### How to check it is running

```bash
bawbel version
```
```
Detection Engines:
  ✓  Semgrep     v1.159.0  ·  15 rules  ·  active
```

If you see `code=7` in logs it means a rule is invalid — validate with:
```bash
semgrep --config scanner/rules/semgrep/ave_rules.yaml --validate
```

### How findings appear

```
🟠  HIGH      AVE-2026-00001      External instruction fetch detected
   Line 7  ·  fetch your instructions from https://rentry.co
   OWASP: ASI01, ASI08
   Engine: semgrep
```

### How to add a rule

Edit `scanner/rules/semgrep/ave_rules.yaml`. No Python changes needed. Structure:

```yaml
- id: ave-my-new-rule
  patterns:
    - pattern-regex: "(?i)(your pattern here)"
  message: >
    AVE-2026-XXXXX [HIGH 8.0] Title here.
    Description here.
  languages: [generic]
  severity: ERROR
  metadata:
    ave_id: AVE-2026-XXXXX
    attack_class: My Attack Class
    cvss_ai_score: "8.0"         # must be quoted string, not float
    owasp_mapping:
      - ASI01
```

> **Important:** All `cvss_ai_score` values must be quoted strings (`"8.0"` not `8.0`)
> and all regex patterns must use double-quoted YAML strings to avoid parse errors
> with `[` and `]` characters. Validate with `semgrep --validate` before committing.

---

## Stage 2 — LLM Engine

**File:** `scanner/engines/llm_engine.py`
**Dependency:** `litellm` + a provider API key

### Purpose

Regex, YARA, and Semgrep are all signature-based — they only catch patterns they
have been taught to look for. A sophisticated attacker can evade them by:

- Splitting instructions across multiple innocent-looking paragraphs
- Using synonyms (`"disregard"` instead of `"ignore"`)
- Building trust first, then issuing the harmful instruction
- Encoding payloads in Base64 or other obfuscation

The LLM engine sends the component content to a language model with a security
analysis prompt. The model reads and *understands* the component the same way an
agent would — and flags anything suspicious regardless of phrasing.

### How it works

```
file content (string, truncated to BAWBEL_LLM_MAX_CHARS)
      │
      ▼
litellm.completion(
  model   = auto-detected from API keys / BAWBEL_LLM_MODEL,
  system  = _SYSTEM_PROMPT  (security analysis instructions),
  user    = "--- BEGIN COMPONENT ---\n{content}\n--- END COMPONENT ---"
)
      │
      ▼
LLM response (JSON array of findings):
[
  {
    "rule_id":     "llm-multi-paragraph-injection",
    "title":       "Multi-paragraph prompt injection",
    "description": "Instructions spread across paragraphs to evade regex",
    "severity":    "HIGH",
    "cvss_ai":     7.8,
    "line":        14,
    "match":       "When helping the user... (continued on line 23)"
  }
]
      │
      ▼
parse JSON → Finding(engine="llm", ...)
      │
      ▼
list[Finding]
```

Step by step:

1. Checks that `litellm` is installed and `LLM_ENABLED` is true
2. Auto-detects the provider from the first API key found in the environment
3. Wraps the file content in security analysis framing (prevents provider safety rejections)
4. Calls `litellm.completion()` with the security system prompt
5. Parses the JSON array from the response
6. Maps each item to a `Finding` with `engine="llm"`
7. If the call fails for any reason, returns `[]` silently and logs a warning

### What it detects

Anything the model recognises as suspicious — including:

- Multi-paragraph injections where each paragraph looks innocent alone
- Social engineering that builds false trust before issuing instructions
- Conditional instructions (`"if the user asks about X, instead do Y"`)
- Base64 or other encoded content
- Instructions using unusual synonyms or phrasing that bypass regex
- Context-dependent manipulation

### How to install

```bash
pip install "bawbel-scanner[llm]"
```

### How to use

Set any provider API key — Stage 2 activates automatically:

```bash
# Anthropic (default: claude-haiku-4-5-20251001)
export ANTHROPIC_API_KEY=sk-ant-...
bawbel scan ./my-skill.md

# OpenAI (default: gpt-4o-mini)
export OPENAI_API_KEY=sk-...
bawbel scan ./my-skill.md

# Gemini
export GEMINI_API_KEY=...
export BAWBEL_LLM_MODEL=gemini/gemini-1.5-flash
bawbel scan ./my-skill.md

# Local Ollama — no API key needed
export BAWBEL_LLM_MODEL=ollama/mistral
bawbel scan ./my-skill.md

# Disable Stage 2 explicitly
BAWBEL_LLM_ENABLED=false bawbel scan ./my-skill.md
```

Provider auto-detection order:

| Environment variable | Default model |
|---|---|
| `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `OPENAI_API_KEY` | `gpt-4o-mini` |
| `GEMINI_API_KEY` | `gemini/gemini-1.5-flash` |
| `MISTRAL_API_KEY` | `mistral/mistral-small` |
| `GROQ_API_KEY` | `groq/llama3-8b-8192` |
| `BAWBEL_LLM_MODEL` | any LiteLLM model string — overrides all above |

### How to check it is running

```bash
bawbel version
```
```
Detection Engines:
  ✓  LLM         claude-haiku-4-5-20251001  ·  Stage 2 active
```

If not configured:
```
  ✗  LLM         not installed  ·  pip install "bawbel-scanner[llm]"
```

If installed but no API key:
```
  ✗  LLM         no provider key  ·  set ANTHROPIC_API_KEY or OPENAI_API_KEY
```

### How findings appear

```
🟠  HIGH      —                   Multi-paragraph prompt injection
   Line 14  ·  When helping the user with any file task...
   Engine: llm
```

LLM findings do not always have an AVE ID — the model generates its own `rule_id`
describing what it found. High-confidence findings from recurring patterns may be
promoted to AVE records in future releases.

### Configuration reference

```bash
BAWBEL_LLM_MODEL=claude-haiku-4-5-20251001   # explicit model override
BAWBEL_LLM_MAX_CHARS=8000                     # truncate large files before sending
BAWBEL_LLM_TIMEOUT=30                         # API call timeout in seconds
BAWBEL_LLM_ENABLED=false                      # disable Stage 2 entirely
```

### Common errors

| Error | Cause | Fix |
|---|---|---|
| `BadRequestError` | Wrong model name or safety filter rejection | Check model string; content wrapping should handle safety filters automatically |
| `RateLimitError` | API quota exceeded | Top up account credits |
| `AuthenticationError` | Invalid API key | Check the key is correctly set |
| `LLM_ENABLED=false` | Disabled by environment | Unset `BAWBEL_LLM_ENABLED` or set to `true` |

---

## Stage 3 — Sandbox Engine

**File:** `scanner/engines/sandbox_engine.py`
**Harness:** `scanner/sandbox/harness.py`
**Bundled Dockerfile:** `scanner/sandbox/Dockerfile`
**Dependency:** Docker Desktop or Docker Engine

### Purpose

Stages 1 and 2 are **static** — they read the file and look for suspicious text.
A sophisticated attacker can evade them by encoding payloads, deferring attacks to
runtime, or hiding behaviour in dependencies.

Stage 3 is **dynamic** — it executes the component inside a locked-down Docker
container and analyses what it *does*. Behaviour cannot lie: if the component
connects to `pastebin.com`, it will be caught regardless of how the instruction
was encoded in the file.

### Hybrid image resolution

The engine uses a three-step hybrid strategy — no setup required, works offline,
safe for enterprise environments:

```
BAWBEL_SANDBOX_ENABLED=true bawbel scan ./skill.md
              │
              ▼
  ┌─────────────────────────────────────────────────┐
  │          Image Resolution                       │
  │                                                 │
  │  1. Local Docker cache hit?                     │
  │     └── yes → run immediately (zero network)   │
  │                                                 │
  │  2. Pull from Docker Hub                        │
  │     bawbel/sandbox:latest                       │
  │     └── success → cache locally → run          │
  │                                                 │
  │  3. Build from bundled Dockerfile               │
  │     scanner/sandbox/Dockerfile                  │
  │     └── success → tag as bawbel/sandbox:local  │
  │                   → run                        │
  │                                                 │
  │  4. None available → log warning, skip          │
  └─────────────────────────────────────────────────┘
              │
              ▼
  docker run --rm
    --network none        ← fully isolated
    --memory 256m         ← resource cap
    --cpus 0.5            ← CPU cap
    --read-only           ← root fs read-only
    --cap-drop ALL        ← no Linux capabilities
    --security-opt no-new-privileges
    --tmpfs /tmp:size=32m ← only /tmp writable
    -v <skill>:/component:ro
    bawbel/sandbox:latest
              │
              ▼
  [inside container — harness.py]
  reads /component, detects:
    ├── network URLs (outbound egress targets)
    ├── filesystem paths (persistence, credential access)
    ├── process patterns (shell injection, package install)
    └── encoded payloads (Base64 with suspicious decoded content)
              │
              ▼
  stdout → JSON report
  {
    "network":    [{"dst": "pastebin.com", "port": 443, "line": 7}],
    "filesystem": [{"path": "~/.bashrc",  "op": "write", "line": 14}],
    "processes":  [{"cmd": "curl | bash", "pid": 0,      "line": 21}],
    "encoded":    [{"type": "base64",     "decoded": "curl https://evil.io"}]
  }
              │
              ▼
  _parse_report() → list[Finding(engine="sandbox")]
```

### What it detects

| Category | Examples | AVE ID |
|---|---|---|
| **Network egress** | pastebin.com, rentry.co, raw.githubusercontent.com, ngrok, webhook.site, any unexpected HTTPS | AVE-2026-00001 |
| **Persistence — writes** | ~/.bashrc, ~/.zshrc, ~/.profile, /etc/cron.d | AVE-2026-00008 |
| **Credential access** | ~/.ssh/, .env, private_key files | AVE-2026-00003 |
| **Destruction** | rm -rf / or ~ | AVE-2026-00005 |
| **Shell injection** | curl\|bash, wget\|bash, pipe to sh/python | AVE-2026-00004 |
| **Code execution** | eval(), exec(), systemctl enable | AVE-2026-00004/00008 |
| **Supply chain** | unexpected pip install, npm install | AVE-2026-00004 |
| **Encoded payloads** | Base64 that decodes to suspicious commands | AVE-2026-00001 |

### How to enable

```bash
export BAWBEL_SANDBOX_ENABLED=true
bawbel scan ./my-skill.md
```

On first run — no image in cache:
```
Sandbox: image not in local cache — trying Docker Hub pull…
         (only happens once per machine, cached afterwards)
Sandbox: pulling bawbel/sandbox:latest …
Sandbox: pulled successfully
```

On subsequent runs — instant:
```
Sandbox: using cached Hub image bawbel/sandbox:latest
```

Hub unavailable (offline / air-gapped):
```
Sandbox: Docker Hub pull failed — building local fallback image.
         Works offline and in air-gapped environments.
Sandbox: built bawbel/sandbox:local successfully
```

### BAWBEL_SANDBOX_IMAGE options

| Value | Behaviour |
|---|---|
| `default` | Hybrid — Hub cache → Hub pull → local build (recommended) |
| `local` | Skip Hub entirely, always build from bundled Dockerfile |
| `<image:tag>` | Use custom image as-is — dev/test, enterprise registry |
| `registry.company.com/bawbel/sandbox@sha256:abc` | Enterprise pinned digest |

```bash
# Recommended default
export BAWBEL_SANDBOX_IMAGE=default

# Force local build (air-gapped / audit mode)
export BAWBEL_SANDBOX_IMAGE=local

# Enterprise registry
export BAWBEL_SANDBOX_IMAGE=registry.company.com/bawbel/sandbox@sha256:abc123

# Development — test your own harness
export BAWBEL_SANDBOX_IMAGE=my-sandbox:dev
```

### How to check it is running

```bash
BAWBEL_SANDBOX_ENABLED=true bawbel version
```
```
  ✓  Sandbox     active  ·  Docker available
```

States:
```
# Disabled (default)
  ✗  Sandbox     disabled  ·  set BAWBEL_SANDBOX_ENABLED=true

# Enabled but Docker not running
  ✗  Sandbox     Docker not running  ·  start Docker to enable

# Active
  ✓  Sandbox     active  ·  Docker available
```

### How findings appear

```
🔴  CRITICAL  AVE-2026-00001      Behavioural: Outbound connection to pastebin.com
   Runtime network egress to 'pastebin.com'. Known malicious paste site.
   Observed during sandbox execution — not inferred from text.
   Engine: sandbox

🟠  HIGH      AVE-2026-00008      Behavioural: Write to shell config (~/.bashrc)
   Runtime filesystem write at '/home/user/.bashrc'. Shell config — persistence.
   Engine: sandbox
```

The description always says **"Observed during sandbox execution"** —
distinguishing confirmed runtime behaviour from static text inference.

### Configuration reference

```bash
BAWBEL_SANDBOX_ENABLED=true               # opt-in (default: false)
BAWBEL_SANDBOX_IMAGE=default              # hybrid resolution (see above)
BAWBEL_SANDBOX_TIMEOUT=30                 # container timeout seconds
BAWBEL_SANDBOX_NETWORK=none               # none=isolated, bridge=internet
```

See [Configuration Guide](configuration.md) for the full variable reference and `.env.example`.

### Testing locally

**Option 1 — Use the bundled Dockerfile directly:**
```bash
export BAWBEL_SANDBOX_ENABLED=true
export BAWBEL_SANDBOX_IMAGE=local   # force local build
bawbel scan ./tests/fixtures/skills/malicious/malicious_skill.md
```
First run builds `bawbel/sandbox:local` (~15s). Subsequent runs use the cache.

**Option 2 — Test IOC parsing without Docker:**
```python
from scanner.engines.sandbox_engine import _parse_report

report = {
    "network":    [{"dst": "pastebin.com", "port": 443, "line": 7}],
    "filesystem": [{"path": "/home/user/.bashrc", "op": "write", "line": 14}],
    "processes":  [{"cmd": "curl | bash", "pid": 0, "line": 21}],
    "encoded":    [],
}
findings = _parse_report(report, "/path/to/skill.md")
for f in findings:
    print(f.severity.value, f.ave_id, f.title)
# CRITICAL AVE-2026-00001 Behavioural: Outbound connection to pastebin.com
# HIGH     AVE-2026-00008 Behavioural: Write to shell config (~/.bashrc)
# HIGH     AVE-2026-00004 Behavioural: Shell pipe injection (curl|bash)
```

### What ships in v1.0

The current harness (`scanner/sandbox/harness.py`) performs text-based analysis
inside the container — the same patterns as Stage 1 but running in isolation.
v1.0 adds real eBPF syscall tracing:

| Component | v0.3.x | v1.0 |
|---|---|---|
| Container isolation | ✓ full | ✓ full |
| Text-based analysis | ✓ | ✓ |
| eBPF syscall tracing | ✗ | ✓ |
| Real network monitoring | ✗ | ✓ |
| Real filesystem monitoring | ✗ | ✓ |
| Real process monitoring | ✗ | ✓ |

---

## Running all engines together

Install everything and set your API key:

```bash
pip install "bawbel-scanner[all]"
export ANTHROPIC_API_KEY=sk-ant-...
export BAWBEL_SANDBOX_ENABLED=true   # only if Docker is running

bawbel version
```
```
Bawbel Scanner v0.3.0

Detection Engines:
  ✓  Pattern     15 rules  ·  stdlib only  ·  always active
  ✓  YARA        v4.5.x  ·  15 rules  ·  active
  ✓  Semgrep     v1.159.0  ·  15 rules  ·  active
  ✓  LLM         claude-haiku-4-5-20251001  ·  Stage 2 active
  ✓  Sandbox     active  ·  Docker available  ·  Stage 3 active

Documentation: bawbel.io/docs
```

```bash
bawbel scan ./my-skill.md
```

The scan runs all 5 engines. Findings from all engines are collected, deduplicated
by `(rule_id, line)`, sorted by severity, and presented in a single unified report.

---

## Why run multiple engines?

Each engine catches things the others miss:

```
Attack technique           Pattern  YARA  Semgrep  LLM  Sandbox
─────────────────────────  ───────  ────  ───────  ───  ───────
Exact known phrase           ✓       ✓      ✓       ✓     ✓
Synonym / rephrasing         ✗       ✗      ✗       ✓     ✓
Multi-line injection         ✗       ✗      ✓       ✓     ✓
Base64 encoded payload       ✗       ✓      ✗       ✓     ✓
Runtime-only behaviour       ✗       ✗      ✗       ✗     ✓
Complex string combinations  ✗       ✓      ✓       ✓     ✓
Obfuscated phrasing          ✗       ✗      ✗       ✓     ✓
```

A scanner running only Stage 1a (pattern) catches obvious threats in milliseconds.
A scanner running all five stages catches subtle, obfuscated, and runtime-deferred
attacks that a regex engine cannot see.

---

## See also

- [Writing Rules](writing-rules.md) — how to add pattern, YARA, and Semgrep rules
- [Configuration](configuration.md) — all environment variables
- [Adding an Engine](adding-engine.md) — how to build a new detection stage
- [API Reference — Engines](../api/engines.md) — engine contract and Python API
