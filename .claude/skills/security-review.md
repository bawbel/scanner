---
name: security-review
description: >
  Run this when asked to do a security review, audit code, or check for
  security issues. Triggers: "security review", "audit this", "is this secure",
  "check for vulnerabilities".
---

# Security Review

Human guide: `docs/guides/` — do not duplicate it here.
This file is AI execution instructions only.

---

## Execute in this exact order

### 1. Automated tools — all must pass before anything else

```bash
source .venv/bin/activate
bandit -r scanner/ cli.py config/ -f screen   # must be: 0 High, 0 Medium, 0 Low
pip-audit -r requirements.txt                 # must be: No known vulnerabilities
python -m pytest tests/ -q                    # must be: all pass
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# must be: 2 findings, Risk 9.4, CRITICAL
```

Stop here if any check fails. Fix before continuing.

### 2. Information exposure — run each grep, every result is a finding

```bash
# Raw exception detail reaching user
grep -rn "str(e)\b\|repr(e)\b\|detail=e\b" scanner/ cli.py config/

# Absolute internal paths in user messages
grep -rn "RULES_DIR\|__file__\|PACKAGE_ROOT" scanner/messages.py

# Stack traces exposed
grep -rn "traceback\|print_exc\|format_exc" scanner/ cli.py

# File content or match text in WARNING/ERROR logs
grep -rn "log\.warning.*content\|log\.error.*content\|log\.warning.*match\b" scanner/

# Exception message (not type) in logs
grep -rn "log\.\(warning\|error\|critical\)(.*str(e)" scanner/
```

### 3. Manual checklist — tick each line

```
File I/O
[x] All file reads use read_file_safe() — never open() directly
[x] All paths go through resolve_path() then is_safe_path()
[x] Symlink checked on RAW path before resolve() — not after
[x] MAX_FILE_SIZE_BYTES enforced before reading

Subprocess
[x] All subprocess calls use run_subprocess() from utils.py
[x] No shell=True anywhere in codebase
[x] No user input interpolated into command args

Error messages
[x] Every error uses Errors.* constant from scanner/messages.py
[x] No error string contains str(e), repr(e), or exception message
[x] No error string contains absolute path — path.name (basename) only
[x] Every error has a stable E-code (E001–E020)

Logging
[x] WARNING/ERROR uses type(e).__name__ — never str(e)
[x] No file content, match strings, or API keys in any log call
[x] Full exception detail only at DEBUG level

Secrets
[x] No hardcoded API keys, tokens, or passwords anywhere
[x] Secrets loaded from os.environ only

Docker
[x] Dockerfile runs as non-root user bawbel
[x] docker-compose mounts scan volume as :ro (read-only)
[x] no-new-privileges:true in security_opt
```

### 4. Report each finding in this format

```
FINDING: <title>
FILE:     <file>:<line>
SEVERITY: HIGH | MEDIUM | LOW
ISSUE:    <what is wrong>
FIX:      <exact change needed>
BEFORE:   <current code>
AFTER:    <corrected code>
```

### 5. After fixing — re-run all checks from step 1

All five commands must pass clean before the review is complete.
