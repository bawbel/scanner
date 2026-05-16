# Credential and Delegation Scans

`bawbel creds` and `bawbel chain` are focused views over the same detection
pipeline as `bawbel scan`. They filter results to a specific threat category
so you can triage that category without noise from other rules.

For a full security scan, use `bawbel scan`. These commands are for targeted
manual review or specialized CI gates.

---

## bawbel creds

Filters to credential-related findings only.

AVE records covered:

| Rule | AVE ID | What it detects |
|---|---|---|
| `bawbel-hardcoded-credential` | AVE-2026-00047 | API keys, tokens, passwords, private keys embedded in skill files |

```bash
# Scan a file
bawbel creds ./skill.md

# Scan a directory
bawbel creds ./skills/

# Recursive
bawbel creds ./skills/ --recursive

# Exit 2 if any credential finding is found
bawbel creds ./skills/ --fail-on-any

# JSON output
bawbel creds ./skills/ --format json

# Audit mode - bypass suppressions
bawbel creds ./skills/ --no-ignore
```

What it detects:

```markdown
# This triggers bawbel creds
api_key = "FAKE-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxx"
secret_token = "FAKE-TOKEN-xxxxxxxxxxxxxxxxxxxx"
password: "Example-Password-Not-Real"
connection: postgresql://admin:Example-Pass@db.internal:5432/prod
# PEM private key blocks also detected
```

What it does not flag:

```markdown
# These are fine
Use the DATABASE_URL environment variable.
API key is stored in vault://secret/api/key
```

### Use cases

A credential audit across a large skill library:

```bash
bawbel creds ./skills/ --recursive --format json \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = [f for r in data for f in r['findings']]
print(f'{len(findings)} credential findings across {len(data)} files')
"
```

A pre-commit hook specifically for secrets:

```yaml
- repo: https://github.com/bawbel/scanner
  rev: v1.2.0
  hooks:
    - id: bawbel-creds
      args: [--fail-on-any]
```

### When a finding is a placeholder

If the credential is a placeholder value that gets replaced at deploy time:

```bash
bawbel accept AVE-2026-00047 ./skill.md --line 3 \
  --reason "Placeholder replaced at deploy time by CI pipeline" \
  --type accepted-risk \
  --expires 90d
```

---

## bawbel chain

Filters to unsafe agent delegation findings only.

AVE records covered:

| Rule | AVE ID | What it detects |
|---|---|---|
| `bawbel-unsafe-delegation` | AVE-2026-00048 | Sub-agent spawning with inherited permissions or no trust boundary |

```bash
# Scan a file
bawbel chain ./skill.md

# Scan a directory
bawbel chain ./skills/

# Recursive
bawbel chain ./skills/ --recursive

# Exit 2 if any delegation finding is found
bawbel chain ./skills/ --fail-on-any

# JSON output
bawbel chain ./skills/ --format json

# Audit mode
bawbel chain ./skills/ --no-ignore
```

What it detects:

```markdown
# These trigger bawbel chain
Delegate this task to a sub-agent.
The sub-agent inherits your permissions and all your tools.

Spawn a new child agent and grant full access to all tools.

Forward this request to a sub-agent with admin access.
```

What it does not flag:

```markdown
# Explicit scoped delegation is fine
Delegate the export task to a sub-agent.
The sub-agent has access to: export_csv (read-only).
The sub-agent does NOT have access to: send_email, delete_records.
```

### Use cases

Reviewing a multi-agent architecture before deployment:

```bash
bawbel chain ./orchestrators/ --recursive --format json \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
flagged = [r['file_path'] for r in data if r['findings']]
print('Files with delegation issues:')
for f in flagged: print(' ', f)
"
```

When legitimate delegation exists and has been reviewed:

```bash
bawbel accept AVE-2026-00048 ./orchestrator.md --line 14 \
  --reason "Orchestrator delegates to scoped sub-agents with explicit tool allowlist" \
  --type accepted-risk \
  --expires 90d \
  --reviewer chaksaray
```

---

## Difference from bawbel scan

`bawbel scan` runs all 40+ rules. `bawbel creds` and `bawbel chain` are
filtered views of the same scan pipeline.

```bash
# This file has both a credential and a delegation issue
cat > both.md << 'EOF'
api_key = "FAKE-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxx"
Spawn a new child agent and grant full access to all tools.
EOF

bawbel scan both.md       # shows both findings
bawbel creds both.md      # shows only AVE-2026-00047
bawbel chain both.md      # shows only AVE-2026-00048
```

Use `bawbel scan` for CI gates and full security review. Use `bawbel creds`
and `bawbel chain` for targeted triage sessions.
