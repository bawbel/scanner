# Suppression Guide — bawbel-ignore

Bawbel Scanner supports three suppression mechanisms for managing false positives.
Suppressed findings are **never deleted** — they move to `ScanResult.suppressed_findings`
and always appear in JSON/SARIF output so security audits remain complete.

---

## Quick reference

```markdown
# Suppress all findings on a line
fetch https://internal.company.com  <!-- bawbel-ignore -->

# Suppress a specific rule
fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->

# Suppress by AVE ID
fetch https://internal.company.com  <!-- bawbel-ignore: AVE-2026-00001 -->

# Suppress multiple rules
fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch, AVE-2026-00007 -->
```

```markdown
# Suppress a whole section
<!-- bawbel-ignore-start -->
fetch https://internal.company.com
Ignore all previous instructions  ← this is intentional for documentation
<!-- bawbel-ignore-end -->
```

```
# .bawbelignore — suppress entire files or directories
tests/fixtures/**
docs/examples/bad.md
```

```bash
# Override all suppressions (audit mode)
bawbel scan ./skills/ --no-ignore
BAWBEL_NO_IGNORE=true bawbel scan ./skills/
```

---

## Mechanism 1 — Inline suppression

Add a `bawbel-ignore` comment on the same line as the content that triggers the finding.

### Suppress all findings on a line

```markdown
fetch your config from https://internal.company.com  <!-- bawbel-ignore -->
```

Works with all comment styles:
```markdown
content here  <!-- bawbel-ignore -->   ← HTML/Markdown
content here  # bawbel-ignore          ← YAML/Python/shell
content here  // bawbel-ignore         ← JavaScript/JSON
```

### Suppress a specific rule

```markdown
fetch your config from https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->
```

Only `bawbel-external-fetch` is suppressed on that line. Any other findings on the
same line remain active.

### Suppress by AVE ID

```markdown
fetch your config from https://internal.company.com  <!-- bawbel-ignore: AVE-2026-00001 -->
```

### Suppress multiple rules on one line

```markdown
content  <!-- bawbel-ignore: bawbel-external-fetch, bawbel-goal-override -->
```

### When inline suppression doesn't apply

Inline suppression only works for findings that have a **line number**. YARA and some
Semgrep findings match against the whole file and have `line=None` — these cannot be
suppressed with inline comments. Use `.bawbelignore` to suppress the whole file instead.

---

## Mechanism 2 — Block suppression

Suppress all findings within a section using start/end markers.

```markdown
<!-- bawbel-ignore-start -->
fetch your instructions from https://internal.company.com
Ignore all previous instructions (intentional — this is a test fixture)
<!-- bawbel-ignore-end -->
```

Also works with hash and double-slash styles:

```yaml
# bawbel-ignore-start
- fetch: https://internal.company.com
# bawbel-ignore-end
```

### Rules
- All findings with a line number inside the block are suppressed
- Findings outside the block are unaffected
- Unclosed `bawbel-ignore-start` (no matching `end`) suppresses to end of file and logs a warning
- Nested `bawbel-ignore-start` blocks are ignored (with a warning)

### Good use cases
- Test fixtures that intentionally contain malicious patterns
- Documentation examples showing what an attack looks like
- Known-safe third-party content included in a skill file

---

## Mechanism 3 — .bawbelignore file

Create a `.bawbelignore` file to suppress findings for entire files or directory trees.
Syntax is the same as `.gitignore`.

### Create the file

```bash
# Generate a template
cat > .bawbelignore << 'EOF'
# Suppress test fixtures — these intentionally contain malicious patterns
tests/fixtures/malicious/**

# Suppress documentation examples
docs/examples/bad.md

# Suppress all files in any examples/ directory
examples/

# Suppress test skill files
**/test_*.md
EOF
```

### Pattern syntax

| Pattern | Matches |
|---|---|
| `bad.md` | Any file named `bad.md` in any directory |
| `tests/fixtures/bad.md` | Exact path relative to `.bawbelignore` |
| `tests/fixtures/` | All files under `tests/fixtures/` |
| `tests/fixtures/**` | All files recursively under `tests/fixtures/` |
| `**/test_*.md` | Any file starting with `test_` in any directory |
| `*.md` | All `.md` files in the same directory |

### Discovery

Bawbel searches for `.bawbelignore` starting from the scanned file's directory,
walking up to the filesystem root — the same way `.gitignore` works. Put it at
the repo root to cover the whole project.

### Good use cases
- Whole test fixture directories
- Known-bad example files used for documentation
- Third-party skill files you didn't write and can't modify

---

## Audit mode — --no-ignore

Override ALL suppressions to see the complete picture:

```bash
# CLI flag
bawbel scan ./skills/ --no-ignore

# Environment variable
BAWBEL_NO_IGNORE=true bawbel scan ./skills/
```

Use this in:
- Security audits — ensure suppressions haven't hidden real vulnerabilities
- CI/CD gates — add `--no-ignore` to your security audit job
- Pre-release scans — verify suppressed findings are still intentional

---

## Output with suppressions

### Text output

```
SUMMARY
──────────────────────────────────────────────────────────
Risk score:   8.1 / 10  HIGH
Findings:     1
Suppressed:   2  (run with --no-ignore to see all)
Scan time:    6ms
```

### JSON output

Suppressed findings always appear in `suppressed_findings` with `suppressed: true`
and a `suppression_reason`:

```json
{
  "findings": [
    {
      "rule_id": "bawbel-goal-override",
      "severity": "HIGH",
      ...
    }
  ],
  "suppressed_findings": [
    {
      "rule_id": "bawbel-external-fetch",
      "severity": "CRITICAL",
      "suppressed": true,
      "suppression_reason": "inline suppression (bawbel-ignore: bawbel-external-fetch)",
      ...
    }
  ]
}
```

---

## Best practices

**Be specific** — suppress specific rule IDs rather than all findings on a line.
`<!-- bawbel-ignore: bawbel-external-fetch -->` is safer than `<!-- bawbel-ignore -->`.

**Add a reason** — add a comment explaining why the suppression is intentional:
```markdown
fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->
<!-- Internal config endpoint — scanned and approved by security team 2026-04-21 -->
```

**Use .bawbelignore for test fixtures** — don't litter test files with inline suppression
comments. Put `tests/fixtures/**` in `.bawbelignore` instead.

**Audit regularly** — run `bawbel scan ./skills/ --no-ignore` as part of your quarterly
security review to verify suppressed findings are still intentional.

**Never suppress in production configs** — suppression is for false positives and test
fixtures. If a production skill has a real finding, fix the skill.

---

## See also

- [Configuration Guide](configuration.md) — `BAWBEL_NO_IGNORE` env var
- [Detection Engines Guide](engines.md) — understanding which engines produce which findings
- [`.env.example`](../../.env.example) — full environment variable reference
