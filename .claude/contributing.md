# Contributing — Bawbel Scanner

## Branching

```
main        ← production, protected, requires PR + 1 approval
develop     ← integration branch, protected, requires PR
```

| Branch prefix | Use case | Example |
|---|---|---|
| `feat/` | New feature or detection engine | `feat/stage2-llm-analysis` |
| `rule/` | New YARA or Semgrep rule | `rule/ave-00003-env-exfil` |
| `fix/` | Bug fix | `fix/semgrep-timeout-handling` |
| `test/` | Tests only | `test/false-positive-regression` |
| `docs/` | Documentation only | `docs/update-architecture` |
| `chore/` | Deps, CI, tooling | `chore/bump-yara-python` |
| `hotfix/` | Urgent production fix | `hotfix/critical-false-negative` |

Always branch from `develop`. Target `develop` in your PR.
Only `develop → main` merges go directly to production.

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:**
- `feat` — new feature
- `fix` — bug fix
- `rule` — new or updated detection rule
- `test` — tests only
- `docs` — documentation only
- `refactor` — code change, no behaviour change
- `perf` — performance improvement
- `chore` — deps, CI, tooling
- `security` — security fix (add `!` for breaking: `security!`)

**Examples:**
```
feat(scanner): add Stage 2 LLM semantic analysis

rule(yara): add AVE-2026-00003 env exfiltration detection

fix(cli): handle UnicodeDecodeError on binary files

security(scanner): enforce 10MB file size limit

chore(deps): bump semgrep to 1.65.0
```

**Rules:**
- Subject line max 72 chars
- Use imperative mood: "add" not "added", "fix" not "fixed"
- No period at end of subject line
- Reference AVE IDs in rule commits: `rule: add AVE-2026-00003`

---

## Pull Request Checklist

Before opening a PR, verify:

```
Code quality
[ ] Runs without errors in clean venv
[ ] flake8 scanner/ cli.py --max-line-length 100 passes
[ ] No print() statements — use rich console
[ ] No hardcoded secrets or API keys

Tests
[ ] bawbel scan tests/fixtures/skills/malicious/malicious_skill.md → still 2 findings, CRITICAL 9.4
[ ] New rules have positive and negative fixture tests
[ ] python -m pytest tests/ -v passes

Security (for any file I/O or subprocess change)
[ ] Read .claude/security.md — all rules followed
[ ] subprocess.run uses list args, never shell=True
[ ] File reads use Path().resolve() and errors="ignore"
[ ] New LLM prompts follow hardening guidelines

Documentation
[ ] CLAUDE.md updated if architecture changed
[ ] .claude/architecture.md updated if new engine added
[ ] Inline comments for non-obvious logic
[ ] YARA/Semgrep rules have complete meta: blocks
```

---

## PR Size Guidelines

| PR type | Max files changed | Max lines changed |
|---|---|---|
| Bug fix | 5 | 50 |
| New rule | 3 | 100 |
| New feature | 15 | 500 |
| Refactor | 10 | 300 |

Large PRs are hard to review. Split them.

---

## Code Style

Python style: PEP 8 + these project-specific rules:

```python
# Alignment — use spaces to align related assignments
file_path      = "..."
component_type = "skill"
scan_time_ms   = 0

# Type hints — required on all public functions
def scan(file_path: str) -> ScanResult:

# Docstrings — required on all public functions
def scan(file_path: str) -> ScanResult:
    """
    Scan an agentic AI component for AVE vulnerabilities.

    Args:
        file_path: Path to the component file to scan

    Returns:
        ScanResult with all findings, severity, and risk score
    """

# Constants — SCREAMING_SNAKE_CASE at module level
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Private functions — prefix with _
def _parse_semgrep_output(raw: str) -> list[dict]:
```

---

## Review Standards

When reviewing PRs:

**Always check:**
- New rules have both positive and negative test fixtures
- No `shell=True` in subprocess calls
- No hardcoded values that should be constants or config
- `scan()` still never raises

**Security PRs:** Require 2 approvals, not 1.

**Rule PRs:** Require the reviewer to run the test fixture locally.

---

## Dependency Updates

Quarterly dependency update process:

```bash
# Check for vulnerabilities
pip-audit -r requirements.txt

# Check for updates
pip list --outdated

# Update one at a time
pip install "package>=new.version"
pip freeze > requirements.txt

# Run full test suite
python -m pytest tests/ -v

# Run golden fixture
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
```

Never bulk-update all dependencies in one commit.
