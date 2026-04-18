# Contributing to Bawbel Scanner

Thank you for helping make agentic AI safer. Every contribution matters.

---

## Ways to Contribute

| Type | What it means |
|---|---|
| **New detection rule** | Add a pattern, YARA, or Semgrep rule to catch a new attack class |
| **False positive fix** | A rule is firing on legitimate content — fix the regex |
| **AVE record** | Research and document a new agentic vulnerability |
| **Bug report** | Something is broken — open an issue |
| **Documentation** | Fix a typo, clarify an explanation, add an example |
| **Code improvement** | Refactor, performance, security hardening |

---

## Before You Start

1. **Check existing issues** — your idea may already be tracked
2. **Open an issue first** for significant changes — get alignment before writing code
3. **Read the security rules** in `.claude/security.md` — this is a security tool and must not be exploitable

---

## Quick Setup

```bash
git clone https://github.com/bawbel/bawbel-scanner
cd bawbel-scanner
./scripts/setup.sh --dev
source .venv/bin/activate
```

See `docs/guides/getting-started.md` for full setup instructions.

---

## Adding a Detection Rule

This is the most impactful contribution. Full guide in `docs/guides/writing-rules.md`.

Quick checklist:

```
[ ] Add rule to PATTERN_RULES in scanner/engines/pattern.py
[ ] Add remediation text to REMEDIATION_GUIDE in scanner/cli.py
[ ] Add positive test fixture (content that triggers the rule)
[ ] Add negative test fixture (similar but innocent content)
[ ] Write pytest tests — positive AND negative
[ ] Run: python -m pytest tests/ -v        (must pass)
[ ] Run: bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
         (must still show 2 findings, CRITICAL 9.4)
[ ] Run: bandit -r scanner/ -f screen      (must be 0 issues)
```

---

## Pull Request Process

1. **Fork** the repository
2. **Branch** from `develop` — never from `main`
   ```bash
   git checkout develop
   git checkout -b rule/your-rule-name   # or feat/, fix/, docs/
   ```
3. **Make your changes** following the code style below
4. **Run the full checklist** before opening the PR
5. **Open a PR** targeting `develop` — fill in the description template

### Full pre-PR checklist

```bash
# Tests — must be 100%
python -m pytest tests/ -v

# Golden fixture — must always show 2 findings, CRITICAL 9.4
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md

# Security — must be 0 issues
bandit -r scanner/ -f screen

# Lint — must be clean
flake8 scanner/ --max-line-length 100

# Format
black --check --line-length 100 scanner/
```

---

## Branch Naming

| Branch | Use case |
|---|---|
| `feat/description` | New feature or detection engine |
| `rule/ave-NNNNN-description` | New detection rule |
| `fix/description` | Bug fix |
| `docs/description` | Documentation only |
| `test/description` | Tests only |
| `chore/description` | Dependencies, CI, tooling |

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
rule(pattern): add bawbel-crypto-drain detection
feat(cli): add --output-file flag to scan command
fix(engine): handle empty semgrep output gracefully
docs(guides): update writing-rules with OWASP mapping table
```

Types: `feat`, `fix`, `rule`, `test`, `docs`, `refactor`, `chore`, `security`

---

## Code Style

- Python 3.10+, Black formatting, 100-char line length
- Type hints on all public functions
- Docstrings on all public functions
- Never inline message strings — use `scanner/messages.py`
- Never write helpers inline — add to `scanner/utils.py` if reused
- Never expose exception details to users — log internally, return E-codes

See `.claude/security.md` for the full information exposure rules.

---

## Reporting a Vulnerability in This Tool

**Do not open a public issue for security vulnerabilities.**

Email: **bawbel.io@gmail.com** — subject: `SECURITY: bawbel-scanner [brief description]`

See `SECURITY.md` for the full disclosure policy.

---

## Researcher Bounties

Found a genuine vulnerability in a real agentic component that should be an AVE record?
Submit it to [bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave).

Every accepted AVE record earns a **$10 thank-you bounty** and permanent credit.

---

## Questions

Open a [GitHub Discussion](https://github.com/bawbel/bawbel-scanner/discussions)
or email bawbel.io@gmail.com.
