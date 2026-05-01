# Contributing to Bawbel Scanner

Thank you for helping make agentic AI safer. Every contribution matters.

---

## Ways to Contribute

| Type | What it means |
|---|---|
| **New detection rule** | Add a pattern, YARA, or Semgrep rule to catch a new attack class |
| **New CLI command** | Add a new `bawbel <command>` — one file, three lines |
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
[ ] Add remediation text to REMEDIATION_GUIDE in scanner/cli/shared/constants.py
[ ] Add positive test fixture (content that triggers the rule)
[ ] Add negative test fixture (similar but innocent content)
[ ] Write pytest tests — positive AND negative
[ ] Run: python -m pytest tests/ -v        (must pass)
[ ] Run: bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
         (must still show 2 findings, CRITICAL 9.4)
[ ] Run: bandit -r scanner/ -f screen      (must be 0 issues)
```

---

## Adding a CLI Command

The CLI is modular — one file per command. Adding a new command touches
exactly **3 lines** in the codebase and creates **1 new file**.

### Step 1 — create `scanner/cli/cmd_<name>.py`

```python
import click
from scanner.cli.shared import console, print_banner, print_json, print_sarif

@click.command("<name>")
@click.argument("...")
@click.option("--format", "fmt", ...)
def <name>_cmd(...) -> None:
    """One-line description shown in bawbel --help."""
    ...
```

Use only helpers from `scanner.cli.shared` — never import Rich directly
in a command file. All rendering lives in `scanner/cli/shared/display.py`.

### Step 2 — register in `scanner/cli/__init__.py`

```python
# Add one import:
from scanner.cli.cmd_<name> import <name>_cmd

# Add one line:
cli.add_command(<name>_cmd)
```

### Step 3 — add a test in `tests/test_cli.py`

```python
def test_<name>_cmd_basic(runner):
    result = runner.invoke(cli, ["<name>", "--help"])
    assert result.exit_code == 0
```

---

## CLI Module Layout

The CLI is a modular package. Each command is in its own file.
Shared utilities live in `shared/`.

```
scanner/cli/
├── __init__.py             ← thin entry point, registers all commands
├── cmd_scan.py             ← bawbel scan + watch mode
├── cmd_scan_card.py        ← bawbel scan-server-card
├── cmd_report.py           ← bawbel report + remediation guide
├── cmd_version.py          ← bawbel version + engine status
├── cmd_init.py             ← bawbel init + project setup
└── shared/
    ├── __init__.py         ← re-exports most-used helpers
    ├── constants.py        ← SEVERITY_COLORS, OWASP_DESCRIPTIONS, REMEDIATION_GUIDE
    ├── display.py          ← Rich rendering: print_banner, print_scan_result
    ├── formatters.py       ← print_json, print_sarif
    └── utils.py            ← collect_files and other small helpers
```

**Rules for command files:**
- Import only from `scanner.cli.shared` — never Rich directly
- `shared/constants.py` is the single source of truth for all display constants
- `shared/display.py` owns all Rich rendering — a redesign touches only this file
- No business logic in command files — they orchestrate, they don't compute

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
feat(cli): add bawbel scan-server-card command
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

## Lint Rules

```
E501  100-char line limit (not 79)
F401  no unused imports
F541  no empty f-strings
F811  no duplicate class names
E221  no extra spaces before operators
E251  no spaces in keyword arguments
E231  space after comma required
SIM105  use contextlib.suppress instead of try/except/pass
SIM102  flatten nested ifs
```

Bandit `nosec` + `noqa` — both tags must be on the **same line**:

```python
import subprocess  # noqa: S404 nosec B404
subprocess.run(cmd)  # noqa: S603,S607 nosec B603,B607
open('/tmp/x')  # noqa: S108 nosec B108
except:  # noqa: S110 nosec B110
    pass
```

Tests: no duplicate class names across test files. No `import pytest` unless
using `pytest.mark`, `pytest.raises`, or `pytest.param`.

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
