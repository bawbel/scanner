# Contributing to Bawbel Scanner

Every contribution makes agentic AI safer. Thank you.

---

## Ways to contribute

| Type | Description |
|---|---|
| Detection rule | Add a pattern, YARA, or Semgrep rule for a new attack class |
| AVE record | Research and document a new agentic vulnerability at github.com/aveproject/ave (an independent project) |
| False positive fix | A rule fires on legitimate content - fix the regex or add exclusion |
| CLI command | Add a new `bawbel <command>` |
| Bug report | Something is broken |
| Documentation | Fix, clarify, add examples |

---

## Issue before PR

Every change starts as an issue, not a PR.

1. Open the issue with a form under `.github/ISSUE_TEMPLATE/`: bug report, feature
   request, new detection rule, or Factory task.
2. Branch from `develop` and open the PR against `develop`. `main` receives promotions
   from `develop` only.
3. The PR body starts with `Closes #N`, or `Refs #N` when the PR is one of several
   against the same issue. Fill in `.github/PULL_REQUEST_TEMPLATE.md`.

A security issue in the scanner itself never goes in an issue. See [SECURITY.md](SECURITY.md).

---

## Setup

```bash
git clone https://github.com/bawbel/scanner
cd scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
pre-commit install
```

---

## Adding a detection rule

The most impactful contribution. Full guide in `docs/guides/writing-rules.md`.

```
1. Add rule to PATTERN_RULES in scanner/engines/pattern.py
2. Map to the correct AVE record ID (github.com/aveproject/ave)
3. Add AIVSS score from the AVE record
4. Add positive test fixture (content that triggers the rule)
5. Add negative test fixture (similar but innocent content)
6. Write pytest tests - positive AND negative
7. Run: python -m pytest tests/ -v
8. Run: bandit -r scanner/ -f screen  (must be 0 issues)
```

---

## Code rules

- No `shell=True` anywhere
- No network calls during a scan (startup sync only)
- No exec/eval of scanned content - ever
- Line length: 100 chars max
- Type hints on all public functions
- No em dashes in strings or comments (use hyphens)
- Run `black scanner/ tests/` before every commit

---

## Output contract: additive fields only

`Finding` and `ScanResult` fields, and the JSON and SARIF output built from them, are a
public contract that downstream tools parse.

- Add fields. Never rename or remove one. A rename or removal is a breaking change and
  needs a major version.
- State fields added, renamed, and removed in the PR template's "Output contract impact"
  block.

---

## Golden fixture

`tests/fixtures/skills/malicious/malicious_skill.md` is the golden fixture. Never modify
it. Run it after any change:

```bash
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
python -m pytest tests/test_scanner.py -k golden -v
```

---

## Pull request checklist

- [ ] Tests pass: `python -m pytest tests/ -v`
- [ ] No new bandit issues: `bandit -r scanner/ -f screen`
- [ ] Linted: `black --check scanner/ tests/`
- [ ] No em dashes in source
- [ ] No CVSS-AI references (use OWASP AIVSS)
- [ ] No github.com/bawbel/bawbel-scanner URLs (use github.com/bawbel/scanner)
- [ ] No github.com/bawbel/bawbel-ave or github.com/bawbel/ave URLs (use github.com/aveproject/ave)

---

## AVE records

Detection rules reference AVE record IDs. If your rule covers a new attack
class not yet in the database, submit an AVE record first at
[github.com/aveproject/ave](https://github.com/aveproject/ave). AVE is an independent
project with its own maintainers; its contact is aveproject.org@gmail.com.

---

## Contact

Questions: open a [GitHub Discussion](https://github.com/bawbel/scanner/discussions)
Security: bawbel.io@gmail.com subject: `SECURITY: bawbel-scanner [description]`
