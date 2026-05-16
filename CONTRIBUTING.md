# Contributing to Bawbel Scanner

Every contribution makes agentic AI safer. Thank you.

---

## Ways to contribute

| Type | Description |
|---|---|
| Detection rule | Add a pattern, YARA, or Semgrep rule for a new attack class |
| AVE record | Research and document a new agentic vulnerability at github.com/bawbel/ave |
| False positive fix | A rule fires on legitimate content - fix the regex or add exclusion |
| CLI command | Add a new `bawbel <command>` |
| Bug report | Something is broken |
| Documentation | Fix, clarify, add examples |

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
2. Map to the correct AVE record ID (github.com/bawbel/ave)
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

## Pull request checklist

- [ ] Tests pass: `python -m pytest tests/ -v`
- [ ] No new bandit issues: `bandit -r scanner/ -f screen`
- [ ] Linted: `black --check scanner/ tests/`
- [ ] No em dashes in source
- [ ] No AIVSS references (use AIVSS)
- [ ] No github.com/bawbel/scanner URLs (use bawbel/scanner)
- [ ] No github.com/bawbel/ave URLs (use bawbel/ave)

---

## AVE records

Detection rules reference AVE record IDs. If your rule covers a new attack
class not yet in the database, submit an AVE record first at
[github.com/bawbel/ave](https://github.com/bawbel/ave).

---

## Contact

Questions: open a [GitHub Discussion](https://github.com/bawbel/scanner/discussions)
Security: bawbel.io@gmail.com subject: `SECURITY: bawbel-scanner [description]`
