# Adding a detection rule

This page adds a **pattern rule**: a regular expression that the always-on pattern engine looks
for. For YARA and Semgrep rules, see [Writing Rules](writing-rules.md).

Every step below can be run as written. `scripts/contributor_smoke.sh` takes the blocks marked
`smoke` from this page, applies them to a clean clone, and runs the checks, once a week and
whenever this page changes. If a step here stops working, that job fails.

A rule needs four things: the rule, a file that triggers it, a similar file that does not, and a
test for both.

## Before you start

- Pick the AVE record the rule detects, at [aveproject.org](https://aveproject.org). A rule cites an
  existing record by its id, such as `AVE-2026-00007`. AVE is a separate project: a missing or wrong
  record is raised with AVE, not changed here.
- Open an issue first. Work on a branch from `develop`, sign off your commits (`git commit -s`), and
  open the pull request against `develop`. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Set up

```bash
git clone https://github.com/bawbel/scanner
cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q -m "not integration and not slow"     # passes before you change anything
```

## 1. The rule

The rules live in `scanner/engines/pattern_engine.py`. `PATTERN_RULES` is built from two lists,
`PATTERN_RULES` and `PATTERN_RULES_V2`, joined by the line
`PATTERN_RULES = PATTERN_RULES + PATTERN_RULES_V2`. Add your rule at the end of `PATTERN_RULES_V2`,
just before the `]` that closes it. The example below is the shape to copy. Change every value.

<!-- smoke: rule -->
```python
    {
        "rule_id": "bawbel-example-rule",
        "ave_id": "AVE-2026-00007",
        "title": "Example rule fired",
        "description": (
            "An example rule from the add-a-rule guide. Replace this text with what the "
            "rule detects and why it matters."
        ),
        "severity": Severity.HIGH,
        "aivss_score": 6.1,
        "owasp": ["ASI01"],
        "owasp_mcp": ["MCP06"],
        "patterns": [
            r"bawbel\s+example\s+trigger\s+phrase",
        ],
    },
```

- `rule_id`: kebab-case, starts with `bawbel-`, and never changes once published.
- `ave_id`: the record the rule detects. `severity`, `aivss_score`, `owasp` and `owasp_mcp` should
  come from that record.
- `patterns`: regular expressions, searched line by line. The first match wins, and a rule gives one
  finding per file.

Severity guide:

```text
CRITICAL (AIVSS 9+)   complete attack path, immediate action
HIGH (7 to 8.9)       significant risk, schedule remediation
MEDIUM (4 to 6.9)     risk factor, review
LOW (below 4)         best practice, informational
```

## 2. A file that triggers the rule, and one that does not

The first goes in `tests/fixtures/skills/malicious/`, the second in `tests/fixtures/skills/clean/`.
Make the second as close to the first as you can without matching, because that is the case that
catches a pattern that is too broad.

<!-- smoke: fixture-positive tests/fixtures/skills/malicious/example-rule.md -->
```markdown
# Example skill

This file contains the bawbel example trigger phrase and should fire the example rule.
```

<!-- smoke: fixture-negative tests/fixtures/skills/clean/example-rule-clean.md -->
```markdown
# Example skill

This file mentions bawbel and an example and a trigger, but never the phrase together.
```

Never edit `tests/fixtures/skills/malicious/malicious_skill.md`. It is the golden fixture.

## 3. A test for both

Put it in `tests/unit/engines/test_<rule-name>.py`.

<!-- smoke: test tests/unit/engines/test_example_rule.py -->
```python
from pathlib import Path

from scanner import scan

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "skills"


def test_detects_example_rule():
    result = scan(str(FIXTURES / "malicious" / "example-rule.md"))
    assert "bawbel-example-rule" in [f.rule_id for f in result.findings]


def test_no_fp_example_rule_clean():
    result = scan(str(FIXTURES / "clean" / "example-rule-clean.md"))
    assert "bawbel-example-rule" not in [f.rule_id for f in result.findings]
```

The second test checks that your rule stays quiet, not that the file is clean of every finding. Other
engines may have views of their own.

## 4. Run it

```bash
python -m pytest tests/unit/engines/test_example_rule.py -v      # your test
python -m pytest tests/test_scanner.py -k golden -v              # the golden fixture still passes
python -m pytest -q -m "not integration and not slow"            # nothing else broke
bawbel scan tests/fixtures/skills/malicious/example-rule.md      # see the finding yourself
```

## 5. Update the README counts

The README states how many rules there are, and a script writes that number. Adding a rule makes it
stale, and the `Record Counts` CI check fails until you run the script. It reads the AVE corpus
pinned in the README, so it needs the network.

```bash
python scripts/sync_record_counts.py
python scripts/sync_record_counts.py --check      # exit 0
```

Commit the change it makes to `README.md`. Never edit those numbers by hand, and never type a rule
count in a document.

## 6. Format and lint

```bash
black --line-length 100 scanner/ tests/
flake8 scanner/ --max-line-length 100
bandit -r scanner/ -c pyproject.toml
```

## 7. Open the pull request

Output stays additive: a rule adds findings and never renames or removes a `Finding` field. State
that in the "Output contract impact" block of the pull request template.
