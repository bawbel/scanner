#!/usr/bin/env bash
# Run the add-a-rule guide (docs/guides/adding-a-rule.md) in a temporary clone.
#
# A guide nobody has executed rots. This clones the committed HEAD of this repository, installs it
# the way the guide says, takes the rule, fixtures and test from the guide's own blocks (the ones
# marked `<!-- smoke: NAME [PATH] -->`), applies them, and runs the checks the guide tells a
# contributor to run. If a step in the guide stops working, this fails.
#
#   bash scripts/contributor_smoke.sh      # every step prints ok; ends: contributor path OK in N seconds
#
# Needs git, python3 with venv, and the network (pip, and the AVE corpus the README pins).
#   SMOKE_SKIP_COUNTS=1   skip the README count step when offline. It is reported as skipped,
#                         never as ok, and the run then ends "contributor path OK (counts skipped)"
#   SMOKE_KEEP=1          keep the temporary clone and print where it is
#   PYTHON=python3.12     the interpreter to build the venv with
#
# Only the committed HEAD is tested. Uncommitted changes, including to the guide, are not.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
GUIDE="docs/guides/adding-a-rule.md"
WORK="$(mktemp -d)"
LOG="$WORK/step.log"
START="$(date +%s)"
COUNTS_SKIPPED=0

cleanup() {
  if [ "${SMOKE_KEEP:-0}" = "1" ]; then
    echo "kept: $WORK"
  elif [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

# step "what it does" command args...   Prints ok, or the tail of the output and exits 1.
step() {
  local name="$1"
  shift
  printf '%-64s' "$name"
  if "$@" >"$LOG" 2>&1; then
    echo ok
  else
    echo FAILED
    echo "--- last lines of the output of: $*" >&2
    tail -n 25 "$LOG" >&2
    exit 1
  fi
}

# expect_exit CODE "what" command args...   The step passes only if the command exits with CODE.
# A different failure, such as exit 2 when the corpus cannot be fetched, is a failure of the step.
expect_exit() {
  local want="$1" name="$2" got=0
  shift 2
  printf '%-64s' "$name"
  "$@" >"$LOG" 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then
    echo ok
  else
    echo FAILED
    echo "--- expected exit $want, got $got: $*" >&2
    tail -n 25 "$LOG" >&2
    exit 1
  fi
}

CLONE="$WORK/clone"
VENV="$WORK/venv"

step "clone the repository (committed HEAD)" git clone --quiet --no-hardlinks "$SRC" "$CLONE"
cd "$CLONE"

step "create a virtual environment" "$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
step "install the package with the dev extras" pip install --quiet --disable-pip-version-check -e ".[dev]"
step "the suite passes before any change" python -m pytest -p no:cacheprovider -q -m "not integration and not slow"

# Take the rule, fixtures and test from the guide. Each block is marked
#   <!-- smoke: NAME [PATH] -->   and is followed by a fenced code block.
# The rule goes at the end of PATTERN_RULES_V2. The other blocks are written to their PATH.
apply_guide() {
  python - "$GUIDE" <<'PY'
import pathlib
import re
import sys

guide = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(r"<!--\s*smoke:\s*(\S+)(?:[ \t]+(\S+))?\s*-->\s*\n```[^\n]*\n(.*?)\n```", guide, re.S)
by_name = {}
for name, path, body in blocks:
    if name in by_name:
        sys.exit(f"the guide has two blocks marked smoke: {name}")
    by_name[name] = (path, body)

for needed in ("rule", "fixture-positive", "fixture-negative", "test"):
    if needed not in by_name:
        sys.exit(f"the guide has no block marked smoke: {needed}")

engine = pathlib.Path("scanner/engines/pattern_engine.py")
text = engine.read_text(encoding="utf-8")
join = "PATTERN_RULES = PATTERN_RULES + PATTERN_RULES_V2"
if text.count(join) != 1:
    sys.exit(f"{engine} no longer contains exactly one line: {join}")
head, tail = text.split(join)
close = head.rstrip().rfind("\n]")
if close == -1:
    sys.exit("could not find the ] that closes PATTERN_RULES_V2")
rule = by_name["rule"][1].rstrip("\n") + "\n"
engine.write_text(head[: close + 1] + rule + head[close + 1 :] + join + tail, encoding="utf-8")

for name in ("fixture-positive", "fixture-negative", "test"):
    path, body = by_name[name]
    if not path:
        sys.exit(f"the block smoke: {name} names no path")
    target = pathlib.Path(path)
    if target.exists():
        sys.exit(f"{path} already exists, so the guide's example would overwrite it")
    target.write_text(body + "\n", encoding="utf-8")
    print(path)
PY
}

step "add the guide's rule, fixtures and test to the clone" apply_guide

# The test file the guide names, and the rule id it adds, are read back from the clone.
TEST_FILE="$(git ls-files --others --exclude-standard -- 'tests/unit/engines/*.py' | head -n 1)"
RULE_ID="$(git diff -U0 -- scanner/engines/pattern_engine.py | sed -n 's/^+ *"rule_id": "\(.*\)",/\1/p' | head -n 1)"
POSITIVE="$(git ls-files --others --exclude-standard -- 'tests/fixtures/skills/malicious/*.md' | head -n 1)"
NEGATIVE="$(git ls-files --others --exclude-standard -- 'tests/fixtures/skills/clean/*.md' | head -n 1)"
[ -n "$TEST_FILE" ] && [ -n "$RULE_ID" ] && [ -n "$POSITIVE" ] && [ -n "$NEGATIVE" ] \
  || { echo "could not find what the guide added" >&2; exit 1; }

fires() { bawbel scan "$POSITIVE" --format json | python -c 'import json,sys; ids=[f["rule_id"] for r in json.load(sys.stdin) for f in r["findings"]]; sys.exit(0 if sys.argv[1] in ids else 1)' "$RULE_ID"; }
quiet() { bawbel scan "$NEGATIVE" --format json | python -c 'import json,sys; ids=[f["rule_id"] for r in json.load(sys.stdin) for f in r["findings"]]; sys.exit(1 if sys.argv[1] in ids else 0)' "$RULE_ID"; }

step "the new rule's tests pass" python -m pytest -p no:cacheprovider -q "$TEST_FILE"
step "bawbel scan finds the rule in the positive fixture" fires
step "bawbel scan does not find it in the negative fixture" quiet
step "the golden fixture still passes" python -m pytest -p no:cacheprovider -q tests/test_scanner.py -k golden
step "the rest of the suite is unaffected" python -m pytest -p no:cacheprovider -q -m "not integration and not slow"

# The README states the rule count and a script writes it, so adding a rule makes it stale.
if [ "${SMOKE_SKIP_COUNTS:-0}" = "1" ]; then
  printf '%-64s%s\n' "the README counts go stale, then sync_record_counts fixes them" "SKIPPED (offline)"
  COUNTS_SKIPPED=1
else
  expect_exit 1 "the README count is stale after adding a rule (the guide says so)" python scripts/sync_record_counts.py --check
  step "python scripts/sync_record_counts.py updates the README" python scripts/sync_record_counts.py
  step "python scripts/sync_record_counts.py --check passes" python scripts/sync_record_counts.py --check
fi

step "black --check on the files the guide changed" black --check --line-length 100 scanner/engines/pattern_engine.py "$TEST_FILE"
step "flake8 on the rule file" flake8 scanner/engines/pattern_engine.py --max-line-length 100

SECONDS_TAKEN=$(( $(date +%s) - START ))
if [ "$COUNTS_SKIPPED" = "1" ]; then
  echo "contributor path OK (counts skipped) in ${SECONDS_TAKEN} seconds"
else
  echo "contributor path OK in ${SECONDS_TAKEN} seconds"
fi
