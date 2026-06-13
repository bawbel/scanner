# Refactoring Guide

How to restructure without breaking anything.
Rule: behavior never changes during a move.

## Phase 0: Green baseline

pytest tests/ -q  # record N passing
git checkout -b refactor/modular-core
git commit -m "chore: baseline before refactor — N tests passing"

## Phase 1: Directory structure

mkdir -p scanner/core/toxic_flows
mkdir -p tests/unit tests/integration tests/e2e
mkdir -p tests/fixtures/golden tests/fixtures/lifecycle tests/fixtures/input
touch scanner/core/__init__.py tests/unit/__init__.py
pytest tests/ -q  # still N passing
git commit -m "refactor: create directory structure"

## Phase 2: Add evidence fields (Issues #69-71)

Additive only. All optional with defaults. Cannot break tests.
Follow prd-02-tasks.md TASK-01 through TASK-09.

## Phase 3: Extract pure functions from scanner.py

For each function, exact sequence:
1. Write unit test in tests/unit/ → MUST FAIL
2. Create scanner/core/[module].py with the function
3. Adjust interface: remove Path → use (name: str, parts: frozenset[str])
4. In scanner.py: replace body with adapter that calls core function
5. pytest tests/unit/[module].py → MUST PASS
6. pytest tests/ -q → N passed (same count)
7. Commit

Extraction order:
  _deduplicate       → scanner/core/dedup.py
  _strip_code_fences → scanner/core/preprocessor.py
  _classify_file     → scanner/core/fp_pipeline.py
  _has_negation_context → scanner/core/fp_pipeline.py
  _score_confidence  → scanner/core/fp_pipeline.py

## Critical: the adapter pattern

tests/test_scanner.py imports _deduplicate from scanner.scanner.
Keep the adapter in scanner.py until that import is updated:

  from scanner.core.dedup import deduplicate as _deduplicate_core

  def _deduplicate(findings):
      return _deduplicate_core(findings)  # thin adapter

## Phase 4: Reorganize tests

Move TestDeduplication → tests/unit/test_dedup.py
Move TestCLI → tests/e2e/test_cli.py
Move everything that calls scan() → tests/integration/test_scanner.py
Remove from original only AFTER new location is verified green.

## Phase 5: Golden fixtures

bawbel scan tests/fixtures/input/clean.md --format json > tests/fixtures/golden/clean_scan.json
Write contract tests in tests/unit/test_output_contracts.py

## What NOT to do

Never rename during extraction — separate commit.
Never change behavior during extraction — separate commit.
Never extract multiple functions in one session.
Never delete adapter until all callers updated.
Never skip the full suite run between phases.
