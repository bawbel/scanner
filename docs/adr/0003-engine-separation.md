# ADR-001: Engine separation

**Status:** Accepted
**Date:** 2026-02-20

---

## Decision

Each detection engine lives in its own file under `scanner/engines/`. The scanner
collects results from all active engines into a single `list[Finding]` and deduplicates.

---

## Context

Early prototypes had all detection logic in `scanner.py`. As rules grew the file became
unmanageable and adding a new detection method required touching the core scan function.

---

## Rationale

**Independent deployability.** An installation without `yara-python` simply has no
`yara_engine.py` contributing findings. The scanner degrades gracefully rather than
failing. `bawbel version` shows which engines are active.

**Independent rules files.** Pattern rules are in `pattern.py`, YARA rules in
`scanner/rules/yara/ave_rules.yar`, Semgrep rules in
`scanner/rules/semgrep/ave_rules.yaml`. Adding a rule never requires touching any
other engine's code.

**Independent testing.** Each engine has its own unit test file under
`tests/unit/engines/`. Tests for the YARA engine do not need `semgrep` installed.

**Consistent interface.** Every engine implements one function:

```python
def run_<engine>_scan(file_path: str, ...) -> list[Finding]
```

Adding a new engine is four steps: create the file, export from `__init__.py`,
add one line to `scanner.py`, add an entry to `bawbel version`.

---

## Consequences

- `Finding.engine` field is required — always identifies the source engine
- Deduplication runs after all engines, collapsing `(rule_id, line)` duplicates
- Each engine must never raise — return `[]` on any error
- New engines must follow the contract in [docs/guides/adding-engine.md](../guides/adding-engine.md)
