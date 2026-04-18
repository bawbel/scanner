# ADR-001: Engine Separation

**Status:** Accepted
**Date:** April 2026

---

## Context

The scanner needs to run multiple detection engines (pattern, YARA, Semgrep,
future LLM and sandbox). Initially all engines were in `scanner.py`.

## Decision

Each engine is a separate file in `scanner/engines/`:

```
scanner/engines/
├── __init__.py          ← registry — imports all engines
├── pattern.py           ← Stage 1a
├── yara_engine.py       ← Stage 1b
├── semgrep_engine.py    ← Stage 1c
└── [llm_engine.py]      ← Stage 2 (planned)
```

`scanner/scanner.py` is a thin orchestrator — it calls engines but contains no detection logic.

## Consequences

**Adding a new engine:** create one file, register in `__init__.py`, add one line in `scanner.py`. No other files change.

**Removing an engine:** delete the file, remove from `__init__.py`. No other files break.

**Testing an engine:** test the file in isolation without loading the full scanner.

**Disabling an engine at runtime:** comment out one import in `__init__.py`.
