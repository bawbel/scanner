# ADR-003: Stable Error Codes

**Status:** Accepted
**Date:** April 2026

---

## Context

Error messages need to be user-friendly but must never expose internal details
(paths, exception messages, library versions). They also need to be stable so
downstream tools can match on them.

## Decision

All user-facing errors use stable `E-codes` defined in `scanner/messages.py`:

```python
CANNOT_READ_FILE = "E008: Could not read file content."
FILE_TOO_LARGE   = "E006: File too large ({size_kb}KB) — maximum is {max_mb}MB."
```

Rules:
- No exception detail in user messages
- No absolute paths (basename only via `path.name`)
- No library versions
- Codes are permanent — once published, never change or reuse
- Full detail goes to logs at DEBUG level only

## Consequences

**Users** see clean, actionable error codes they can search in docs.

**CI/CD systems** can match on `"E006"` without parsing free-text.

**Security** — no internal paths or exception types leak to external systems.

**Debugging** — engineers set `BAWBEL_LOG_LEVEL=DEBUG` to see full detail.
