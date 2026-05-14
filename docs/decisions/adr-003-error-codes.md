# ADR-003: Error codes not raw messages

**Status:** Accepted
**Date:** 2026-02-25

---

## Decision

All error messages are defined as constants in `scanner/messages.py` with stable `E-code`
prefixes (`E001`, `E002`, etc.). `ScanResult.error` always contains an E-code string, never
a raw exception message.

---

## Context

The scanner must never leak internal information in error messages. A naive implementation
might put `str(e)` in `ScanResult.error`, which could expose file paths, library versions,
stack frames, or other implementation details.

At the same time, error messages need to be actionable for the user. "Something went wrong"
is not helpful. "E003: File not found: malicious.md" is.

---

## Rationale

**Security.** `str(e)` from a Python exception often contains absolute paths (`/home/saray/.venv/lib/...`),
library versions, and internal variable names. E-codes give users actionable information
(the file was not found, it was too large, it is a symlink) without leaking internals.

**Stability.** E-codes are versioned. Tools that parse `ScanResult.error` can match on
`"E003"` regardless of how the human-readable text changes. Renaming an E-code is a
breaking change; renaming the text is not.

**Centralisation.** All messages in one place means a single audit of `messages.py` covers
all user-visible error text. No need to grep the codebase for string literals.

---

## E-code ranges

| Range | Category |
|---|---|
| E001-E009 | Path and file validation |
| E010-E019 | Engine errors |
| E020-E029 | Rules and configuration |

---

## Consequences

- `ScanResult.error` is always an E-code string or `None`
- `type(e).__name__` is used in log messages, never `str(e)`
- New error conditions get a new E-code in `messages.py`
- E-codes must not be reused after retirement
