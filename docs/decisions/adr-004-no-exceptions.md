# ADR-004: scan() Never Raises

**Status:** Accepted
**Date:** April 2026

---

## Context

`scan()` processes untrusted input. Any unhandled exception would expose
a stack trace to the user, potentially leaking internal paths, library
versions, or file content.

## Decision

`scan()` and all engine functions never raise. All errors are captured
and returned in `ScanResult.error` or as an empty `list[Finding]`.

```python
# scan() contract
def scan(file_path: str) -> ScanResult:
    # ALWAYS returns ScanResult
    # NEVER raises
    # On any failure: ScanResult(error="E00X: ...")
```

Engine contract:
```python
def run_X_scan(file_path: str) -> list[Finding]:
    # ALWAYS returns list (may be empty)
    # NEVER raises
    # On failure: log + return []
```

## Consequences

**CI/CD** — a bad file never crashes the scanner process. The build continues
and the error is visible in the JSON output.

**Security** — no stack traces ever reach users or logs above DEBUG.

**Reliability** — callers never need try/except around scan().

**Testing** — every error path must return a result, making tests deterministic.
