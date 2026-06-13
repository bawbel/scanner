# ADR-004: scan() never raises

**Status:** Accepted
**Date:** 2026-02-28

---

## Decision

`scanner.scan()` never raises an exception under any circumstances. All errors are
returned as `ScanResult(error=E-code)`. Every engine function also never raises —
returns `[]` on any error.

---

## Context

Security scanners are used in CI/CD pipelines where an uncaught exception would break
the build in a confusing way. The scanner is also used as a Python library where callers
expect a predictable return value.

---

## Rationale

**Predictable interface.** The caller always gets a `ScanResult`. They check
`result.has_error` and `result.error` rather than catching exceptions. This is simpler
and less error-prone.

**Pipeline safety.** In CI, an unhandled `PermissionError` from a file read would produce
a Python traceback with internal paths and exit with code 1 — indistinguishable from a
scan finding. A `ScanResult(error="E008: Could not read file content.")` produces a clean
error message and the CI step can handle it correctly.

**Security.** Exceptions propagate stack frames, variable values, and internal paths.
Returning an E-code string avoids all of that.

**Trust.** A security tool that crashes on unusual input is unreliable. `scan()` handles
every edge case: symlinks, binary files, files over the size limit, invalid paths,
missing rules files, subprocess timeouts. All return a `ScanResult` with an appropriate
error code.

---

## Implementation pattern

Every error-prone operation uses the `(result, error)` tuple pattern:

```python
path, err = resolve_path(file_path)
if err:
    return _error_result(original_path, err)

ok, err = is_safe_path(path)
if not ok:
    return _error_result(original_path, err)

content, err = read_file_safe(path)
if err:
    return _error_result(original_path, err)
```

Engine functions wrap their entire body in `try/except Exception`:

```python
try:
    # ... detection logic ...
except Exception as e:  # nosec B110
    log.error("Engine error: engine=%s error_type=%s", ENGINE_NAME, type(e).__name__)
    return []
```

---

## Consequences

- Callers must check `result.has_error` before using `result.findings`
- `result.is_clean` returns `False` when `error` is set (an errored scan is not clean)
- Test coverage must include error paths — every `return _error_result(...)` line
- Engine functions must have `except Exception` at the outermost level
