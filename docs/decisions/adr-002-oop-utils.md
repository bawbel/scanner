# ADR-002: OOP utils with function aliases

**Status:** Accepted
**Date:** 2026-02-22

---

## Decision

`scanner/utils.py` uses classes (`Logger`, `PathValidator`, `FileReader`,
`SubprocessRunner`, `JsonParser`, `TextSanitiser`, `Timer`) internally, but
exposes module-level function aliases for all commonly used operations.

---

## Context

The scanner has a clear security requirement: all path handling, subprocess execution,
and file reading must follow strict contracts. The question was whether to express these
contracts as functions, classes, or something else.

---

## Rationale

**Classes enforce the contract.** `PathValidator.resolve()` always checks for symlinks
before calling `Path.resolve()`. The class boundary makes it impossible to bypass the
check by calling `Path.resolve()` directly. Security-critical logic belongs in a class
where the method order is enforced.

**Function aliases are cleaner at call sites.** Callers write:

```python
from scanner.utils import resolve_path, is_safe_path, read_file_safe
```

Not:

```python
from scanner.utils import PathValidator, FileReader
path, err = PathValidator.resolve(file_path)
ok, err   = PathValidator.validate(path)
content, err = FileReader.read_text(path)
```

The function aliases are one-liners that delegate to the class methods:

```python
def resolve_path(file_path: str) -> tuple[Optional[Path], Optional[str]]:
    return PathValidator.resolve(file_path)
```

**Testability.** Classes can be instantiated and their methods patched independently.
`monkeypatch.setattr(PathValidator, "resolve", ...)` is unambiguous.

---

## Consequences

- New utility functions should be methods on an appropriate class, then aliased at module level
- Direct class imports (`from scanner.utils import PathValidator`) are acceptable for advanced use
- The security contracts documented in each class docstring are the canonical spec
