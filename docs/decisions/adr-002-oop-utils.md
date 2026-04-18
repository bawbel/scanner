# ADR-002: OOP Utils with Function Aliases

**Status:** Accepted
**Date:** April 2026

---

## Context

`scanner/utils.py` provides shared infrastructure used by all engines.
Needed a structure that is both testable (OOP) and ergonomic to call (functions).

## Decision

Utils are implemented as classes (`Logger`, `PathValidator`, `FileReader`,
`SubprocessRunner`, `JsonParser`, `TextSanitiser`) with module-level function
aliases that proxy to class methods.

```python
# Class (testable, mockable, subclassable)
class PathValidator:
    @classmethod
    def resolve(cls, file_path: str) -> tuple[...]: ...

# Function alias (ergonomic for callers)
def resolve_path(file_path: str) -> tuple[...]:
    return PathValidator.resolve(file_path)
```

## Consequences

**Callers** import and use functions — clean, minimal call sites.

**Tests** can mock at the class level — `monkeypatch.setattr(PathValidator, "resolve", ...)`.

**Future engines** can subclass utils (e.g. `class SecurePathValidator(PathValidator)`)
without changing call sites.

**New utility** = add a method to the right class + add a function alias at the bottom.
