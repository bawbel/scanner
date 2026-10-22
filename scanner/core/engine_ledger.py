"""
Bawbel Scanner - per-scan record of which engines ran.

Engines keep their contract: `run_X_scan(...) -> list[Finding]`, never raising. They also
report whether they ran, through the ledger of the scan in progress. The ledger lives in a
ContextVar, so:

  - report_ran() and report_degraded() do nothing when no scan is active. Calling an engine
    directly, as the unit tests do, is unaffected
  - concurrent scans in different threads or tasks never share a ledger
  - nothing here can raise into an engine

An engine that reports degraded is not counted as having run, even if it reported ran
earlier. The first degradation reported for an engine is the one kept.
"""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

from scanner.models.engine_status import ENGINES, EngineDegradation

_ERROR_CODE = re.compile(r"^(E\d{3})\b")


def error_code(message: Optional[str]) -> Optional[str]:
    """The leading error code of a scanner error message ("E013: ..." -> "E013"), or None.

    Only the code is ever recorded as a degradation detail, never the message text.
    """
    match = _ERROR_CODE.match(message or "")
    return match.group(1) if match else None


class EngineLedger:
    """The engines that ran and the engines that did not, for one scan."""

    def __init__(self) -> None:
        self._ran: set[str] = set()
        self._degraded: dict[str, EngineDegradation] = {}

    def ran(self, engine: str) -> None:
        if engine not in self._degraded:
            self._ran.add(engine)

    def degraded(self, engine: str, reason: str, detail: Optional[str] = None) -> None:
        self._ran.discard(engine)
        self._degraded.setdefault(engine, EngineDegradation(engine, reason, detail))

    @property
    def engines_run(self) -> list[str]:
        return [e for e in ENGINES if e in self._ran]

    @property
    def engines_degraded(self) -> list[EngineDegradation]:
        return [self._degraded[e] for e in ENGINES if e in self._degraded]


_current: ContextVar[Optional[EngineLedger]] = ContextVar("bawbel_engine_ledger", default=None)


@contextmanager
def engine_ledger() -> Iterator[EngineLedger]:
    """Open a ledger for the scan in progress."""
    ledger = EngineLedger()
    token = _current.set(ledger)
    try:
        yield ledger
    finally:
        _current.reset(token)


def report_ran(engine: str) -> None:
    """Record that an engine ran. No-op outside a scan."""
    ledger = _current.get()
    if ledger is not None:
        ledger.ran(engine)


def report_degraded(engine: str, reason: str, detail: Optional[str] = None) -> None:
    """Record that an engine did not run, and why. No-op outside a scan."""
    ledger = _current.get()
    if ledger is not None:
        ledger.degraded(engine, reason, detail)
