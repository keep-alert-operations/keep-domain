"""The steps one alert passes through inside one service (REV-74, observability 3).

A ``Flow`` is one pass: one delivered input in ingestion and the source processor,
one changed event in correlation and the indexer. Each step is its own record.
Every step carries the identifiers the pass has learned so far and a sequence
number, so a query for one alert or one delivery returns the steps in order even
when several share a millisecond.

A step that describes a database effect is written only once that transaction has
committed: ``note`` holds it and ``settle`` writes it. A rolled-back effect never
leaves a record saying it happened.
"""

from contextvars import ContextVar
from datetime import UTC, datetime
from time import monotonic

from keep.observability import logs
from keep.observability.catalog import CATALOG

_active = ContextVar("keep_alert_flow", default=None)


class Flow:
    def __init__(self, logger, *, alert=None, **fields):
        self.logger = logger
        self.fields = {name: value for name, value in fields.items() if value is not None}
        self.alert = dict(alert or {})
        self.sequence = 0
        self.seen = []  # names of the steps written, in order
        self._written = []
        self._held = []
        self._started = monotonic()

    def know(self, *, alert=None, **fields):
        """Add identifiers to every later step of this pass."""
        self.fields.update({name: value for name, value in fields.items() if value is not None})
        if alert:
            self.alert.update(alert)
        return self

    def elapsed(self):
        return monotonic() - self._started

    def step(
        self,
        event,
        /,
        *,
        alert=None,
        detail=False,
        ok=None,
        exc=None,
        level=None,
        line=None,
        **fields,
    ):
        """Write one step now. ``detail`` marks a step that only narrates progress."""
        if detail and not logs.DETAIL and ok is not False and exc is None:
            # Not written, still counted: the numbers do not depend on the setting.
            entry = CATALOG.get(event)
            if entry is not None:
                shown = {k: v for k, v in fields.items() if v is not None}
                logs.measure(event, logs.outcome_of(entry, ok, level or entry.level), shown)
            return
        self.sequence += 1
        self.seen.append(event)
        self._written.append((event, fields))
        if alert and alert.get("id") not in (None, self.alert.get("id", alert.get("id"))):
            # A step about another alert (one a decision also attached) names only it.
            merged = dict(alert)
        else:
            merged = {**self.alert, **(alert or {})}
        logs.log_event(
            self.logger,
            event,
            level=level,
            ok=ok,
            exc=exc,
            alert=merged or None,
            line=line,
            **{**self.fields, **fields, "sequence": self.sequence},
        )

    def note(self, event, /, *, learned=None, **step):
        """Hold a step until ``settle``. ``learned`` is passed to ``know`` at that point."""
        self._held.append((event, learned, step))

    def held(self, event):
        """The fields of each held step named ``event``."""
        return [step for name, _, step in self._held if name == event]

    def recorded(self, event):
        """The fields of each step named ``event``, whether written or still held."""
        return [fields for name, fields in self._written if name == event] + self.held(event)

    def mark(self):
        """Where the held steps stand now; a transaction settles or drops what follows."""
        return len(self._held)

    def settle(self, since=0):
        """Write the steps held since ``since``: their transaction has committed."""
        held, self._held = self._held[since:], self._held[:since]
        for event, learned, step in held:
            if learned:
                self.know(**learned)
            # A value given as a function is read now, at the commit (a delay, say).
            self.step(event, **{k: v() if callable(v) else v for k, v in step.items()})

    def discard(self, since=0):
        """Drop the steps held since ``since``: their transaction rolled back."""
        self._held = self._held[:since]

    def __enter__(self):
        self._token = _active.set(self)
        return self

    def __exit__(self, kind, error, trace):
        _active.reset(self._token)
        if kind is not None:
            self.discard()
        return False


def seconds_since(instant):
    """Seconds from a wire instant or a datetime to now, or None when it cannot be read."""
    try:
        at = instant if isinstance(instant, datetime) else datetime.fromisoformat(
            str(instant).replace("Z", "+00:00")
        )
        return max(0.0, (datetime.now(UTC) - at).total_seconds())
    except (TypeError, ValueError):
        return None


def active():
    """The flow of the alert being handled on this thread or task, if any."""
    return _active.get()


def note(event, /, **step):
    """Add a held step to the active flow. Code with no flow around it records nothing."""
    flow = _active.get()
    if flow is not None:
        flow.note(event, **step)
