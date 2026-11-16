"""Keep's metric registry and the rules every metric obeys (REV-74, observability 7).

Names start with ``keep_`` and labels are closed sets defined in code. No tenant,
alert, operator, user or source value is ever a label: the allowed label names are
listed here and a metric that asks for another one is refused at import.
"""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

ALLOWED_LABELS = frozenset(
    {
        "service",
        "role",
        # A log event's name: the closed set of the event catalog.
        "event",
        # A section of the UI, from the closed list the Product API accepts.
        "view",
        "route",
        "method",
        "status",
        "outcome",
        "reason",
        "code",
        "error_code",
        "sli",
        "level",
        "origin",
        "consumer",
        "partition",
        "topic",
        "client",
        "dependency",
        "operation",
        "stage",
        "state",
        "kind",
        "mode",
        "source",
        "api",
        "name",
        "version",
    }
)

# Seconds. Each set includes the thresholds of the objectives measured with it
# (reliability 4 and 5: 1 s, 2 s and 5 s).
FAST = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10)
LONG = (*FAST, 30, 60, 100)
DELAY = (0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 1800, 7200)
# From a few milliseconds (a healthy hop between services) to a long backlog.
SPAN = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 1800)


def _check(name, labels):
    if not name.startswith("keep_"):
        raise ValueError(f"metric {name} must start with keep_")
    unknown = sorted(set(labels) - ALLOWED_LABELS)
    if unknown:
        raise ValueError(f"metric {name} uses labels outside the allowed list: {unknown}")
    return tuple(labels)


def counter(name, documentation, labels=()):
    return Counter(name, documentation, _check(name, labels), registry=REGISTRY)


def gauge(name, documentation, labels=()):
    return Gauge(name, documentation, _check(name, labels), registry=REGISTRY)


def histogram(name, documentation, labels=(), *, buckets=FAST):
    return Histogram(name, documentation, _check(name, labels), buckets=buckets, registry=REGISTRY)


def registered_labels():
    """Every registered metric with its label names, for the label test."""
    result = {}
    for collector in list(REGISTRY._collector_to_names):
        names = getattr(collector, "_labelnames", None)
        name = getattr(collector, "_name", None)
        if name is not None and names is not None:
            result[name] = tuple(names)
    return result
