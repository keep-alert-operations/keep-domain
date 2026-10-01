"""User-deferred automation; retained implementations are not deployable roles."""

DEFERRED_WORKERS = frozenset({
    "maintenance", "assignment-cleanup", "inactivity", "operators", "directory",
    "retention", "incident-retention", "audit-retention", "command-retention",
    "configuration-retention", "correlation-retention", "maintenance-retention",
    "operator-retention",
})
