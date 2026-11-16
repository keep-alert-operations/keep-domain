"""Logs, metrics and their shared rules for every Keep process (REV-74).

See ``keep-design/specs/spec-observability.md``. This package imports no service
entrypoint; services call into it.
"""

from keep.observability.alerts import alert_fields
from keep.observability.catalog import register
from keep.observability.context import bind, bind_more
from keep.observability.exposition import start_metrics_server
from keep.observability.flow import Flow
from keep.observability.logs import Repeats, configure_logging, log_event

__all__ = [
    "Flow",
    "Repeats",
    "alert_fields",
    "bind",
    "bind_more",
    "configure_logging",
    "log_event",
    "register",
    "start_metrics_server",
]
