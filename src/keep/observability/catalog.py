"""The event catalog: every log event is registered once (REV-74, observability 5).

An entry gives the event's level, the plain sentence written as the record's
``message``, the fields it must carry, and when it fires and what to do. The
operations runbook's event reference is generated from this catalog. Services
register their own events beside the code that emits them.
"""

import logging
from typing import NamedTuple

from keep.observability.fields import ALERT_FIELDS, DURATION, FIELDS


class Event(NamedTuple):
    level: int
    message: str  # sentence; {field} placeholders
    doc: str  # when it fires and what to do
    required: tuple = ()
    outcome: str | None = None  # success | failure | unknown
    text: str | None = None  # %-template of the token line, to keep an existing message


CATALOG: dict[str, Event] = {}


def register(name, level, message, doc, *, required=(), outcome=None, text=None):
    if name in CATALOG:
        raise ValueError(f"log event {name} is already registered")
    unknown = [
        field for field in required if field not in FIELDS and field not in (DURATION, "alert")
    ]
    if unknown:
        raise ValueError(f"log event {name} requires unregistered fields {unknown}")
    if outcome not in (None, "success", "failure", "unknown"):
        raise ValueError(f"log event {name} has an invalid outcome")
    CATALOG[name] = Event(level, message, doc, tuple(required), outcome, text)
    return name


def known_field(name):
    return name in FIELDS or name == DURATION


def known_alert_field(name):
    return name in ALERT_FIELDS


INFO, WARNING, ERROR = logging.INFO, logging.WARNING, logging.ERROR

register(
    "process_started",
    INFO,
    "Process started as {role}",
    "A process finished configuring logging and is starting work.",
    outcome="success",
)
register(
    "process_stopping",
    INFO,
    "Process is stopping: {reason}",
    "A stop was requested; the process drains and exits.",
)
register(
    "process_unhandled_error",
    ERROR,
    "Unhandled {error_class} in {origin}",
    "An exception escaped every handler. Look at the stack; the process may have exited.",
    required=("error_class", "origin"),
    outcome="failure",
)
register(
    "http_request",
    INFO,
    "{method} {route} answered {status}",
    "One record per HTTP request, at completion. A 5xx is written as a warning. A "
    "successful read repeated by the same user is written once a minute; repeats is the "
    "number not written in between.",
    required=("request_id", "method", "route", "status"),
)
register(
    "http_unhandled_error",
    ERROR,
    "Unhandled {error_class} while serving {method} {route}",
    "A request failed with an unexpected exception and was answered 500 internal_error. "
    "Look at the stack.",
    required=("request_id", "error_class"),
    outcome="failure",
)
register(
    "http_client_closed",
    INFO,
    "Client closed {method} {route} before the response",
    "The caller disconnected before a response was produced.",
    required=("request_id",),
    outcome="unknown",
)
register(
    "worker_capability_unavailable",
    WARNING,
    "Worker {role} turn failed with {error_class}",
    "A worker turn failed and is retried each second. Repeats are summarised once a minute. "
    "Check the named dependency or error code.",
    outcome="failure",
)
register(
    "worker_transport_restarted",
    WARNING,
    "Worker {role} discarded its Kafka client and will rejoin",
    "The consumer was closed after a failed turn and is recreated on the next turn.",
    outcome="failure",
)
register(
    "worker_ready_changed",
    INFO,
    "Worker {role} is now {state}",
    "The worker's readiness changed.",
    required=("role", "state"),
)
register(
    "search_kafka_degraded_reconciliation_active",
    WARNING,
    "Search hints from Kafka are unavailable; reconciliation continues",
    "The indexer cannot consume changed events and is repairing from PostgreSQL only. "
    "Repeats are summarised once a minute.",
    outcome="failure",
)
register(
    "search_reconciliation_degraded_hints_active",
    WARNING,
    "Search reconciliation is unavailable; Kafka hints continue",
    "The indexer's authority scan failed while hints still work. "
    "Repeats are summarised once a minute.",
    outcome="failure",
)

# The alert's flow (observability 3). Steps written by shared code are registered
# here; each service registers the steps only it takes beside the code that writes
# them. Every step carries the pass's identifiers and its sequence number.
register(
    "alert_applied",
    INFO,
    "Alert {outcome}: status {status_before} to {status_after}, revision {revision}",
    "The source processor applied a delivered input and PostgreSQL committed it. "
    "outcome is created, updated, unchanged (a repeat that changed nothing), resolved "
    "or reopened. Carries the whole alert as delivered.",
    required=("alert", "outcome", "status_after"),
    outcome="success",
)
register(
    "alert_refused",
    WARNING,
    "Delivery refused after acceptance: {error_code}",
    "Ingestion accepted the input (202) but the source processor could not apply it. "
    "identity_conflict: the fixed identity fields differ from the existing alert; "
    "operator_deleted: its operator was deleted; retired_receipt: the alert was retired "
    "after this receipt. The sender is not told; check its configuration.",
    required=("error_code",),
    outcome="failure",
)
register(
    "alert_change_consumed",
    INFO,
    "Read changed event {changed_event_id} ({cause}) from partition {partition} "
    "at offset {offset}",
    "A consumer of alert changes read one change from Kafka. delay_seconds is the time "
    "since the change was committed.",
    required=("changed_event_id", "alert", "partition", "offset"),
    outcome="success",
)
register(
    "alert_incident_attached",
    INFO,
    "Alert attached to incident {incident_id} by rule {rule_id} ({outcome})",
    "Correlation attached the alert to an incident and PostgreSQL committed it. "
    "outcome is incident_created or incident_existing.",
    required=("alert", "incident_id", "rule_id", "outcome"),
    outcome="success",
)
register(
    "alert_correlated",
    INFO,
    "Correlation evaluated the change: {outcome}",
    "Correlation finished evaluating one alert change and PostgreSQL committed it. "
    "outcome is incident_created, attached or no_incident; count is the number of passes.",
    required=("changed_event_id", "alert", "outcome"),
    outcome="success",
)
register(
    "alert_correlation_skipped",
    INFO,
    "Correlation did not evaluate the change: {reason}",
    "The change needed no evaluation. duplicate: this event was already handled; "
    "not_source: the change came from a command or control, which correlates inline; "
    "unchanged: the delivery changed nothing rules look at; retired: the alert is retired.",
    required=("changed_event_id", "alert", "reason"),
    outcome="success",
)
register(
    "changed_partition_retry",
    WARNING,
    "Consumer {consumer} could not handle offset {offset} of partition {partition} "
    "and holds the partition for retry",
    "A changed event failed in its consumer. The partition is held at this offset and "
    "retried; other partitions continue. error.code and error.type name the cause.",
    required=("consumer", "partition"),
    outcome="failure",
    text="changed_partition_retry consumer=%(consumer)s partition=%(partition)d",
)
register(
    "alert_changed",
    INFO,
    "Alert changed by {cause}: status {status_before} to {status_after}, revision {revision}",
    "Something other than a delivered input changed an alert and PostgreSQL committed it: "
    "a user command (set_status, set_assignee, set_dismissal), a note, an incident link, "
    "unlink or move, or a maintenance effect. cause names it and user.id the user. "
    "outcome is changed, or recorded when only history changed.",
    required=("alert", "cause", "status_after", "revision"),
    outcome="success",
)
register(
    "alert_notification_published",
    INFO,
    "Changed event {changed_event_id} sent to Kafka",
    "After a commit, the service that changed an alert sent the change to Kafka so "
    "search follows at once.",
    required=("changed_event_id", "alert"),
    outcome="success",
)
register(
    "alert_notification_unconfirmed",
    WARNING,
    "Kafka did not confirm the alert changes of this request in time",
    "The change is committed in PostgreSQL but its hint may not have reached Kafka. "
    "Search catches up by reconciliation. Check the broker if this repeats.",
    outcome="failure",
)
register(
    "alert_notification_failed",
    WARNING,
    "The alert changes of this request could not be sent to Kafka",
    "The change is committed in PostgreSQL but its hint was not sent. Search catches "
    "up by reconciliation. error.type names the cause.",
    outcome="failure",
)

# Real user monitoring (observability 9): written by the Product API on behalf of the
# browser, so they are shipped under service.name "browser".
register(
    "rum_js_error",
    ERROR,
    "The browser raised an unhandled {error_class} ({kind}) on the {view} view",
    "The UI raised a JavaScript error nothing handled. error.stack_trace holds the "
    "same-origin frames; the error's own text is not recorded. user.id names the user.",
    required=("kind", "view"),
    outcome="failure",
)
register(
    "rum_api_error",
    WARNING,
    "The browser's {method} {route} failed: {reason}",
    "A Product API call failed as the browser saw it: no answer (network), an answer "
    "that could not be read (unreadable), or a 5xx. http.request.id is the failed "
    "request's ID when the browser received one; search it in the api index.",
    required=("method", "route", "reason"),
    outcome="failure",
)
register(
    "rum_live_disconnect",
    INFO,
    "A browser's live connection ended: {reason}",
    "The UI lost its live update stream and falls back to polling until it reconnects. "
    "reason is watchdog, stream_end, http_status, invalid_response, network or denied.",
    required=("reason",),
    outcome="failure",
)
