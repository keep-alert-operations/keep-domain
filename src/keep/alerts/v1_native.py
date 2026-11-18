"""v1 alerts as sent (REV-77): the old-vocabulary view and its conversion.

Before REV-77 a v1 alert was stored in v2 words: `object` in `component`,
error as critical and major as high. Those rows stay valid until converted, by
the conversion command or by the next source update of the alert. Display and
search read such a row as its v1 equivalent (`as_sent`); rule evaluation
(maintenance, correlation) reads stored values as they are.

`convert_alert` is the one conversion used by the batch command. It runs in the
writers' lock order (coordinator, catalog, contexts, linked incidents, alert),
records a maintenance input under cause `v1-native-conversion` so a rewritten
window can open its cause on this transition, and publishes a non-semantic
change, so no activity row shows the vocabulary change. The source processor
converts on touch inside its own transition instead (keep.alerts.processor).
"""

CAUSE = "v1-native-conversion"
TO_SENT = {"critical": "error", "high": "major"}
TO_LEGACY = {value: key for key, value in TO_SENT.items()}


def legacy(row) -> bool:
    """A stored v1 row that still holds the pre-REV-77 vocabulary."""
    return row.get("schema_version") == "v1" and (
        row.get("component") is not None or row.get("severity") in TO_SENT
    )


def sent(row) -> bool:
    """A stored v1 row in the REV-77 vocabulary that `--reverse` can restore."""
    return row.get("schema_version") == "v1" and (
        row.get("object") is not None or row.get("severity") in TO_LEGACY
    )


def as_sent(row: dict) -> dict:
    """The v1 equivalent of an old-vocabulary row; other rows are returned as they are."""
    if not legacy(row):
        return row
    result = dict(row)
    if result.get("component") is not None:
        result["object"] = result.get("object") or result["component"]
        result["component"] = None
    result["severity"] = TO_SENT.get(result["severity"], result["severity"])
    return result


def as_legacy(row: dict) -> dict:
    """The pre-REV-77 equivalent of a v1 row (rollback with `--reverse`)."""
    if not sent(row):
        return row
    result = dict(row)
    if result.get("object") is not None:
        result["component"] = result["object"]
        result["object"] = None
    result["severity"] = TO_LEGACY.get(result["severity"], result["severity"])
    return result


def _in_leaving_words(program, reverse) -> bool:
    """Whether a window's expression names the vocabulary the row is leaving.

    Forward, that is `component` or critical/high; with `--reverse`, `object` or
    error/major. A window written in the target words, or in neither, must see
    the converted row so its cause can open. An expression the rewriter cannot
    read is treated as leaving words, the safe side.
    """
    from keep.cel.v1_rewrite import rewrite

    source = getattr(program, "source", None)
    if source is None:
        return True
    try:
        return rewrite(source, reverse=reverse).changed
    except Exception:
        return True


def held_by(catalog, raw, converted, at, order, *, reverse=False):
    """Maintenance windows whose match would change if this row were converted now.

    A window that has started cannot have its expression edited, so one still
    written in the words the row is leaving would release (or newly catch) the
    alert at the conversion. Such a row keeps those words until the window ends;
    a rerun of the conversion, or the next source update after that, converts
    it. Windows are evaluated on the same rule snapshot maintenance uses.
    """
    from keep.maintenance.processing import _snapshot
    from keep.maintenance.temporal import Boundary

    if catalog is None or raw is converted:
        return []
    boundary = Boundary(at, max(int(order), 0), "v1-native-probe")
    before, after = _snapshot(raw), _snapshot(converted)
    held = []
    for segment in catalog.segments:
        if not segment.covers(boundary) or not _in_leaving_words(segment.program, reverse):
            continue
        try:
            differs = segment.program.evaluate(before, at) != segment.program.evaluate(after, at)
        except Exception:
            differs = True
        if differs:
            held.append(str(segment.window_id))
    return sorted(set(held))


def source_prior(previous, catalog, at, order):
    """(state the source update applies to, keep old words) for the processor."""
    if previous is None:
        return None, False
    prior = as_sent(previous)
    if prior is previous:
        return previous, False
    if held_by(catalog, previous, prior, at, order):
        return prior, True
    return prior, False


def convert_alert(conn, row, now, catalog, *, reverse=False):
    """Convert one locked, retained v1 row; return the stored result or None.

    The caller holds the tenant coordinator, has locked the maintenance catalog
    and correlation contexts for this alert, its linked incidents and the row
    (FOR UPDATE), and owns the transaction.
    """
    from keep.alerts.lifecycle import SEMANTIC_FIELDS
    from keep.alerts.repository import publish, store_alert
    from keep.maintenance.runtime import apply_transition

    target = as_legacy(row) if reverse else as_sent(row)
    if target is row:
        return None
    target = dict(target)
    order = conn.execute(
        "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
        (row["tenant_id"],),
    ).fetchone()["admission_order"]
    adjusted, _, _ = apply_transition(conn, row, target, now, order, CAUSE, now, catalog)
    # The vocabulary is not a semantic change; derived suppression can be.
    semantic = any(
        row.get(field) != adjusted.get(field) for field in SEMANTIC_FIELDS if field != "severity"
    )
    adjusted["revision"] = row["revision"] + int(semantic)
    adjusted["projection_version"] = row["projection_version"] + 1
    store_alert(conn, adjusted)
    publish(
        conn,
        row,
        adjusted,
        now,
        CAUSE,
        semantic=semantic,
        original_order=order,
        maintenance_input_recorded=True,
    )
    return adjusted
