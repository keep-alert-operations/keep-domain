"""Current ownership presentation, independent of retained legacy evidence."""

LEGACY_ACK_FIELDS = frozenset(
    {"acknowledged", "acknowledged_by", "acknowledged_at", "acknowledged_by_display_name"}
)


def display_status(alert):
    if alert.get("status") == "resolved":
        return "resolved"
    if alert.get("status") == "firing":
        return "acknowledged" if alert.get("assignee_id") is not None else "firing"
    return None


def present_alert(alert):
    from keep.alerts.v1_native import as_sent

    # A v1 row not yet converted reads as its v1 equivalent (REV-77).
    alert = as_sent(alert)
    result = {key: value for key, value in alert.items() if key not in LEGACY_ACK_FIELDS}
    result["display_status"] = display_status(alert)
    if "key_field" in alert:
        from keep.cel.catalog import alert_name, alert_provider  # keep.cel imports this module

        # Stored and replayed rows hold only a supplied name (REV-54).
        result["name"] = alert_name(alert)
        # Rows from before REV-55 hold no provider; v1 reads as api.
        result["provider"] = alert_provider(alert)
        result.setdefault("alert_rule_url", None)
        # Rows and command results from before REV-77 have no object.
        result.setdefault("object", None)
    return result


def present_command_result(result):
    """Adapt new and replayed responses without rewriting stored command results."""
    data = result["data"]
    return {
        **result,
        "data": [present_alert(row) for row in data]
        if isinstance(data, list)
        else present_alert(data),
    }
