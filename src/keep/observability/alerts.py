"""The alert as it appears in log records (REV-74, observability 3)."""

from keep.observability.fields import ALERT_CONTENT, ALERT_IDENTIFYING

# The native limits (alert operations); also applied to members that failed validation.
_LIMITS = {"message": 8192, "impact": 4096, "runbook_url": 2048, "key_field": 1024}


def alert_fields(
    source=None, *, alert_id=None, key_digest=None, native_version=None, provider=None, whole=False
):
    """Build the ``keep.alert`` object from a native payload or an alert row.

    Identifying fields always; the content fields only for a whole-alert record.
    Only the alert's own registered names are read, so nothing a sender names can
    become a log field, and each value is held to its native length.
    """
    result = {}
    if alert_id is not None:
        result["id"] = str(alert_id)
    if key_digest is not None:
        result["key_digest"] = (
            key_digest.hex() if isinstance(key_digest, (bytes, bytearray)) else str(key_digest)
        )
    if native_version is not None:
        result["native_version"] = str(native_version)
    if provider is not None:
        result["provider"] = str(provider)
    if isinstance(source, dict) or hasattr(source, "get"):
        for name in (*ALERT_IDENTIFYING, *(ALERT_CONTENT if whole else ())):
            value = source.get(name)
            if value is None or isinstance(value, (dict, list, tuple, set, bytes)):
                continue
            text = str(value)
            if text:
                result[name] = text[: _LIMITS.get(name, 256)]
    return result
