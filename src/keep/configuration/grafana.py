"""Which Grafana addresses a Grafana panel may frame (REV-68).

The deployment lists the allowed Grafana instances in ``KEEP_GRAFANA_PANEL_ORIGINS``:
comma-separated absolute addresses, each an origin with an optional base path for a
Grafana served under a sub-path. Entries that are not usable are ignored with a reason
rather than failing start-up, so one typo cannot take the API down; an empty list turns
Grafana panels off. The browser runs the same checks on input and on every render; the
Product API runs them when a panel's address is new or changed.
"""

from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL = 2048


def is_loopback(host):
    host = (host or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def origin_of(parts):
    """The browser's ``URL.origin`` for a split http(s) address: scheme, host, non-default port."""
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    suffix = f":{port}" if port is not None and port != DEFAULT_PORTS.get(parts.scheme) else ""
    return f"{parts.scheme}://{host}{suffix}"


@dataclass(frozen=True)
class GrafanaOrigins:
    """Allowed Grafana as ``{"origin", "path_prefix"}`` entries, plus ignored entries and why."""

    allowed: list = field(default_factory=list)
    ignored: list = field(default_factory=list)

    @property
    def enabled(self):
        return bool(self.allowed)


def parse_grafana_origins(value, public_origin, environment="production"):
    """Parse the allowed Grafana list; https only, loopback http in development."""
    keep = origin_of(urlsplit(public_origin))
    allowed, ignored, seen = [], [], set()
    for raw in (value or "").split(","):
        entry = raw.strip()
        if not entry:
            continue

        def skip(reason):
            ignored.append({"entry": entry, "reason": reason})

        if not entry.isascii() or any(c.isspace() or not c.isprintable() for c in entry):
            skip("Use an address without spaces or control characters.")
            continue
        try:
            parts = urlsplit(entry)
            parts.port
        except ValueError:
            skip("Not a valid address.")
            continue
        scheme_ok = parts.scheme == "https" or (
            parts.scheme == "http" and environment == "development" and is_loopback(parts.hostname)
        )
        if not entry.lower().startswith(("https://", "http://")) or not parts.hostname:
            skip("Use a full address that starts with https://.")
        elif not scheme_ok:
            skip("Only https is allowed (http only for this computer in development).")
        elif parts.username is not None or parts.password is not None:
            skip("Remove the user name and password.")
        elif parts.query or parts.fragment or "?" in entry or "#" in entry:
            skip("Remove the query and fragment; list only the Grafana address.")
        elif origin_of(parts) == keep:
            skip("This is Keep's own address.")
        else:
            prefix = parts.path.rstrip("/")
            key = (origin_of(parts), prefix)
            if key not in seen:
                seen.add(key)
                allowed.append({"origin": key[0], "path_prefix": prefix})
    return GrafanaOrigins(allowed, ignored)


def grafana_url_problem(url, origins, public_origin):
    """Why a Grafana panel address can't be framed, or None (checks 5-11 of REV-68).

    The panel model has already checked the address's form: printable ASCII, an absolute
    http(s) address with a host, no user name or password, at most 2,048 characters.
    """
    parts = urlsplit(url)
    if origin_of(parts) == origin_of(urlsplit(public_origin)):
        return "Keep's own pages can't be shown in a Grafana panel."
    if not origins.enabled:
        return "Grafana panels are turned off."
    if parts.scheme == "http" and not is_loopback(parts.hostname):
        return "Keep is served over https, so the panel address must be https too."
    origin = origin_of(parts)
    entry = next(
        (
            item
            for item in origins.allowed
            if item["origin"] == origin
            and (not item["path_prefix"] or parts.path.startswith(item["path_prefix"] + "/"))
        ),
        None,
    )
    if entry is None:
        return f"{parts.netloc} isn't an allowed Grafana."
    if not parts.path.startswith(entry["path_prefix"] + "/d-solo/"):
        return "Use a single-panel address from Share › Embed. Whole dashboards can't be shown."
    return None
