"""ServiceNow tickets on incidents (REV-70).

Keep never calls ServiceNow: an incident stores only a ticket link and an optional
number. The deployment names its ServiceNow in ``KEEP_SERVICENOW_URL`` (not a secret):
an https address with a host and an optional base path. A saved link must point into
that ServiceNow, so a link to anywhere else cannot be stored on an incident.
"""

from dataclasses import dataclass
import ipaddress
import logging
import re
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

NUMBER = re.compile(r"[A-Z]{2,8}[0-9]{4,12}")
MAX_URL = 2048
DEFAULT_PORTS = {"http": 80, "https": 443}
LOOPBACK_NAMES = {"localhost"}


@dataclass(frozen=True)
class ServiceNow:
    """The configured ServiceNow: scheme, lower-case host, port and base path."""

    base_url: str
    scheme: str
    host: str
    port: int
    path: str


def _loopback(host):
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _clean(value):
    return value.isascii() and not any(c.isspace() or not c.isprintable() for c in value)


def parse_servicenow(raw, *, development=False):
    """The configured ServiceNow, or None when it is absent or unusable.

    It must be https with a host and no user name, password, query or fragment; plain
    http is accepted only for a loopback host in development. A trailing slash is
    dropped. An unusable value is logged and treated as unset.
    """
    value = (raw or "").strip()
    if not value:
        return None
    try:
        if not _clean(value) or len(value) > MAX_URL:
            raise ValueError
        parts = urlsplit(value)
        port = parts.port
        host = (parts.hostname or "").lower()
        if not host or parts.username is not None or parts.password is not None:
            raise ValueError
        if parts.query or parts.fragment or "?" in value or "#" in value:
            raise ValueError
        local = development and parts.scheme == "http" and _loopback(host)
        if parts.scheme != "https" and not local:
            raise ValueError
    except ValueError:
        log.warning(
            "KEEP_SERVICENOW_URL is not an https address with a host and no query "
            "(http only for a loopback host in development); ServiceNow tickets are off"
        )
        return None
    path = parts.path.rstrip("/")
    shown = f"[{host}]" if ":" in host else host
    default = DEFAULT_PORTS[parts.scheme]
    netloc = shown + (f":{port}" if port is not None and port != default else "")
    return ServiceNow(
        base_url=f"{parts.scheme}://{netloc}{path}",
        scheme=parts.scheme,
        host=host,
        port=port if port is not None else default,
        path=path,
    )


def link_allowed(url, servicenow):
    """True when ``url`` is a link into the configured ServiceNow.

    Same scheme, host and port, and a path equal to the base path or under it.
    The command model has already checked characters, length and credentials.
    """
    if servicenow is None:
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != servicenow.scheme or (parts.hostname or "").lower() != servicenow.host:
        return False
    if (port if port is not None else DEFAULT_PORTS.get(parts.scheme)) != servicenow.port:
        return False
    if parts.username is not None or parts.password is not None:
        return False
    base = servicenow.path
    return not base or parts.path == base or parts.path.startswith(base + "/")


def valid_link(value):
    """Shared shape rules for a stored ticket link; raises ValueError with the reason."""
    if not value or len(value) > MAX_URL:
        raise ValueError("Use a ServiceNow link of 1 to 2,048 characters")
    if not _clean(value):
        raise ValueError("Use a link without spaces or control characters")
    try:
        parts = urlsplit(value)
        parts.port
    except ValueError:
        raise ValueError("Use a valid link address") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Use a full link that starts with https://")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Links cannot contain a user name or password")
    return value


def valid_number(value):
    """Upper-cased ticket number, letters then digits, e.g. INC0041235."""
    number = value.strip().upper()
    if not NUMBER.fullmatch(number):
        raise ValueError("Ticket numbers are letters followed by digits, like INC0041235")
    return number
