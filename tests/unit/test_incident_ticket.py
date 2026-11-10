import logging

from pydantic import ValidationError
import pytest

from keep.incidents.models import IncidentTicket
from keep.incidents.tickets import link_allowed, parse_servicenow
from keep.shared.display_names import IncidentDisplayNames

COMMAND = {"command_id": "00000000-0000-4000-8000-000000000001", "expected_revision": "3"}
LINK = "https://acme.service-now.com/nav_to.do?uri=incident.do%3Fsysparm_query%3Dnumber%3DINC0041235"


def ticket(**values):
    return IncidentTicket(**COMMAND, **values)


def test_ticket_command_links_unlinks_and_normalizes_numbers():
    """Requirements: REV-70; incident operations 18."""
    linked = ticket(url=LINK, number=" inc0041235 ")
    assert (linked.url, linked.number) == (LINK, "INC0041235")
    assert ticket(url=LINK).number is None
    unlinked = ticket(url=None, number=None)
    assert (unlinked.url, unlinked.number) == (None, None)
    assert ticket().url is None
    assert ticket(url="https://acme.service-now.com/" + "a" * 2019).url


@pytest.mark.parametrize(
    "values",
    [
        {"url": ""},
        {"url": "https://acme.service-now.com/" + "a" * 2020},
        {"url": "https://acme.service-now.com/a b"},
        {"url": "https://acme.service-now.com/é"},
        {"url": "https://acme.service-now.com/a\tb"},
        {"url": "ftp://acme.service-now.com/x"},
        {"url": "javascript:alert(1)"},
        {"url": "/incident.do"},
        {"url": "https://user:pw@acme.service-now.com/x"},
        {"url": "https://acme.service-now.com:99999/x"},
        {"number": "INC0041235"},
        {"url": LINK, "number": "INC 0041235"},
        {"url": LINK, "number": "0041235"},
        {"url": LINK, "number": "INC123"},
        {"url": LINK, "number": "ABCDEFGHI1234"},
        {"url": LINK, "number": ""},
        {"url": LINK, "extra": True},
        {"url": 7},
    ],
)
def test_ticket_command_rejects_bad_links_and_numbers(values):
    """Requirements: REV-70; incident operations 18."""
    with pytest.raises(ValidationError):
        ticket(**values)


def test_servicenow_setting_accepts_https_with_optional_base_path(caplog):
    """Requirements: REV-70."""
    plain = parse_servicenow(" https://ACME.service-now.com/ ")
    assert plain.base_url == "https://acme.service-now.com"
    assert (plain.scheme, plain.host, plain.port, plain.path) == ("https", "acme.service-now.com", 443, "")
    based = parse_servicenow("https://tools.acme.example:8443/sn/")
    assert based.base_url == "https://tools.acme.example:8443/sn"
    assert parse_servicenow("https://acme.service-now.com:443").base_url == "https://acme.service-now.com"
    assert parse_servicenow(None) is None
    assert parse_servicenow("   ") is None
    local = parse_servicenow("http://127.0.0.1:58091/", development=True)
    assert local.base_url == "http://127.0.0.1:58091"
    caplog.set_level(logging.WARNING)
    for raw in (
        "http://127.0.0.1:58091",
        "http://acme.service-now.com",
        "https://user:pw@acme.service-now.com",
        "https://acme.service-now.com/?a=1",
        "https://acme.service-now.com/#x",
        "acme.service-now.com",
        "https://",
        "https://acme.service-now.com/a b",
    ):
        assert parse_servicenow(raw) is None, raw
    assert parse_servicenow("http://acme.example", development=True) is None
    assert "KEEP_SERVICENOW_URL" in caplog.text
    assert "user:pw" not in caplog.text


def test_links_must_point_into_the_configured_servicenow():
    """Requirements: REV-70; incident operations 15."""
    plain = parse_servicenow("https://acme.service-now.com")
    assert link_allowed(LINK, plain)
    assert link_allowed("https://ACME.service-now.com:443/incident.do?sys_id=1#top", plain)
    assert link_allowed("https://acme.service-now.com", plain)
    for url in (
        "http://acme.service-now.com/incident.do",
        "https://acme-dev.service-now.com/incident.do",
        "https://acme.service-now.com:8443/incident.do",
        "https://service-now.com/incident.do",
        "https://acme.service-now.com.evil.example/incident.do",
        "https://user@acme.service-now.com/incident.do",
        "https://acme.service-now.com:bad/x",
    ):
        assert not link_allowed(url, plain), url
    based = parse_servicenow("https://tools.acme.example/sn")
    assert link_allowed("https://tools.acme.example/sn", based)
    assert link_allowed("https://tools.acme.example/sn/incident.do", based)
    assert not link_allowed("https://tools.acme.example/snow/incident.do", based)
    assert not link_allowed("https://tools.acme.example/incident.do", based)
    assert not link_allowed(LINK, None)


def test_incident_reads_document_ticket_fields():
    """Requirements: REV-70; system completion 10."""
    fields = IncidentDisplayNames.model_fields
    for name in (
        "ticket_url",
        "ticket_number",
        "ticket_linked_at",
        "ticket_linked_by",
        "ticket_linked_by_display_name",
    ):
        assert name in fields and fields[name].default is None
