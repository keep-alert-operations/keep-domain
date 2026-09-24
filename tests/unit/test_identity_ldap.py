import pytest

from appchi.identity.directory import DirectoryUnavailable, PrincipalKey
from appchi.identity.ldap import LDAPConfig, LDAPDirectoryReader, LDAPSchema


def config(**changes):
    schema = LDAPSchema(
        "dc=example",
        "(objectClass=person)",
        "(objectClass=group)",
        "entryUUID",
        "cn",
        "member",
        "active",
        "text",
        eligibility_values=("true",),
    )
    return LDAPConfig(
        "company", "directory.example", "cn=reader", "secret", "company-ca.pem", schema, **changes
    )


class Connection:
    def __init__(self, pages):
        self.pages, self.calls = iter(pages), []

    def search(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        self.response, self.result = next(self.pages)


def page(rows=(), cookie=b"", result=0):
    return list(rows), {
        "result": result,
        "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}},
    }


def entry(identity="user-1", **attributes):
    return {
        "type": "searchResEntry",
        "dn": "cn=user,dc=example",
        "raw_attributes": {
            "entryUUID": [identity.encode()],
            "cn": [b"User"],
            "active": [b"true"],
            **attributes,
        },
    }


def test_all_pages_consumed_with_critical_paging_and_safe_filter():
    connection = Connection([page([entry()], b"next"), page([entry("user-2")])])
    reader = LDAPDirectoryReader(config(), connection=connection)
    assert len(reader._search("dc=example", "(objectClass=person)")) == 2
    assert connection.calls[1][1]["paged_cookie"] == b"next"
    assert connection.calls[0][1]["paged_criticality"] is True
    assert (
        reader._identity_filter(PrincipalKey("company", "x*)(uid=*)"))
        == r"(entryUUID=x\2a\29\28uid=\2a\29)"
    )


@pytest.mark.parametrize(
    "pages",
    [
        [page([entry()], result=4)],
        [(list([entry()]), {"result": 0})],
        [page([entry()], b"same"), page([], b"same")],
        [page([{"type": "searchResRef", "uri": ["ldap://other"]}])],
        [page([entry(**{"member;range=0-1499": [b"cn=partial"]})])],
    ],
)
def test_partial_limit_missing_control_loop_referral_and_range_are_not_absence(pages):
    reader = LDAPDirectoryReader(config(), connection=Connection(pages))
    with pytest.raises(DirectoryUnavailable):
        reader._search("dc=example", "(objectClass=person)")


def test_complete_negative_lookup_is_tombstone():
    reader = LDAPDirectoryReader(config(), connection=Connection([page(), page()]))
    obj = reader.lookup(PrincipalKey("company", "missing"))
    assert obj.deleted and not obj.eligible


def test_eligibility_attribute_is_required_not_assumed_active():
    reader = LDAPDirectoryReader(
        config(), connection=Connection([page([entry(active=[])]), page()])
    )
    with pytest.raises(DirectoryUnavailable):
        reader.lookup(PrincipalKey("company", "user-1"))


def test_unknown_schema_does_not_guess_membership_or_disable_semantics():
    with pytest.raises(ValueError):
        LDAPSchema(
            "dc=x",
            "(objectClass=user)",
            "(objectClass=group)",
            "id",
            "cn",
            "member",
            "active",
            "text",
        )
    with pytest.raises(ValueError):
        LDAPSchema(
            "dc=x",
            "(objectClass=user)",
            "(objectClass=group)",
            "id",
            "cn",
            "member",
            "active",
            "text",
            eligibility_values=("true",),
            primary_group_mode="attribute",
        )
