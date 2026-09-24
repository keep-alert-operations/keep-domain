import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from appchi.shared.crypto import EnvelopeCipher
from appchi.shared.cursors import Cursor
from appchi.shared.errors import AppError


def test_rewrap_preserves_payload_and_secret_with_old_version_overlap():
    old = EnvelopeCipher({"old": b"a" * 32}, "old")
    overlap = EnvelopeCipher({"old": b"a" * 32, "current": b"b" * 32}, "current")
    sealed = old.seal(b"unchanged-customer-api-key", "operator-key:operator:credential:1")
    assert (
        overlap.open(sealed, "operator-key:operator:credential:1") == b"unchanged-customer-api-key"
    )
    wrapped = overlap.rewrap(sealed, "operator-key:operator:credential:1")
    before, after = json.loads(sealed), json.loads(wrapped)
    assert before["data"] == after["data"] and before["n"] == after["n"]
    assert before["key"] != after["key"] and before["wn"] != after["wn"]
    assert after["kid"] == "current"
    only_current = EnvelopeCipher({"current": b"b" * 32}, "current")
    assert (
        only_current.open(wrapped, "operator-key:operator:credential:1")
        == b"unchanged-customer-api-key"
    )
    with pytest.raises(ValueError):
        old.open(wrapped, "operator-key:operator:credential:1")
    assert overlap.rewrap(wrapped, "operator-key:operator:credential:1") == wrapped


@pytest.mark.parametrize("method", ["open", "rewrap"])
def test_wrong_aad_and_tampered_payload_are_rejected_even_with_current_key(method):
    cipher = EnvelopeCipher({"current": b"b" * 32}, "current")
    sealed = cipher.seal(b"refresh-token", "session-tokens:abc")
    with pytest.raises(ValueError):
        getattr(cipher, method)(sealed, "session-csrf:abc")
    with pytest.raises(ValueError):
        getattr(cipher, method)(sealed, "session-tokens:def")
    envelope = json.loads(sealed)
    ciphertext = bytearray(base64.urlsafe_b64decode(envelope["data"]))
    ciphertext[0] ^= 1
    envelope["data"] = base64.urlsafe_b64encode(ciphertext).decode()
    with pytest.raises(ValueError):
        getattr(cipher, method)(json.dumps(envelope).encode(), "session-tokens:abc")


@pytest.mark.parametrize(
    "change",
    [{"v": True}, {"v": 2}, {"kid": "unknown"}, {"n": "AA=="}, {"key": "*"}, {"unexpected": 1}],
)
def test_malformed_or_unavailable_envelopes_fail_closed(change):
    cipher = EnvelopeCipher({"current": b"b" * 32}, "current")
    envelope = json.loads(cipher.seal(b"secret", "purpose:id"))
    envelope.update(change)
    with pytest.raises(ValueError):
        cipher.rewrap(json.dumps(envelope).encode(), "purpose:id")


def test_supplied_keyring_is_validated_without_mutable_external_key_references():
    encoded = base64.b64encode(b"a" * 32).decode()
    cipher = EnvelopeCipher.from_keyring(json.dumps({"current": "v1", "keys": {"v1": encoded}}))
    assert cipher.open(cipher.seal(b"secret", "purpose:id"), "purpose:id") == b"secret"
    keys = {"v1": b"a" * 32}
    cipher = EnvelopeCipher(keys, "v1")
    original = cipher.seal(b"secret", "purpose:id")
    keys["v1"] = b"z" * 32
    assert cipher.open(original, "purpose:id") == b"secret"
    with pytest.raises(TypeError):
        cipher.keys["v1"] = b"z" * 32
    for value in (
        '{"current":"a","current":"b","keys":{}}',
        json.dumps({"current": "v1", "keys": {"v1": "not-base64"}}),
        json.dumps({"current": "v2", "keys": {"v1": encoded}}),
        json.dumps({"current": "v1", "keys": {"v1": base64.b64encode(b"a").decode()}}),
    ):
        with pytest.raises(ValueError):
            EnvelopeCipher.from_keyring(value)
    with pytest.raises(ValueError):
        cipher.open(original[:-1] + b',"kid":"v1"}', "purpose:id")


def test_rotation_overlap_keeps_existing_cursor_and_fixed_expiry():
    old = EnvelopeCipher({"old": b"a" * 32}, "old")
    overlap = EnvelopeCipher({"old": b"a" * 32, "current": b"b" * 32}, "current")
    now = datetime(2026, 9, 23, tzinfo=UTC)
    context = {"session": "test", "tenant": "one", "epoch": "deployed"}
    token = Cursor(old, context, now).encode("position")
    reader = Cursor(overlap, context, now + timedelta(minutes=14))
    assert reader.decode(token)["position"] == "position"
    continued = reader.encode("next")
    assert reader.expires_at == now + timedelta(minutes=15)
    with pytest.raises(AppError) as failure:
        Cursor(overlap, context, now + timedelta(minutes=15)).decode(continued)
    assert failure.value.code == "cursor_expired"


def test_supplied_purpose_keys_keep_legacy_overlap_and_use_distinct_active_ids():
    keys = {"legacy": b"a" * 32, "csrf-v2": b"b" * 32, "cursor-v2": b"c" * 32}
    ring = {
        "current": "legacy",
        "keys": {kid: base64.b64encode(key).decode() for kid, key in keys.items()},
        "purposes": {
            "session-csrf": "csrf-v2",
            "cursor": "cursor-v2",
            "search-cursor": "cursor-v2",
        },
    }
    cipher = EnvelopeCipher.from_keyring(json.dumps(ring))
    legacy = EnvelopeCipher({"legacy": keys["legacy"]}, "legacy")
    previous = legacy.seal(b"unchanged-csrf", "session-csrf:abc")
    assert cipher.open(previous, "session-csrf:abc") == b"unchanged-csrf"
    wrapped = cipher.rewrap(previous, "session-csrf:abc")
    assert json.loads(wrapped)["kid"] == "csrf-v2"
    assert json.loads(wrapped)["data"] == json.loads(previous)["data"]
    assert json.loads(cipher.seal(b"cursor", "cursor:v1"))["kid"] == "cursor-v2"
    assert json.loads(cipher.seal(b"search", "search-cursor:digest"))["kid"] == "cursor-v2"
    assert json.loads(cipher.seal(b"key", "operator-key:a:b:1"))["kid"] == "legacy"
    with pytest.raises(ValueError):
        cipher.open(wrapped, "cursor:abc")
    for purpose, kid in (("typo-cursor", "cursor-v2"), ("cursor", "missing")):
        ring["purposes"] = {purpose: kid}
        with pytest.raises(ValueError):
            EnvelopeCipher.from_keyring(json.dumps(ring))
