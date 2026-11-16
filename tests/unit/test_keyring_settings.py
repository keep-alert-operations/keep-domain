import base64
import json

import pytest
from pydantic import ValidationError

from keep.config import Settings


def configuration(**values):
    return Settings(database_url="unused", deployment_epoch="test", **values)


def test_keyring_settings_accept_overlap_and_reload_atomic_file_rotation(tmp_path, monkeypatch):
    monkeypatch.delenv("KEEP_WRAPPING_KEY", raising=False)
    monkeypatch.delenv("KEEP_WRAPPING_KEYRING", raising=False)
    old = base64.b64encode(b"o" * 32).decode()
    new = base64.b64encode(b"n" * 32).decode()
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps({"current": "old", "keys": {"old": old}}), encoding="utf-8")
    settings = configuration(wrapping_keyring=path)
    ciphertext = settings.cipher().seal(b"synthetic", "session-csrf:test")
    replacement = tmp_path / "replacement.json"
    replacement.write_text(
        json.dumps({"current": "new", "keys": {"old": old, "new": new}}), encoding="utf-8"
    )
    replacement.replace(path)
    cipher = settings.cipher()
    assert cipher.current == "new" and cipher.open(ciphertext, "session-csrf:test") == b"synthetic"
    assert old not in repr(settings) and new not in repr(settings)
    with pytest.raises(ValidationError, match="exactly one"):
        configuration(wrapping_keyring=path, wrapping_key=old)
    with pytest.raises(ValidationError, match="exactly one"):
        configuration()


@pytest.mark.parametrize(
    "document", [b"{}", b"x" * 65537, b"{invalid"], ids=["missing-fields", "oversized", "malformed"]
)
def test_invalid_mounted_keyring_fails_at_startup_without_echoing_contents(tmp_path, document):
    path = tmp_path / "invalid.json"
    path.write_bytes(document)
    with pytest.raises(ValidationError, match="Invalid mounted wrapping keyring") as error:
        configuration(wrapping_keyring=path)
    assert document.decode() not in str(error.value)


def test_missing_keyring_fails_closed(tmp_path):
    with pytest.raises(ValidationError, match="Invalid mounted wrapping keyring"):
        configuration(wrapping_keyring=tmp_path / "missing")
