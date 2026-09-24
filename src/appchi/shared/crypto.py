import base64
import json
import secrets
import re
from collections.abc import Mapping
from types import MappingProxyType

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PURPOSES = frozenset(
    {
        "operator-key",
        "session-tokens",
        "session-csrf",
        "login",
        "receipt",
        "cursor",
        "search-cursor",
        "rewrap-cursor",
    }
)


class EnvelopeCipher:
    """Per-record AES-256 key, itself wrapped under a separately supplied versioned key."""

    def __init__(
        self, keys: Mapping[str, bytes], current: str, *, purposes: Mapping[str, str] | None = None
    ):
        if (
            not isinstance(keys, Mapping)
            or not isinstance(current, str)
            or current not in keys
            or any(
                not _key_id(kid) or type(key) is not bytes or len(key) != 32
                for kid, key in keys.items()
            )
        ):
            raise ValueError("A 256-bit wrapping key and current key ID are required")
        self.keys, self.current = MappingProxyType(dict(keys)), current
        purposes = {} if purposes is None else purposes
        if not isinstance(purposes, Mapping) or any(
            purpose not in PURPOSES or not isinstance(kid, str) or kid not in keys
            for purpose, kid in purposes.items()
        ):
            raise ValueError("Purpose bindings require known purposes and supplied key IDs")
        self.purposes = MappingProxyType(dict(purposes))

    def active_key_id(self, aad: str) -> str:
        _context(aad)
        return self.purposes.get(aad.split(":", 1)[0], self.current)

    @classmethod
    def from_keyring(cls, document: bytes | str):
        """Load supplied versions; never generate, retire, or guess a wrapping key."""
        try:
            value = json.loads(document, object_pairs_hook=_unique)
            if (
                not isinstance(value, dict)
                or not {"current", "keys"} <= set(value) <= {"current", "keys", "purposes"}
                or not isinstance(value["keys"], dict)
            ):
                raise ValueError()
            keys = {
                kid: base64.b64decode(encoded, validate=True)
                for kid, encoded in value["keys"].items()
            }
            return cls(keys, value["current"], purposes=value.get("purposes"))
        except (ValueError, TypeError, KeyError):
            raise ValueError("Invalid supplied wrapping keyring") from None

    def seal(self, value: bytes, aad: str) -> bytes:
        if type(value) is not bytes:
            raise ValueError("Secret material must be bytes")
        data_key, nonce, wrap_nonce = (
            secrets.token_bytes(32),
            secrets.token_bytes(12),
            secrets.token_bytes(12),
        )
        context = _context(aad)
        kid = self.active_key_id(aad)
        ciphertext = AESGCM(data_key).encrypt(nonce, value, context)
        wrapped = AESGCM(self.keys[kid]).encrypt(wrap_nonce, data_key, context)
        return json.dumps(
            {
                "v": 1,
                "kid": kid,
                "n": _encode(nonce),
                "wn": _encode(wrap_nonce),
                "key": _encode(wrapped),
                "data": _encode(ciphertext),
            },
            separators=(",", ":"),
        ).encode()

    def open(self, value: bytes, aad: str) -> bytes:
        envelope = _envelope(value)
        context = _context(aad)
        key = self._unwrap(envelope, context)
        try:
            return AESGCM(key).decrypt(_decode(envelope["n"]), _decode(envelope["data"]), context)
        except Exception:
            raise ValueError("Secret envelope authentication failed") from None

    def _unwrap(self, envelope, context):
        try:
            return AESGCM(self.keys[envelope["kid"]]).decrypt(
                _decode(envelope["wn"]), _decode(envelope["key"]), context
            )
        except Exception:
            raise ValueError("Secret envelope authentication failed") from None

    def rewrap(self, value: bytes, aad: str) -> bytes:
        """Authenticate both layers, then wrap the SAME data key under current.

        Payload ciphertext and nonce remain identical, including for customer API
        keys. Even an already-current envelope is authenticated before return.
        """
        envelope = _envelope(value)
        context = _context(aad)
        key = self._unwrap(envelope, context)
        try:
            AESGCM(key).decrypt(_decode(envelope["n"]), _decode(envelope["data"]), context)
        except Exception:
            raise ValueError("Secret envelope authentication failed") from None
        target = self.active_key_id(aad)
        if envelope["kid"] == target:
            return value
        nonce = secrets.token_bytes(12)
        envelope.update(
            kid=target,
            wn=_encode(nonce),
            key=_encode(AESGCM(self.keys[target]).encrypt(nonce, key, context)),
        )
        return json.dumps(envelope, separators=(",", ":")).encode()


def _key_id(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is not None
    )


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate envelope field")
        result[key] = value
    return result


def _context(aad):
    if not isinstance(aad, str) or not aad:
        raise ValueError("An explicit secret purpose and identity are required")
    return ("appchi:1:" + aad).encode()


def _envelope(value):
    try:
        if type(value) is not bytes:
            raise ValueError()
        envelope = json.loads(value, object_pairs_hook=_unique)
        if not isinstance(envelope, dict) or set(envelope) != {
            "v",
            "kid",
            "n",
            "wn",
            "key",
            "data",
        }:
            raise ValueError()
        if type(envelope["v"]) is not int or envelope["v"] != 1 or not _key_id(envelope["kid"]):
            raise ValueError()
        if (
            len(_decode(envelope["n"])) != 12
            or len(_decode(envelope["wn"])) != 12
            or len(_decode(envelope["key"])) != 48
            or len(_decode(envelope["data"])) < 16
        ):
            raise ValueError()
        return envelope
    except (ValueError, TypeError, KeyError):
        raise ValueError("Invalid secret envelope") from None


def _encode(value):
    return base64.urlsafe_b64encode(value).decode()


def _decode(value):
    if not isinstance(value, str):
        raise ValueError("Invalid envelope encoding")
    decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    if _encode(decoded) != value:
        raise ValueError("Invalid envelope encoding")
    return decoded
