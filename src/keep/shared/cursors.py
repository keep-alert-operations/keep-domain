import base64
import json
from datetime import timedelta
from keep.shared.errors import AppError
from keep.serialization import wire


class Cursor:
    def __init__(self, cipher, context, now, ttl=900):
        self.cipher, self.context, self.now, self.ttl = cipher, context, now, ttl
        self.expires_at = now + timedelta(seconds=ttl)

    def encode(self, position, **extra):
        payload = {
            "context": self.context,
            "expires_at": wire(self.expires_at),
            "position": wire(position),
            **wire(extra),
        }
        return base64.urlsafe_b64encode(
            self.cipher.seal(json.dumps(payload).encode(), "cursor:v1")
        ).decode()

    def decode(self, token):
        from datetime import datetime

        try:
            payload = json.loads(self.cipher.open(base64.urlsafe_b64decode(token), "cursor:v1"))
            if payload["context"] != self.context:
                raise AppError("invalid_cursor", "Cursor context changed; restart pagination.", 409)
            if datetime.fromisoformat(payload["expires_at"]) <= self.now:
                raise AppError("cursor_expired", "Restart from the first page.", 409)
            self.expires_at = datetime.fromisoformat(payload["expires_at"])
            return payload
        except AppError:
            raise
        except Exception:
            raise AppError("invalid_cursor", "Cursor is invalid for this view.", 400) from None
