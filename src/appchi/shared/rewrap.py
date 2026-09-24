"""Bounded, compare-and-swap rewrap of the application's known secret columns."""

import argparse
import base64
import json
from dataclasses import asdict, dataclass
from time import monotonic
from uuid import UUID

from psycopg import sql

from appchi.shared.errors import unavailable


@dataclass(frozen=True)
class Family:
    table: str
    primary: str
    column: str
    purpose: str
    hashed: bool = False
    context: tuple[str, ...] = ()

    def aad(self, row):
        identity = bytes(row[self.primary]).hex() if self.hashed else str(row[self.primary])
        if self.context:
            return f"operator-key:{row['operator_id']}:{identity}:1"
        return self.purpose + identity


FAMILIES = {
    "operator-credentials": Family(
        "operator_credentials", "id", "ciphertext", "operator-key:", context=("operator_id",)
    ),
    "session-tokens": Family("auth_sessions", "handle_hash", "tokens", "session-tokens:", True),
    "session-csrf": Family("auth_sessions", "handle_hash", "csrf_cipher", "session-csrf:", True),
    "login-transactions": Family(
        "login_transactions", "state_hash", "encrypted_state", "login:", True
    ),
    "ingest-receipts": Family("ingest_requests", "id", "response_cipher", "receipt:"),
}


@dataclass(frozen=True)
class RewrapPage:
    family: str
    active_key_id: str
    examined: int
    needs_rewrap: int
    rewrapped: int
    already_current: int
    conflicts: int
    next_cursor: str | None


def _cursor_aad(cipher, family):
    target = cipher.active_key_id(FAMILIES[family].purpose)
    return f"rewrap-cursor:{family}:{target}:1"


def _position(cipher, family, token):
    try:
        value = json.loads(
            cipher.open(
                base64.b64decode(token, altchars=b"-_", validate=True),
                _cursor_aad(cipher, family),
            )
        )
        if not isinstance(value, dict) or set(value) != {"position"}:
            raise ValueError()
        position = value["position"]
        if FAMILIES[family].hashed:
            result = bytes.fromhex(position)
            if len(result) != 32 or result.hex() != position:
                raise ValueError()
            return result
        result = UUID(position)
        if str(result) != position:
            raise ValueError()
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise unavailable("rewrap_cursor_invalid") from None


def _cursor(cipher, family, position):
    value = bytes(position).hex() if FAMILIES[family].hashed else str(position)
    return base64.urlsafe_b64encode(
        cipher.seal(json.dumps({"position": value}).encode(), _cursor_aad(cipher, family))
    ).decode()


def _replace(db, spec, row, replacement):
    # Cipher work is finished before taking a row lock. An erase/refresh/rewrap
    # wins over this stale candidate; no lifecycle field is changed here.
    conditions = [
        sql.SQL("{}=%s").format(sql.Identifier(spec.primary)),
        sql.SQL("{}=%s").format(sql.Identifier(spec.column)),
    ]
    arguments = [replacement, row[spec.primary], row[spec.column]]
    for column in spec.context:
        conditions.append(sql.SQL("{} IS NOT DISTINCT FROM %s").format(sql.Identifier(column)))
        arguments.append(row[column])
    with db.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout='100ms'")
        conn.execute("SET LOCAL lock_timeout='50ms'")
        return (
            conn.execute(
                sql.SQL("UPDATE {} SET {}=%s WHERE {}").format(
                    sql.Identifier(spec.table),
                    sql.Identifier(spec.column),
                    sql.SQL(" AND ").join(conditions),
                ),
                arguments,
            ).rowcount
            == 1
        )


def rewrap_page(db, cipher, family, *, cursor=None, limit=100, verify_only=False):
    """One keyset page, at most 100 records; repeat passes after CAS conflicts.

    A completed scan is not key-retirement authority: concurrent inserts may sort
    behind its cursor, client-held cursors cannot be scanned, and backups may
    still require older wrapping versions.
    """
    if (
        family not in FAMILIES
        or type(limit) is not int
        or not 1 <= limit <= 100
        or type(verify_only) is not bool
    ):
        raise ValueError("Choose a known family and a page size from 1 to 100")
    spec = FAMILIES[family]
    columns = (spec.primary, spec.column, *spec.context)
    query = sql.SQL("SELECT {} FROM {} WHERE {} IS NOT NULL").format(
        sql.SQL(",").join(map(sql.Identifier, columns)),
        sql.Identifier(spec.table),
        sql.Identifier(spec.column),
    )
    arguments = []
    if cursor:
        query += sql.SQL(" AND {}>%s").format(sql.Identifier(spec.primary))
        arguments.append(_position(cipher, family, cursor))
    query += sql.SQL(" ORDER BY {} LIMIT %s").format(sql.Identifier(spec.primary))
    arguments.append(limit + 1)
    with db.transaction() as conn:
        rows = conn.execute(query, arguments).fetchall()
    examined = needs = changed = current = conflicts = 0
    started = monotonic()
    for row in rows[:limit]:
        old = bytes(row[spec.column])
        try:
            replacement = cipher.rewrap(old, spec.aad(row))
        except (ValueError, TypeError):
            raise unavailable("rewrap_authentication_failed") from None
        if replacement == old:
            current += 1
        else:
            needs += 1
            if not verify_only:
                if _replace(db, spec, row, replacement):
                    changed += 1
                else:
                    conflicts += 1
        examined += 1
        if monotonic() - started >= 0.1:
            break
    continuation = (
        _cursor(cipher, family, rows[examined - 1][spec.primary])
        if examined and len(rows) > examined
        else None
    )
    return RewrapPage(
        family,
        cipher.active_key_id(spec.purpose),
        examined,
        needs,
        changed,
        current,
        conflicts,
        continuation,
    )


def main():
    from appchi.config import Settings
    from appchi.db import Database

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=tuple(FAMILIES))
    parser.add_argument("--cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    db = None
    try:
        settings = Settings()
        cipher = settings.cipher()
        db = Database(
            settings.database_url.get_secret_value(),
            settings.pool_size,
            deployment_epoch=settings.deployment_epoch,
        )
        result = rewrap_page(
            db,
            cipher,
            args.family,
            cursor=args.cursor,
            limit=args.limit,
            verify_only=args.verify_only,
        )
        print(json.dumps(asdict(result)))
    except Exception:
        # No exception repr: driver errors can include secret-bearing parameters.
        print(json.dumps({"error": "rewrap_failed"}))
        raise SystemExit(1) from None
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    main()
