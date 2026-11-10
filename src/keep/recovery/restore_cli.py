"""Controlled restore operations using a separately supplied recovery database identity."""

import argparse
import json
import os
from dataclasses import asdict

from keep.db import Database
from keep.recovery.restore import begin_restore, status, collect_restore
from keep.shared.errors import AppError
from keep.serialization import wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    begin = commands.add_parser("begin")
    begin.add_argument("--run-id", required=True)
    begin.add_argument("--previous-epoch", required=True)
    begin.add_argument("--deployment-epoch", required=True)
    begin.add_argument("--operation-reference", required=True)
    inspect = commands.add_parser("status")
    inspect.add_argument("run_id")
    collect = commands.add_parser("collect")
    collect.add_argument("run_id")
    assess = commands.add_parser("assess", help="Read-only blockers; never reopens capabilities")
    assess.add_argument("run_id")
    assess.add_argument("--deployment-epoch", required=True)
    args = parser.parse_args()
    db = None
    try:
        # This explicit offline connection is not available as a runtime setting.
        db = Database(os.environ["KEEP_RECOVERY_DATABASE_URL"], 1)
        if args.command == "begin":
            row = begin_restore(
                db,
                run_id=args.run_id,
                previous_epoch=args.previous_epoch,
                deployment_epoch=args.deployment_epoch,
                operation_reference=args.operation_reference,
            )
        elif args.command == "collect":
            from keep.config import Settings
            from keep.recovery.runtime import configured_store

            store = configured_store(Settings())
            try:
                row = collect_restore(db, store, args.run_id)
            finally:
                store.close()
        elif args.command == "assess":
            from keep.recovery.assessment import assess_restore

            row = asdict(assess_restore(db, args.run_id, deployment_epoch=args.deployment_epoch))
        else:
            row = status(db, args.run_id)
        print(json.dumps({"data": wire(row), "ready": False}))
    except Exception as error:
        print(
            json.dumps(
                {"error": error.code if isinstance(error, AppError) else "restore_operation_failed"}
            )
        )
        raise SystemExit(1) from None
    finally:
        if db:
            db.close()


if __name__ == "__main__":
    main()
