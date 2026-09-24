# ruff: noqa: F811
"""Offline warmup proves retained baselines without enabling capabilities."""

import pytest

from appchi.maintenance.processing import record_input
from appchi.maintenance.warmup import warmup_page, warmup_status
from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator

from test_maintenance_processing import PROFILE, publish_source
from test_maintenance_repository import maintenance_browser, maintenance_db  # noqa: F401

pytestmark = pytest.mark.integration


def disabled(db):
    with db.transaction() as conn:
        conn.execute("UPDATE capability_gates SET ready=false WHERE capability='maintenance'")


def test_warmup_complete_head_new_source_invalidation_and_idempotent_replay(
    maintenance_browser, maintenance_db
):
    _, tenant, _, _ = maintenance_browser
    db, _ = maintenance_db
    disabled(db)
    first, _, _ = publish_source(db, tenant, None, None)
    assert warmup_status(db, tenant) == {
        "retained": 1,
        "missing_baseline": 0,
        "complete": 0,
        "pending": 1,
    }
    result = warmup_page(db, tenant, PROFILE)
    assert result.completed == 1 and result.blocked == () and result.cursor is None
    assert warmup_status(db, tenant)["complete"] == 1
    with db.transaction(tenant) as conn:
        assert not conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='maintenance'"
        ).fetchone()["ready"]
        row = conn.execute(
            "SELECT * FROM alerts WHERE tenant_id=%s AND id=%s", (tenant, first["id"])
        ).fetchone()
        assert (
            row["revision"] == first["revision"]
            and row["projection_version"] == first["projection_version"]
        )
        original = conn.execute(
            "SELECT * FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s",
            (tenant, first["id"]),
        ).fetchone()
        coordinator(conn, tenant)
        record_input(
            conn,
            None,
            first,
            original["effective_at"],
            original["original_order"],
            original["kind"],
            original["recorded_at"],
        )
        assert (
            conn.execute(
                "SELECT input_revision FROM maintenance_alert_input_heads WHERE tenant_id=%s AND alert_id=%s",
                (tenant, first["id"]),
            ).fetchone()["input_revision"]
            == 1
        )
    assert warmup_status(db, tenant)["complete"] == 1
    repeated, changed, _ = publish_source(db, tenant, row, None)
    assert not changed and repeated["revision"] == first["revision"]
    assert warmup_status(db, tenant)["pending"] == 1
    assert warmup_page(db, tenant, PROFILE).completed == 1
    with db.transaction(tenant) as conn:
        proof = conn.execute(
            "SELECT * FROM maintenance_alert_checkpoints WHERE tenant_id=%s AND alert_id=%s",
            (tenant, first["id"]),
        ).fetchone()
        assert proof["input_revision"] == 2 and proof["complete"]


def test_warmup_never_invents_missing_creation_baseline(maintenance_browser, maintenance_db):
    _, tenant, _, _ = maintenance_browser
    db, _ = maintenance_db
    disabled(db)
    first, _, _ = publish_source(db, tenant, None, None)
    with db.transaction(tenant) as conn:
        conn.execute("DELETE FROM maintenance_alert_input_heads WHERE tenant_id=%s", (tenant,))
        conn.execute("DELETE FROM maintenance_alert_inputs WHERE tenant_id=%s", (tenant,))
    result = warmup_page(db, tenant, PROFILE)
    assert result.completed == 0 and result.blocked[0][0] == str(first["id"])
    assert warmup_status(db, tenant) == {
        "retained": 1,
        "missing_baseline": 1,
        "complete": 0,
        "pending": 1,
    }


def test_warmup_pages_and_explicit_qualification(maintenance_browser, maintenance_db):
    _, tenant, _, _ = maintenance_browser
    db, _ = maintenance_db
    disabled(db)
    for _ in range(3):
        publish_source(db, tenant, None, None)
    cursor, seen = None, 0
    while True:
        page = warmup_page(db, tenant, PROFILE, cursor=cursor, limit=1)
        seen += page.completed
        cursor = page.cursor
        if cursor is None:
            break
    assert seen == 3 and warmup_status(db, tenant)["complete"] == 3
    with pytest.raises(AppError, match="maintenance_capacity_profile_required"):
        warmup_page(db, tenant, {**PROFILE, "qualified": False})
