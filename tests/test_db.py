from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

def test_task_deduplication_and_account_lock(database):
    database.upsert_account_snapshot({"sub2api_account_id": 7, "username": "demo", "status": "error"})
    first, created = database.create_task(7, trigger="scan")
    second, second_created = database.create_task(7, trigger="scan")
    assert created
    assert not second_created
    assert first == second

    lock = database.acquire_account_lock(7)
    assert lock
    assert database.acquire_account_lock(7) is None
    database.release_account_lock(7, lock)
    assert database.acquire_account_lock(7)


def test_credentials_are_encrypted_and_not_returned(database):
    database.upsert_account_snapshot({"sub2api_account_id": 8, "username": "private", "status": "unknown"})
    database.save_credentials(8, {"access_token": "access-secret", "refresh_token": "refresh-secret"})
    row = database.get_mapping(8)
    assert "access-secret" not in str(row)
    assert "refresh-secret" not in str(row)
    assert database.load_credentials(8)["refresh_token"] == "refresh-secret"


def test_stale_running_tasks_are_requeued_after_restart(database):
    database.upsert_account_snapshot({"sub2api_account_id": 12, "status": "auth_failed"})
    task_id, _ = database.create_task(12, trigger="scan")
    claimed = database.claim_next_task("stopped-worker")
    assert claimed["id"] == task_id

    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    with database.connect() as conn:
        conn.execute("UPDATE recovery_tasks SET updated_at=? WHERE id=?", (old, task_id))

    assert database.requeue_stale_tasks(stale_after_seconds=900) == 1
    recovered = database.get_task(task_id)
    assert recovered["status"] == "queued"
    assert recovered["stage"] == "recovered_after_restart"
    assert database.claim_next_task("new-worker")["id"] == task_id


def test_backup_creates_a_readable_snapshot(database, tmp_path):
    database.upsert_account_snapshot({"sub2api_account_id": 13, "email": "backup@example.com"})
    destination = tmp_path / "backups" / "snapshot.db"

    assert database.backup(str(destination)) == destination
    assert destination.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(destination) as snapshot:
        row = snapshot.execute(
            "SELECT email FROM account_mapping WHERE sub2api_account_id = 13"
        ).fetchone()
    assert row == ("backup@example.com",)


def test_event_details_are_redacted(database):
    database.record_event(
        "test",
        "OAuth failure",
        {"reason": "Authorization: Bearer live-token https://user:password@example.test"},
    )

    with sqlite3.connect(database.path) as connection:
        detail = connection.execute(
            "SELECT detail_json FROM app_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    assert "live-token" not in detail
    assert "user:password" not in detail


def test_account_scan_reconciles_removed_and_readded_accounts(database):
    database.upsert_account_snapshot({"sub2api_account_id": 7, "email": "seven@example.com", "status": "active"})
    database.upsert_account_snapshot({"sub2api_account_id": 8, "email": "eight@example.com", "status": "active"})

    assert database.mark_accounts_missing({7}) == 1
    assert [row["sub2api_account_id"] for row in database.list_accounts()] == [7]
    assert database.get_mapping(8)["remote_present"] == 0

    database.upsert_account_snapshot({"sub2api_account_id": 8, "email": "eight@example.com", "status": "active"})
    assert {row["sub2api_account_id"] for row in database.list_accounts()} == {7, 8}
