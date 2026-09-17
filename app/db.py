from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .redaction import redact, redact_text
from .security import SecretBox


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    serialized = json.dumps(redact(value), ensure_ascii=True, separators=(",", ":"))
    return redact_text(serialized)


class Database:
    """SQLite persistence with short-lived connections and explicit transactions."""

    def __init__(self, path: str, secret_box: SecretBox):
        self.path = Path(path)
        self.secret_box = secret_box
        self._init_lock = threading.Lock()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("PRAGMA journal_mode = WAL")
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._init_lock:
            with self.connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schema_version (
                        version INTEGER NOT NULL
                    );
                    INSERT INTO schema_version(version)
                    SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

                    CREATE TABLE IF NOT EXISTS account_mapping (
                        sub2api_account_id INTEGER PRIMARY KEY,
                        account_type TEXT NOT NULL DEFAULT 'oauth',
                        email TEXT NOT NULL DEFAULT '',
                        username TEXT NOT NULL DEFAULT '',
                        email_password_encrypted TEXT,
                        openai_password_encrypted TEXT,
                        totp_secret_encrypted TEXT,
                        credentials_encrypted TEXT,
                        status TEXT NOT NULL DEFAULT 'unknown',
                        failure_class TEXT,
                        failure_reason TEXT,
                        last_401_at TEXT,
                        last_recovery_at TEXT,
                        last_test_at TEXT,
                        last_seen_at TEXT,
                        remote_present INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS recovery_tasks (
                        id TEXT PRIMARY KEY,
                        sub2api_account_id INTEGER NOT NULL,
                        trigger TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'queued',
                        stage TEXT NOT NULL DEFAULT 'queued',
                        attempt INTEGER NOT NULL DEFAULT 0,
                        failure_class TEXT,
                        error_reason TEXT,
                        auth_session_id TEXT,
                        worker_id TEXT,
                        available_at TEXT NOT NULL,
                        started_at TEXT,
                        finished_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(sub2api_account_id) REFERENCES account_mapping(sub2api_account_id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_recovery_tasks_queue
                        ON recovery_tasks(status, available_at, created_at);
                    CREATE INDEX IF NOT EXISTS idx_recovery_tasks_account
                        ON recovery_tasks(sub2api_account_id, status);

                    CREATE TABLE IF NOT EXISTS recovery_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task_id TEXT NOT NULL,
                        level TEXT NOT NULL,
                        stage TEXT NOT NULL,
                        message TEXT NOT NULL,
                        detail_json TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(task_id) REFERENCES recovery_tasks(id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_recovery_logs_task
                        ON recovery_logs(task_id, created_at, id);

                    CREATE TABLE IF NOT EXISTS oauth_sessions (
                        id TEXT PRIMARY KEY,
                        sub2api_account_id INTEGER NOT NULL,
                        task_id TEXT,
                        state TEXT NOT NULL UNIQUE,
                        code_verifier_encrypted TEXT NOT NULL,
                        redirect_uri TEXT NOT NULL,
                        auth_url TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        error_reason TEXT,
                        token_payload_encrypted TEXT,
                        expires_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        completed_at TEXT,
                        FOREIGN KEY(sub2api_account_id) REFERENCES account_mapping(sub2api_account_id),
                        FOREIGN KEY(task_id) REFERENCES recovery_tasks(id) ON DELETE SET NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_oauth_sessions_state
                        ON oauth_sessions(state, status, expires_at);

                    CREATE TABLE IF NOT EXISTS account_locks (
                        sub2api_account_id INTEGER PRIMARY KEY,
                        lock_token TEXT NOT NULL,
                        locked_until TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS app_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        message TEXT NOT NULL,
                        detail_json TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS runtime_settings (
                        key TEXT PRIMARY KEY,
                        value_encrypted TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS runtime_settings_meta (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        revision INTEGER NOT NULL DEFAULT 0,
                        active_profile_id TEXT
                    );
                    INSERT INTO runtime_settings_meta(id, revision)
                    SELECT 1, 0 WHERE NOT EXISTS (SELECT 1 FROM runtime_settings_meta WHERE id = 1);
                    """
                )
                columns = {row[1] for row in conn.execute("PRAGMA table_info(account_mapping)")}
                if "account_type" not in columns:
                    conn.execute(
                        "ALTER TABLE account_mapping ADD COLUMN account_type TEXT NOT NULL DEFAULT 'oauth'"
                    )
                if "remote_present" not in columns:
                    conn.execute(
                        "ALTER TABLE account_mapping ADD COLUMN remote_present INTEGER NOT NULL DEFAULT 1"
                    )
                runtime_meta_columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(runtime_settings_meta)")
                }
                if "active_profile_id" not in runtime_meta_columns:
                    conn.execute(
                        "ALTER TABLE runtime_settings_meta ADD COLUMN active_profile_id TEXT"
                    )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS runtime_setting_profiles (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        values_encrypted TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )

    def load_runtime_settings(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT key, value_encrypted FROM runtime_settings ORDER BY key"
            ).fetchall()
        result: dict[str, Any] = {}
        for row in rows:
            raw = self.secret_box.decrypt(row["value_encrypted"])
            if raw is not None:
                result[str(row["key"])] = json.loads(raw)
        return result

    def runtime_settings_revision(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT revision FROM runtime_settings_meta WHERE id = 1"
            ).fetchone()
        return int(row["revision"]) if row else 0

    def active_runtime_profile_id(self) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT active_profile_id FROM runtime_settings_meta WHERE id = 1"
            ).fetchone()
        return str(row["active_profile_id"]) if row and row["active_profile_id"] else None

    def list_runtime_profiles(self) -> list[dict[str, Any]]:
        active_id = self.active_runtime_profile_id()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, name, created_at, updated_at FROM runtime_setting_profiles ORDER BY name"
            ).fetchall()
        return [
            {
                "id": str(row["id"]),
                "name": str(row["name"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "active": str(row["id"]) == active_id,
            }
            for row in rows
        ]

    def get_runtime_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, name, values_encrypted, created_at, updated_at "
                "FROM runtime_setting_profiles WHERE id = ?",
                (profile_id,),
            ).fetchone()
        if not row:
            return None
        raw = self.secret_box.decrypt(row["values_encrypted"])
        values = json.loads(raw) if raw else {}
        if not isinstance(values, dict):
            raise ValueError("runtime setting profile payload must be an object")
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "values": values,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_runtime_profile(self, name: str, values: dict[str, Any]) -> dict[str, Any]:
        profile_id = str(uuid.uuid4())
        now = utc_now()
        encrypted = self.secret_box.encrypt(
            json.dumps(values, ensure_ascii=True, separators=(",", ":"))
        )
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO runtime_setting_profiles(id, name, values_encrypted, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (profile_id, name, encrypted, now, now),
            )
        return {"id": profile_id, "name": name, "created_at": now, "updated_at": now}

    def activate_runtime_profile(self, profile_id: str) -> int:
        profile = self.get_runtime_profile(profile_id)
        if not profile:
            raise KeyError("runtime setting profile not found")
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM runtime_settings")
            for key, value in profile["values"].items():
                encrypted = self.secret_box.encrypt(
                    json.dumps(value, ensure_ascii=True, separators=(",", ":"))
                )
                conn.execute(
                    """
                    INSERT INTO runtime_settings(key, value_encrypted, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (key, encrypted, now),
                )
            conn.execute(
                "UPDATE runtime_settings_meta SET revision = revision + 1, active_profile_id = ? WHERE id = 1",
                (profile_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT revision FROM runtime_settings_meta WHERE id = 1"
            ).fetchone()
        return int(row["revision"]) if row else 0

    def delete_runtime_profile(self, profile_id: str) -> bool:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            deleted = conn.execute(
                "DELETE FROM runtime_setting_profiles WHERE id = ?", (profile_id,)
            ).rowcount
            if deleted:
                conn.execute(
                    "UPDATE runtime_settings_meta SET active_profile_id = NULL WHERE active_profile_id = ?",
                    (profile_id,),
                )
            conn.commit()
        return bool(deleted)

    def save_runtime_settings(
        self,
        values: dict[str, Any],
        *,
        clear_keys: list[str] | tuple[str, ...] = (),
    ) -> int:
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for key in clear_keys:
                conn.execute("DELETE FROM runtime_settings WHERE key = ?", (key,))
            for key, value in values.items():
                encrypted = self.secret_box.encrypt(
                    json.dumps(value, ensure_ascii=True, separators=(",", ":"))
                )
                conn.execute(
                    """
                    INSERT INTO runtime_settings(key, value_encrypted, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_encrypted=excluded.value_encrypted,
                        updated_at=excluded.updated_at
                    """,
                    (key, encrypted, now),
                )
            conn.execute(
                "UPDATE runtime_settings_meta SET revision = revision + 1, active_profile_id = NULL WHERE id = 1"
            )
            conn.commit()
            row = conn.execute(
                "SELECT revision FROM runtime_settings_meta WHERE id = 1"
            ).fetchone()
        return int(row["revision"]) if row else 0

    def clear_runtime_settings(self) -> int:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM runtime_settings")
            conn.execute(
                "UPDATE runtime_settings_meta SET revision = revision + 1, active_profile_id = NULL WHERE id = 1"
            )
            conn.commit()
            row = conn.execute(
                "SELECT revision FROM runtime_settings_meta WHERE id = 1"
            ).fetchone()
        return int(row["revision"]) if row else 0

    def upsert_account_snapshot(self, snapshot: dict[str, Any]) -> None:
        account_id = int(snapshot["sub2api_account_id"])
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO account_mapping(
                    sub2api_account_id, account_type, email, username, status, last_seen_at,
                    remote_present, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sub2api_account_id) DO UPDATE SET
                    account_type = CASE WHEN excluded.account_type <> '' THEN excluded.account_type ELSE account_mapping.account_type END,
                    email = CASE WHEN excluded.email <> '' THEN excluded.email ELSE account_mapping.email END,
                    username = CASE WHEN excluded.username <> '' THEN excluded.username ELSE account_mapping.username END,
                    status = CASE WHEN account_mapping.status NOT IN ('unknown', 'observed')
                                  THEN account_mapping.status ELSE excluded.status END,
                    remote_present = 1,
                    last_seen_at = excluded.last_seen_at,
                    updated_at = excluded.updated_at
                """,
                (
                    account_id,
                    str(snapshot.get("account_type") or "oauth"),
                    str(snapshot.get("email") or ""),
                    str(snapshot.get("username") or snapshot.get("name") or ""),
                    str(snapshot.get("status") or "unknown"),
                    now,
                    1,
                    now,
                    now,
                ),
            )

    def mark_accounts_missing(self, account_ids: set[int]) -> int:
        """Hide local mappings absent from a successful remote account scan."""
        now = utc_now()
        with self.connect() as conn:
            if account_ids:
                placeholders = ", ".join("?" for _ in account_ids)
                cursor = conn.execute(
                    f"""
                    UPDATE account_mapping
                    SET remote_present = 0, updated_at = ?
                    WHERE remote_present = 1
                      AND sub2api_account_id NOT IN ({placeholders})
                    """,
                    (now, *sorted(account_ids)),
                )
            else:
                cursor = conn.execute(
                    "UPDATE account_mapping SET remote_present = 0, updated_at = ? WHERE remote_present = 1",
                    (now,),
                )
        return max(0, int(cursor.rowcount))

    def get_mapping(self, account_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM account_mapping WHERE sub2api_account_id = ?", (account_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_accounts(self, *, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM account_mapping
                WHERE remote_present = 1
                ORDER BY CASE status WHEN 'auth_failed' THEN 0
                                     WHEN 'reauth_required' THEN 1
                                     WHEN 'recovering' THEN 2 ELSE 3 END,
                         COALESCE(last_401_at, '') DESC, sub2api_account_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_credentials(
        self,
        account_id: int,
        credentials: dict[str, Any],
        *,
        email: str | None = None,
        username: str | None = None,
    ) -> None:
        known = {
            "email_password": credentials.get("email_password") or credentials.get("password"),
            "openai_password": credentials.get("openai_password"),
            "totp_secret": credentials.get("totp_secret"),
        }
        encrypted_known = {
            key: self.secret_box.encrypt(str(value)) if value else None
            for key, value in known.items()
        }
        payload = {str(key): value for key, value in credentials.items() if value is not None}
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE account_mapping SET
                    email = CASE WHEN ? <> '' THEN ? ELSE email END,
                    username = CASE WHEN ? <> '' THEN ? ELSE username END,
                    email_password_encrypted = COALESCE(?, email_password_encrypted),
                    openai_password_encrypted = COALESCE(?, openai_password_encrypted),
                    totp_secret_encrypted = COALESCE(?, totp_secret_encrypted),
                    credentials_encrypted = ?, updated_at = ?
                WHERE sub2api_account_id = ?
                """,
                (
                    email or "",
                    email or "",
                    username or "",
                    username or "",
                    encrypted_known["email_password"],
                    encrypted_known["openai_password"],
                    encrypted_known["totp_secret"],
                    self.secret_box.encrypt_json(payload),
                    now,
                    account_id,
                ),
            )

    def load_credentials(self, account_id: int) -> dict[str, Any]:
        row = self.get_mapping(account_id)
        if not row:
            return {}
        credentials = self.secret_box.decrypt_json(row.get("credentials_encrypted"))
        for encrypted_key, output_key in (
            ("email_password_encrypted", "email_password"),
            ("openai_password_encrypted", "openai_password"),
            ("totp_secret_encrypted", "totp_secret"),
        ):
            if output_key not in credentials and row.get(encrypted_key):
                value = self.secret_box.decrypt(row[encrypted_key])
                if value:
                    credentials[output_key] = value
        return credentials

    def update_account_state(
        self,
        account_id: int,
        *,
        status: str,
        failure_class: str | None = None,
        failure_reason: str | None = None,
        mark_401: bool = False,
        mark_recovery: bool = False,
        mark_test: bool = False,
    ) -> None:
        now = utc_now()
        assignments = ["status = ?", "failure_class = ?", "failure_reason = ?", "updated_at = ?"]
        values: list[Any] = [status, failure_class, failure_reason, now]
        if mark_401:
            assignments.append("last_401_at = ?")
            values.append(now)
        if mark_recovery:
            assignments.append("last_recovery_at = ?")
            values.append(now)
        if mark_test:
            assignments.append("last_test_at = ?")
            values.append(now)
        values.append(account_id)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE account_mapping SET {', '.join(assignments)} WHERE sub2api_account_id = ?",
                values,
            )

    def create_task(
        self,
        account_id: int,
        *,
        trigger: str,
        force: bool = False,
    ) -> tuple[str, bool]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT id, status FROM recovery_tasks
                WHERE sub2api_account_id = ?
                  AND status IN ('queued', 'running', 'manual_required')
                ORDER BY created_at DESC LIMIT 1
                """,
                (account_id,),
            ).fetchone()
            if existing:
                if not force or existing["status"] in ("queued", "running"):
                    conn.commit()
                    return str(existing["id"]), False
                conn.execute(
                    """
                    UPDATE recovery_tasks SET status='queued', stage='queued',
                        failure_class=NULL, error_reason=NULL, auth_session_id=NULL,
                        worker_id=NULL, started_at=NULL, finished_at=NULL,
                        available_at=?, updated_at=? WHERE id=?
                    """,
                    (now, now, existing["id"]),
                )
                conn.commit()
                return str(existing["id"]), True
            task_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO recovery_tasks(
                    id, sub2api_account_id, trigger, status, stage,
                    available_at, created_at, updated_at
                ) VALUES (?, ?, ?, 'queued', 'queued', ?, ?, ?)
                """,
                (task_id, account_id, trigger, now, now, now),
            )
            conn.commit()
            return task_id, True

    def skip_pending_tasks(self, account_id: int, reason: str) -> list[str]:
        now = utc_now()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id FROM recovery_tasks
                WHERE sub2api_account_id=? AND status IN ('queued', 'running', 'manual_required')
                """,
                (account_id,),
            ).fetchall()
            conn.execute(
                """
                UPDATE recovery_tasks SET status='skipped', stage='automation_blocked',
                    error_reason=?, finished_at=?, updated_at=?
                WHERE sub2api_account_id=? AND status IN ('queued', 'running', 'manual_required')
                """,
                (safe_message(reason), now, now, account_id),
            )
            conn.execute(
                """
                UPDATE oauth_sessions SET status='cancelled', error_reason=?, completed_at=?
                WHERE sub2api_account_id=? AND status='pending'
                """,
                (safe_message(reason), now, account_id),
            )
        return [str(row["id"]) for row in rows]

    def claim_next_task(self, worker_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT * FROM recovery_tasks
                WHERE status='queued' AND available_at <= ?
                ORDER BY created_at LIMIT 1
                """,
                (now,),
            ).fetchone()
            if not row:
                conn.commit()
                return None
            attempt = int(row["attempt"]) + 1
            conn.execute(
                """
                UPDATE recovery_tasks SET status='running', stage='starting',
                    attempt=?, worker_id=?, started_at=COALESCE(started_at, ?), updated_at=?
                WHERE id=? AND status='queued'
                """,
                (attempt, worker_id, now, now, row["id"]),
            )
            conn.commit()
            claimed = dict(row)
            claimed.update(status="running", stage="starting", attempt=attempt, worker_id=worker_id)
            return claimed

    def requeue_stale_tasks(self, *, stale_after_seconds: int = 900) -> int:
        """Return tasks abandoned by a stopped worker to the durable queue."""

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=max(60, stale_after_seconds))).isoformat(timespec="seconds")
        available_at = now.isoformat(timespec="seconds")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id FROM recovery_tasks WHERE status='running' AND updated_at < ?",
                (cutoff,),
            ).fetchall()
            if not rows:
                conn.commit()
                return 0
            conn.execute(
                """
                UPDATE recovery_tasks SET status='queued', stage='recovered_after_restart',
                    worker_id=NULL, finished_at=NULL, available_at=?,
                    error_reason=?, updated_at=?
                WHERE status='running' AND updated_at < ?
                """,
                (
                    available_at,
                    "Worker lease expired; task was requeued after restart",
                    available_at,
                    cutoff,
                ),
            )
            conn.commit()
            return len(rows)

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM recovery_tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT t.*, m.email, m.username FROM recovery_tasks t
                LEFT JOIN account_mapping m ON m.sub2api_account_id=t.sub2api_account_id
                ORDER BY t.created_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_task_stage(self, task_id: str, stage: str, *, status: str | None = None) -> None:
        values: list[Any] = [stage, utc_now()]
        sql = "UPDATE recovery_tasks SET stage=?, updated_at=?"
        if status is not None:
            sql += ", status=?"
            values.append(status)
        sql += " WHERE id=?"
        values.append(task_id)
        with self.connect() as conn:
            conn.execute(sql, values)

    def set_task_auth_session(self, task_id: str, session_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE recovery_tasks SET auth_session_id=?, updated_at=? WHERE id=?",
                (session_id, utc_now(), task_id),
            )

    def finish_task(
        self,
        task_id: str,
        *,
        status: str,
        failure_class: str | None = None,
        error_reason: str | None = None,
        stage: str | None = None,
        available_at: str | None = None,
    ) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE recovery_tasks SET status=?, stage=COALESCE(?, stage),
                    failure_class=?, error_reason=?, finished_at=?, available_at=COALESCE(?, available_at),
                    updated_at=? WHERE id=?
                """,
                (status, stage, failure_class, error_reason, now, available_at, now, task_id),
            )

    def force_retry_task(self, task_id: str) -> bool:
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE recovery_tasks SET status='queued', stage='queued',
                    failure_class=NULL, error_reason=NULL, auth_session_id=NULL,
                    worker_id=NULL, started_at=NULL, finished_at=NULL,
                    available_at=?, updated_at=?
                WHERE id=? AND status IN ('queued', 'manual_required')
                """,
                (now, now, task_id),
            )
        return cursor.rowcount > 0

    def append_log(
        self,
        task_id: str,
        *,
        level: str,
        stage: str,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO recovery_logs(task_id, level, stage, message, detail_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, level, stage, safe_message(message), _json(detail) if detail else None, utc_now()),
            )

    def list_logs(self, task_id: str, *, limit: int = 300) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, task_id, level, stage, message, detail_json, created_at
                FROM recovery_logs WHERE task_id=? ORDER BY id LIMIT ?
                """,
                (task_id, limit),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if item.get("detail_json"):
                try:
                    item["detail"] = json.loads(item.pop("detail_json"))
                except json.JSONDecodeError:
                    item["detail"] = None
            else:
                item.pop("detail_json", None)
            result.append(item)
        return result

    def acquire_account_lock(self, account_id: int, *, ttl_seconds: int = 300) -> str | None:
        import time

        lock_token = str(uuid.uuid4())
        deadline = datetime.fromtimestamp(time.time() + ttl_seconds, tz=timezone.utc).isoformat(
            timespec="seconds"
        )
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT locked_until FROM account_locks WHERE sub2api_account_id=?", (account_id,)
            ).fetchone()
            if row and str(row["locked_until"]) > now:
                conn.rollback()
                return None
            conn.execute(
                """
                INSERT INTO account_locks(sub2api_account_id, lock_token, locked_until, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sub2api_account_id) DO UPDATE SET
                    lock_token=excluded.lock_token, locked_until=excluded.locked_until,
                    updated_at=excluded.updated_at
                """,
                (account_id, lock_token, deadline, now),
            )
            conn.commit()
        return lock_token

    def release_account_lock(self, account_id: int, lock_token: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM account_locks WHERE sub2api_account_id=? AND lock_token=?",
                (account_id, lock_token),
            )

    def get_oauth_session(self, session_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM oauth_sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def get_oauth_session_by_state(self, state: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM oauth_sessions WHERE state=?", (state,)).fetchone()
        return dict(row) if row else None

    def create_oauth_session(self, session: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO oauth_sessions(
                    id, sub2api_account_id, task_id, state, code_verifier_encrypted,
                    redirect_uri, auth_url, status, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    session["id"],
                    session["sub2api_account_id"],
                    session.get("task_id"),
                    session["state"],
                    self.secret_box.encrypt(session["code_verifier"]),
                    session["redirect_uri"],
                    session["auth_url"],
                    session["expires_at"],
                    utc_now(),
                ),
            )

    def complete_oauth_session(
        self,
        session_id: str,
        *,
        status: str,
        token_payload: dict[str, Any] | None = None,
        error_reason: str | None = None,
    ) -> None:
        now = utc_now()
        encrypted = self.secret_box.encrypt_json(token_payload) if token_payload else None
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE oauth_sessions SET status=?, token_payload_encrypted=?,
                    error_reason=?, completed_at=? WHERE id=?
                """,
                (status, encrypted, error_reason, now, session_id),
            )

    def load_oauth_token_payload(self, session_id: str) -> dict[str, Any]:
        session = self.get_oauth_session(session_id)
        if not session:
            return {}
        return self.secret_box.decrypt_json(session.get("token_payload_encrypted"))

    def dashboard_summary(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS count FROM account_mapping WHERE remote_present = 1 GROUP BY status"
            ).fetchall()
            tasks = conn.execute(
                """
                SELECT status, COUNT(*) AS count FROM recovery_tasks
                WHERE created_at >= ? GROUP BY status
                """,
                ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds"),),
            ).fetchall()
        accounts = {str(row["status"]): int(row["count"]) for row in rows}
        task_counts = {str(row["status"]): int(row["count"]) for row in tasks}
        return {
            "accounts": sum(accounts.values()),
            "auth_failures": accounts.get("auth_failed", 0) + accounts.get("reauth_required", 0),
            "recovering": accounts.get("recovering", 0),
            "success": task_counts.get("succeeded", 0),
            "failed": task_counts.get("failed", 0),
            "manual_required": task_counts.get("manual_required", 0),
        }

    def record_event(self, event_type: str, message: str, detail: dict[str, Any] | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO app_events(event_type, message, detail_json, created_at) VALUES (?, ?, ?, ?)",
                (event_type, safe_message(message), _json(detail) if detail else None, utc_now()),
            )

    def backup(self, destination: str) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = destination_path.with_suffix(destination_path.suffix + ".partial")
        if temp_path.exists():
            temp_path.unlink()
        try:
            with self.connect() as source:
                target = sqlite3.connect(temp_path)
                try:
                    source.backup(target)
                    target.commit()
                finally:
                    target.close()
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        os.replace(temp_path, destination_path)
        try:
            os.chmod(destination_path, 0o600)
        except OSError:
            pass
        return destination_path


def safe_message(message: str) -> str:
    from .redaction import safe_error

    return safe_error(message, max_length=1000)
