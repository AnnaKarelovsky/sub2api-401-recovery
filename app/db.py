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

    def __init__(self, path: str, secret_box: SecretBox, evidence_dir: str | None = None):
        self.path = Path(path)
        self.secret_box = secret_box
        self.evidence_dir = Path(evidence_dir) if evidence_dir else self.path.parent / "evidence"
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
                        last_upstream_probe_at TEXT,
                        last_seen_at TEXT,
                        materials_checked_at TEXT,
                        remote_present INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS mailbox_pool (
                        id TEXT PRIMARY KEY,
                        email TEXT NOT NULL UNIQUE,
                        password_encrypted TEXT,
                        source_account_id INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_accessed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_mailbox_pool_updated
                        ON mailbox_pool(updated_at, email);

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

                    CREATE TABLE IF NOT EXISTS task_evidence (
                        id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        content_type TEXT NOT NULL,
                        file_name TEXT NOT NULL UNIQUE,
                        size_bytes INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(task_id) REFERENCES recovery_tasks(id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_task_evidence_task
                        ON task_evidence(task_id, created_at);

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

                    CREATE TABLE IF NOT EXISTS account_enrollments (
                        id TEXT PRIMARY KEY,
                        email TEXT NOT NULL,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'queued',
                        stage TEXT NOT NULL DEFAULT 'queued',
                        message TEXT NOT NULL DEFAULT '',
                        auth_url TEXT NOT NULL,
                        state TEXT NOT NULL,
                        code_verifier_encrypted TEXT NOT NULL,
                        materials_encrypted TEXT NOT NULL,
                        sub2api_account_id INTEGER,
                        error_reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        started_at TEXT,
                        finished_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_account_enrollments_queue
                        ON account_enrollments(status, created_at);

                    CREATE TABLE IF NOT EXISTS account_enrollment_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        enrollment_id TEXT NOT NULL,
                        level TEXT NOT NULL,
                        stage TEXT NOT NULL,
                        message TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(enrollment_id) REFERENCES account_enrollments(id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_account_enrollment_logs
                        ON account_enrollment_logs(enrollment_id, id);

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
                if "materials_checked_at" not in columns:
                    conn.execute(
                        "ALTER TABLE account_mapping ADD COLUMN materials_checked_at TEXT"
                    )
                if "last_upstream_probe_at" not in columns:
                    conn.execute(
                        "ALTER TABLE account_mapping ADD COLUMN last_upstream_probe_at TEXT"
                    )
                self._migrate_mailbox_pool(conn)
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

    def _migrate_mailbox_pool(self, conn: sqlite3.Connection) -> None:
        """Copy existing email materials before account deletion can remove them."""
        rows = conn.execute(
            """
            SELECT sub2api_account_id, email, email_password_encrypted
            FROM account_mapping
            WHERE TRIM(email) <> ''
            """
        ).fetchall()
        now = utc_now()
        for row in rows:
            email = str(row["email"] or "").strip().lower()
            if not email:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO mailbox_pool(
                    id, email, password_encrypted, source_account_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    email,
                    row["email_password_encrypted"],
                    int(row["sub2api_account_id"]),
                    now,
                    now,
                ),
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

    def mark_account_deleted(self, account_id: int, reason: str) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE account_mapping SET status='account_deleted', remote_present=0,
                    failure_class='ACCOUNT_ERROR', failure_reason=?,
                    email_password_encrypted=NULL, openai_password_encrypted=NULL,
                    totp_secret_encrypted=NULL, credentials_encrypted=NULL,
                    updated_at=? WHERE sub2api_account_id=?
                """,
                (safe_message(reason), now, account_id),
            )
            conn.execute("DELETE FROM oauth_sessions WHERE sub2api_account_id=?", (account_id,))

    def get_mapping(self, account_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM account_mapping WHERE sub2api_account_id = ?", (account_id,)
            ).fetchone()
        return dict(row) if row else None

    def latest_task_for_account(self, account_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM recovery_tasks WHERE sub2api_account_id=? ORDER BY created_at DESC LIMIT 1",
                (account_id,),
            ).fetchone()
        return dict(row) if row else None

    def task_has_evidence(self, task_id: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT file_name FROM task_evidence WHERE task_id=? LIMIT 1",
                (task_id,),
            ).fetchone()
        if not row:
            return False
        file_name = str(row["file_name"])
        return Path(file_name).name == file_name and (self.evidence_dir / file_name).is_file()

    def finalize_account_deletion(
        self,
        account_id: int,
        task_id: str,
        *,
        already_absent: bool = False,
    ) -> None:
        now = utc_now()
        message = (
            "所选账号已确认不在 Sub2API 中；恢复日志和诊断截图已保留。"
            if already_absent
            else "账号已由管理员从 Sub2API 删除；恢复日志和诊断截图已保留。"
        )
        detail = _json(
            {"account_id": account_id, "evidence_retained": True, "already_absent": already_absent}
        )
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE account_mapping SET status='account_deleted', remote_present=0,
                    email_password_encrypted=NULL, openai_password_encrypted=NULL,
                    totp_secret_encrypted=NULL, credentials_encrypted=NULL,
                    updated_at=? WHERE sub2api_account_id=? AND remote_present=1
                """,
                (now, account_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise ValueError("account mapping changed before local deletion was finalized")
            conn.execute("DELETE FROM oauth_sessions WHERE sub2api_account_id=?", (account_id,))
            conn.execute(
                """
                INSERT INTO recovery_logs(task_id, level, stage, message, detail_json, created_at)
                VALUES (?, 'WARNING', 'account_deleted', ?, ?, ?)
                """,
                (task_id, message, detail, now),
            )
            conn.commit()

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
        credential_email = str(email or credentials.get("email") or "").strip().lower()
        if credential_email:
            self.upsert_mailbox(
                credential_email,
                known["email_password"],
                source_account_id=account_id,
            )

    def upsert_mailbox(
        self,
        email: str,
        password: str | None = None,
        *,
        source_account_id: int | None = None,
    ) -> str:
        normalized_email = str(email or "").strip().lower()
        if not normalized_email or "@" not in normalized_email:
            raise ValueError("mailbox email is invalid")
        now = utc_now()
        encrypted_password = self.secret_box.encrypt(password.strip()) if password and password.strip() else None
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT id, password_encrypted FROM mailbox_pool WHERE email=?",
                (normalized_email,),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE mailbox_pool SET
                        password_encrypted=COALESCE(?, password_encrypted),
                        source_account_id=COALESCE(?, source_account_id), updated_at=?
                    WHERE id=?
                    """,
                    (encrypted_password, source_account_id, now, str(existing["id"])),
                )
                return str(existing["id"])
            mailbox_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO mailbox_pool(
                    id, email, password_encrypted, source_account_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (mailbox_id, normalized_email, encrypted_password, source_account_id, now, now),
            )
            return mailbox_id

    def list_mailboxes(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT p.id, p.email, p.source_account_id, p.created_at, p.updated_at,
                    p.last_accessed_at, (p.password_encrypted IS NOT NULL) AS has_password,
                    m.status AS source_account_status, m.remote_present AS source_account_present
                FROM mailbox_pool p
                LEFT JOIN account_mapping m ON m.sub2api_account_id=p.source_account_id
                ORDER BY p.updated_at DESC, p.email
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_mailbox(self, mailbox_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM mailbox_pool WHERE id=?", (mailbox_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_mailbox_secret(self, mailbox_id: str) -> dict[str, str] | None:
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT email, password_encrypted FROM mailbox_pool WHERE id=?",
                (mailbox_id,),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE mailbox_pool SET last_accessed_at=? WHERE id=?",
                (now, mailbox_id),
            )
        return {
            "email": str(row["email"]),
            "password": self.secret_box.decrypt(row["password_encrypted"]) or "",
        }

    def delete_mailbox(self, mailbox_id: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM mailbox_pool WHERE id=?", (mailbox_id,))
        return cursor.rowcount == 1

    def save_account_material(self, account_id: int, values: dict[str, Any]) -> None:
        """Merge browser-login material without replacing OAuth credentials."""
        mapping = self.get_mapping(account_id)
        if not mapping:
            raise KeyError(f"account mapping not found: {account_id}")
        credentials = self.load_credentials(account_id)
        for key in ("email", "email_password", "openai_password", "totp_secret"):
            value = values.get(key)
            if isinstance(value, str) and value.strip():
                credentials[key] = value.strip()
        self.save_credentials(
            account_id,
            credentials,
            email=str(credentials.get("email") or mapping.get("email") or "").strip().lower(),
            username=str(mapping.get("username") or ""),
        )

    def mark_materials_checked(self, account_id: int) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE account_mapping SET materials_checked_at = ?, updated_at = ? "
                "WHERE sub2api_account_id = ?",
                (now, now, account_id),
            )

    def mark_upstream_probe(self, account_id: int) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE account_mapping SET last_upstream_probe_at = ?, updated_at = ? "
                "WHERE sub2api_account_id = ?",
                (now, now, account_id),
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
                SELECT t.*, m.email, m.username,
                    CASE
                        WHEN m.status='account_deleted'
                          OR (t.error_reason LIKE '%get_account: account not found%')
                        THEN 'account_deleted'
                        ELSE m.status
                    END AS account_status,
                    EXISTS (SELECT 1 FROM task_evidence e WHERE e.task_id=t.id) AS has_evidence
                FROM recovery_tasks t
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

    def save_task_evidence(self, task_id: str, image: bytes) -> str:
        if not image.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("evidence must be a PNG image")
        if len(image) > 12 * 1024 * 1024:
            raise ValueError("evidence image exceeds the 12 MiB limit")
        evidence_id = str(uuid.uuid4())
        file_name = f"{evidence_id}.png.enc"
        self.evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.evidence_dir, 0o700)
        file_path = self.evidence_dir / file_name
        descriptor = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(self.secret_box.encrypt_bytes(image))
                output.flush()
                os.fsync(output.fileno())
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO task_evidence(id, task_id, content_type, file_name, size_bytes, created_at)
                    VALUES (?, ?, 'image/png', ?, ?, ?)
                    """,
                    (evidence_id, task_id, file_name, len(image), utc_now()),
                )
        except Exception:
            file_path.unlink(missing_ok=True)
            raise
        return evidence_id

    def get_task_evidence(self, task_id: str, evidence_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT content_type, file_name, size_bytes, created_at
                FROM task_evidence WHERE id=? AND task_id=?
                """,
                (evidence_id, task_id),
            ).fetchone()
        if not row:
            return None
        file_name = str(row["file_name"])
        if Path(file_name).name != file_name:
            return None
        try:
            encrypted_image = (self.evidence_dir / file_name).read_bytes()
        except OSError:
            return None
        return {
            "content_type": str(row["content_type"]),
            "image": self.secret_box.decrypt_bytes(encrypted_image),
            "size_bytes": int(row["size_bytes"]),
            "created_at": str(row["created_at"]),
        }

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

    def create_account_enrollment(self, enrollment: dict[str, Any]) -> None:
        now = utc_now()
        materials = self.secret_box.encrypt_json(enrollment["materials"])
        verifier = self.secret_box.encrypt(str(enrollment["code_verifier"]))
        message = "新增账号请求已排队，等待自动授权。"
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute(
                "SELECT id FROM account_enrollments WHERE lower(email)=lower(?) "
                "AND status IN ('queued', 'running') LIMIT 1",
                (enrollment["email"],),
            ).fetchone()
            if active:
                conn.rollback()
                raise ValueError("该邮箱已有一个新增账号任务正在处理")
            conn.execute(
                """
                INSERT INTO account_enrollments(
                    id, email, name, auth_url, state, code_verifier_encrypted,
                    materials_encrypted, message, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    enrollment["id"], enrollment["email"], enrollment["name"],
                    enrollment["auth_url"], enrollment["state"], verifier,
                    materials, message, now, now,
                ),
            )
            conn.execute(
                """
                INSERT INTO account_enrollment_logs(enrollment_id, level, stage, message, created_at)
                VALUES (?, 'INFO', 'queued', ?, ?)
                """,
                (enrollment["id"], message, now),
            )
            conn.commit()

    def claim_next_account_enrollment(self) -> dict[str, Any] | None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM account_enrollments WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if not row:
                conn.commit()
                return None
            message = "正在准备自动授权流程。"
            conn.execute(
                """
                UPDATE account_enrollments SET status='running', stage='starting',
                    message=?, started_at=?, updated_at=? WHERE id=? AND status='queued'
                """,
                (message, now, now, row["id"]),
            )
            conn.execute(
                """
                INSERT INTO account_enrollment_logs(enrollment_id, level, stage, message, created_at)
                VALUES (?, 'INFO', 'starting', ?, ?)
                """,
                (row["id"], message, now),
            )
            conn.commit()
            claimed = dict(row)
        claimed["code_verifier"] = self.secret_box.decrypt(claimed.pop("code_verifier_encrypted")) or ""
        claimed["materials"] = self.secret_box.decrypt_json(claimed.pop("materials_encrypted"))
        return claimed

    def requeue_stale_account_enrollments(self, *, stale_after_seconds: int = 1800) -> int:
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=max(60, stale_after_seconds))).isoformat(timespec="seconds")
        stamp = now.isoformat(timespec="seconds")
        message = "服务重启后重新排队；原 OAuth 登录流程已结束。"
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id FROM account_enrollments WHERE status='running' AND updated_at < ?",
                (cutoff,),
            ).fetchall()
            if rows:
                conn.execute(
                    """
                    UPDATE account_enrollments SET status='queued', stage='recovered_after_restart',
                        message=?, updated_at=?, started_at=NULL
                    WHERE status='running' AND updated_at < ?
                    """,
                    (message, stamp, cutoff),
                )
                conn.executemany(
                    """
                    INSERT INTO account_enrollment_logs(enrollment_id, level, stage, message, created_at)
                    VALUES (?, 'WARNING', 'recovered_after_restart', ?, ?)
                    """,
                    [(str(row["id"]), message, stamp) for row in rows],
                )
            conn.commit()
        return len(rows)

    def update_account_enrollment_stage(
        self, enrollment_id: str, *, stage: str, message: str, level: str = "INFO"
    ) -> None:
        safe = safe_message(message)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE account_enrollments SET stage=?, message=?, updated_at=? "
                "WHERE id=? AND status='running'",
                (stage, safe, now, enrollment_id),
            )
            conn.execute(
                """
                INSERT INTO account_enrollment_logs(enrollment_id, level, stage, message, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (enrollment_id, level, stage, safe, now),
            )

    def finish_account_enrollment(
        self,
        enrollment_id: str,
        *,
        status: str,
        stage: str,
        message: str,
        error_reason: str | None = None,
        sub2api_account_id: int | None = None,
    ) -> None:
        safe = safe_message(message)
        error = safe_message(error_reason) if error_reason else None
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE account_enrollments SET status=?, stage=?, message=?, error_reason=?,
                    sub2api_account_id=?, auth_url='', state='', code_verifier_encrypted='',
                    materials_encrypted='', updated_at=?, finished_at=? WHERE id=?
                """,
                (status, stage, safe, error, sub2api_account_id, now, now, enrollment_id),
            )
            conn.execute(
                """
                INSERT INTO account_enrollment_logs(enrollment_id, level, stage, message, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (enrollment_id, "ERROR" if status == "failed" else "INFO", stage, safe, now),
            )

    def get_account_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, email, name, status, stage, message, sub2api_account_id,
                    error_reason, created_at, updated_at, started_at, finished_at
                FROM account_enrollments WHERE id=?
                """,
                (enrollment_id,),
            ).fetchone()
            if not row:
                return None
            logs = conn.execute(
                """
                SELECT level, stage, message, created_at FROM account_enrollment_logs
                WHERE enrollment_id=? ORDER BY id LIMIT 200
                """,
                (enrollment_id,),
            ).fetchall()
        result = dict(row)
        result["logs"] = [dict(log) for log in logs]
        return result

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
            active_tasks = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running_count,
                    SUM(CASE WHEN status='queued' AND stage='retry_wait' THEN 1 ELSE 0 END) AS retry_wait_count,
                    MIN(CASE WHEN status='queued' AND stage='retry_wait' THEN available_at END) AS next_retry_at
                FROM recovery_tasks
                """
            ).fetchone()
        accounts = {str(row["status"]): int(row["count"]) for row in rows}
        task_counts = {str(row["status"]): int(row["count"]) for row in tasks}
        return {
            "accounts": sum(accounts.values()),
            "auth_failures": accounts.get("auth_failed", 0) + accounts.get("reauth_required", 0),
            "recovering": accounts.get("recovering", 0),
            "running_tasks": int(active_tasks["running_count"] or 0),
            "retry_wait_tasks": int(active_tasks["retry_wait_count"] or 0),
            "next_retry_at": active_tasks["next_retry_at"],
            "success": task_counts.get("succeeded", 0),
            "failed": task_counts.get("failed", 0),
            "manual_required": task_counts.get("manual_required", 0),
        }

    def scan_status(self) -> dict[str, Any]:
        """Return the latest durable account-sync state for the Dashboard."""
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT event_type, detail_json, created_at
                FROM app_events
                WHERE event_type IN (
                    'scan_requested', 'scan_started', 'scan_completed',
                    'scan_failed', 'scan_skipped'
                )
                ORDER BY id DESC LIMIT 1
                """
            ).fetchone()
        if not row:
            return {"status": "never", "last_event_at": None}

        detail: dict[str, Any] = {}
        if row["detail_json"]:
            try:
                parsed = json.loads(row["detail_json"])
                if isinstance(parsed, dict):
                    detail = parsed
            except json.JSONDecodeError:
                pass
        event_type = str(row["event_type"])
        status = {
            "scan_requested": "queued",
            "scan_started": "running",
            "scan_completed": "success",
            "scan_failed": "failed",
            "scan_skipped": "busy",
        }.get(event_type, "unknown")
        result: dict[str, Any] = {
            "status": status,
            "last_event_at": row["created_at"],
        }
        if event_type in {"scan_completed", "scan_failed", "scan_skipped"}:
            result["finished_at"] = row["created_at"]
        for key in ("found", "auth_failures", "queued", "removed"):
            if key in detail:
                try:
                    result[key] = int(detail[key])
                except (TypeError, ValueError):
                    continue
        if event_type == "scan_failed" and detail.get("reason"):
            result["reason"] = str(detail["reason"])
        return result

    def latest_event_at(self, event_types: tuple[str, ...]) -> str | None:
        if not event_types:
            return None
        placeholders = ", ".join("?" for _ in event_types)
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT created_at FROM app_events WHERE event_type IN ({placeholders}) "
                "ORDER BY id DESC LIMIT 1",
                event_types,
            ).fetchone()
        return str(row["created_at"]) if row else None

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
