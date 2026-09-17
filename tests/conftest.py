from __future__ import annotations

import base64

import pytest

from app.config import Settings
from app.db import Database
from app.security import SecretBox


@pytest.fixture
def encryption_key() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


@pytest.fixture
def settings(tmp_path, encryption_key) -> Settings:
    return Settings(
        _env_file=None,
        encryption_key=encryption_key,
        dashboard_username="admin",
        dashboard_password="password",
        dashboard_secret="dashboard-secret",
        sub2api_base_url="http://sub2api.test",
        sub2api_admin_key="admin-key",
        database_path=str(tmp_path / "recovery.db"),
        backup_dir=str(tmp_path / "backups"),
        scan_interval_seconds=10,
        recovery_backoff_seconds=0,
    )


@pytest.fixture
def database(settings) -> Database:
    db = Database(settings.database_path, SecretBox(settings.encryption_key))
    db.initialize()
    return db
