from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.main import create_app


def test_required_evidence_mount_must_not_share_database_filesystem(settings, tmp_path):
    settings.evidence_mount_required = True
    (tmp_path / "evidence").mkdir()

    with pytest.raises(ValueError, match="separate data filesystem"):
        settings.validate_runtime(require_sub2api=False)


def test_health_login_and_dashboard(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/healthz").status_code == 200
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        assert login.status_code == 200
        token = login.json()["access_token"]
        dashboard = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
        assert dashboard.status_code == 200
        assert dashboard.json()["summary"]["accounts"] == 0
        assert dashboard.json()["sync"]["status"] == "never"


def test_mailbox_pool_hides_password_until_explicit_secret_request(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        created = client.post(
            "/api/v1/mailboxes",
            headers=headers,
            json={"email": "pool@example.com", "password": "pool-secret"},
        )
        assert created.status_code == 201
        mailbox_id = created.json()["id"]

        listed = client.get("/api/v1/mailboxes", headers=headers)
        assert listed.status_code == 200
        assert "pool-secret" not in listed.text
        assert listed.json()["items"][0]["has_password"] == 1

        assert client.get(f"/api/v1/mailboxes/{mailbox_id}/secret").status_code == 401
        secret = client.get(f"/api/v1/mailboxes/{mailbox_id}/secret", headers=headers)
        assert secret.status_code == 200
        assert secret.json() == {"email": "pool@example.com", "password": "pool-secret"}
        assert secret.headers["cache-control"] == "private, no-store"


def test_task_evidence_requires_auth_and_is_scoped_to_its_task(settings):
    image = b"\x89PNG\r\n\x1a\naccount-disabled-page"
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot({"sub2api_account_id": 301, "status": "auth_failed"})
        task_id, _ = runtime.db.create_task(301, trigger="test")
        evidence_id = runtime.db.save_task_evidence(task_id, image)
        evidence_file = settings.evidence_dir + "/" + evidence_id + ".png.enc"
        with open(evidence_file, "rb") as encrypted_image:
            assert image not in encrypted_image.read()
        assert evidence_file.startswith(settings.evidence_dir)

        endpoint = f"/api/v1/tasks/{task_id}/evidence/{evidence_id}"
        assert client.get(endpoint).status_code == 401
        assert client.get(f"/api/v1/tasks/missing/evidence/{evidence_id}", headers=headers).status_code == 404
        response = client.get(endpoint, headers=headers)

        assert response.status_code == 200
        assert response.content == image
        assert response.headers["content-type"] == "image/png"
        assert response.headers["cache-control"] == "private, no-store"


def test_disabled_account_delete_preserves_logs_and_evidence_and_clears_materials(settings):
    image = b"\x89PNG\r\n\x1a\naccount-disabled-page"
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot(
            {"sub2api_account_id": 302, "email": "disabled@example.com", "status": "account_disabled"}
        )
        runtime.db.save_credentials(302, {"refresh_token": "encrypted-refresh", "openai_password": "encrypted-password"})
        task_id, _ = runtime.db.create_task(302, trigger="test")
        runtime.db.finish_task(task_id, status="failed", stage="account_disabled", error_reason="account_deactivated")
        evidence_id = runtime.db.save_task_evidence(task_id, image)
        runtime.db.append_log(
            task_id,
            level="ERROR",
            stage="account_disabled",
            message="account_deactivated",
            detail={"evidence_id": evidence_id, "screenshot_saved": True},
        )
        deleted_remote_ids = []
        runtime.sub2api.get_account = lambda account_id: {"id": account_id, "email": "disabled@example.com"}
        runtime.sub2api.delete_account = deleted_remote_ids.append

        response = client.request(
            "DELETE",
            "/api/v1/accounts/disabled",
            headers=headers,
            json={"account_ids": [302], "confirmation": "DELETE"},
        )

        assert response.status_code == 200
        assert response.json()["deleted"] == [{"account_id": 302, "email": "disabled@example.com"}]
        assert deleted_remote_ids == [302]
        assert runtime.db.get_mapping(302)["status"] == "account_deleted"
        assert runtime.db.get_mapping(302)["remote_present"] == 0
        assert runtime.db.load_credentials(302) == {}
        assert runtime.db.get_task_evidence(task_id, evidence_id)["image"] == image
        assert [log["stage"] for log in runtime.db.list_logs(task_id)][-1] == "account_deleted"

        task_response = client.get(f"/api/v1/tasks/{task_id}", headers=headers)
        assert task_response.status_code == 200
        assert task_response.json()["sub2api_account_id"] == 302
        assert task_response.json()["logs"][-1]["stage"] == "account_deleted"

        retry_response = client.post(f"/api/v1/tasks/{task_id}/retry", headers=headers)
        assert retry_response.status_code == 409


def test_disabled_account_delete_refuses_non_disabled_accounts(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot({"sub2api_account_id": 303, "status": "auth_failed"})
        task_id, _ = runtime.db.create_task(303, trigger="test")
        runtime.db.finish_task(task_id, status="failed", stage="failed", error_reason="401")
        runtime.db.upsert_account_snapshot(
            {"sub2api_account_id": 304, "email": "disabled@example.com", "status": "account_disabled"}
        )
        disabled_task_id, _ = runtime.db.create_task(304, trigger="test")
        runtime.db.finish_task(
            disabled_task_id,
            status="failed",
            stage="account_disabled",
            error_reason="account_deactivated",
        )
        deleted_remote_ids = []
        runtime.sub2api.delete_account = deleted_remote_ids.append
        runtime.sub2api.get_account = lambda account_id: {"id": account_id, "email": "disabled@example.com"}

        response = client.request(
            "DELETE",
            "/api/v1/accounts/disabled",
            headers=headers,
            json={"account_ids": [304, 303], "confirmation": "DELETE"},
        )

        assert response.status_code == 409
        assert deleted_remote_ids == []


def test_missing_account_task_is_not_retryable_and_is_marked_deleted(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot(
            {"sub2api_account_id": 279, "email": "missing@example.com", "status": "failed"}
        )
        task_id, _ = runtime.db.create_task(279, trigger="automatic-scan")
        runtime.db.finish_task(
            task_id,
            status="failed",
            stage="failed",
            failure_class="UNKNOWN",
            error_reason="get_account: account not found",
        )

        tasks = client.get("/api/v1/tasks", headers=headers)
        task = next(item for item in tasks.json()["items"] if item["id"] == task_id)
        assert task["account_status"] == "account_deleted"

        retry = client.post(f"/api/v1/tasks/{task_id}/retry", headers=headers)
        assert retry.status_code == 409
        assert runtime.db.get_mapping(279)["status"] == "account_deleted"


def test_dashboard_settings_are_encrypted_and_reloadable(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        current = client.get("/api/v1/settings", headers=headers)
        assert current.status_code == 200
        assert "admin-key" not in current.text
        sub2api = next(
            field
            for group in current.json()["groups"]
            for field in group["fields"]
            if field["key"] == "sub2api_admin_key"
        )
        assert sub2api["value"] == ""
        assert sub2api["configured"] is True

        updated = client.put(
            "/api/v1/settings",
            headers=headers,
            json={
                "values": {
                    "sub2api_base_url": "http://sub2api.changed",
                    "sub2api_admin_key": "replacement-key",
                    "scan_interval_seconds": 30,
                }
            },
        )
        assert updated.status_code == 200
        assert settings.sub2api_base_url == "http://sub2api.changed"
        assert settings.sub2api_admin_key == "replacement-key"
        assert settings.scan_interval_seconds == 30
        assert b"replacement-key" not in open(settings.database_path, "rb").read()

        reset = client.delete("/api/v1/settings", headers=headers)
        assert reset.status_code == 200
        assert settings.sub2api_base_url == "http://sub2api.test"
        assert settings.sub2api_admin_key == "admin-key"


def test_account_materials_can_be_saved_partially_without_exposing_secrets(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot(
            {"sub2api_account_id": 77, "email": "old@example.com", "status": "auth_failed"}
        )

        response = client.put(
            "/api/v1/accounts/77/materials",
            headers=headers,
            json={
                "email": "owner@example.com",
                "email_password": "mail-pass",
                "openai_password": "gpt-pass",
                "totp_secret": "",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["automation_ready"] is True
        assert body["automation_complete"] is False
        assert body["automation_configured_count"] == 3
        assert body["automation_materials_checked"] is True
        assert body["automation_missing"] == ["2FA 密钥"]
        assert "mail-pass" not in response.text
        assert "gpt-pass" not in response.text
        assert b"mail-pass" not in open(settings.database_path, "rb").read()
        assert b"gpt-pass" not in open(settings.database_path, "rb").read()


def test_new_account_enrollment_keeps_login_materials_private(settings):
    settings.playwright_enabled = True
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = client.post(
            "/api/v1/account-enrollments",
            headers=headers,
            json={
                "email": "owner@example.com",
                "email_password": "mail-secret",
                "openai_password": "openai-secret",
                "totp_secret": "totp-secret",
            },
        )

        assert response.status_code == 202
        enrollment_id = response.json()["id"]
        assert response.json()["status"] == "queued"
        assert "mail-secret" not in response.text
        assert "openai-secret" not in response.text
        assert "totp-secret" not in response.text

        status = client.get(f"/api/v1/account-enrollments/{enrollment_id}", headers=headers)
        assert status.status_code == 200
        assert "materials" not in status.json()
        assert "auth_url" not in status.json()
        raw_database = open(settings.database_path, "rb").read()
        assert b"mail-secret" not in raw_database
        assert b"openai-secret" not in raw_database
        assert b"totp-secret" not in raw_database


def test_new_account_enrollment_requires_browser_automation_to_be_enabled(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        response = client.post(
            "/api/v1/account-enrollments",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            json={"email": "owner@example.com", "openai_password": "openai-secret"},
        )

        assert response.status_code == 409
        assert "启用浏览器自动授权" in response.json()["detail"]


def test_unchecked_account_materials_are_not_reported_as_missing(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        runtime = client.app.state.runtime
        runtime.db.upsert_account_snapshot(
            {"sub2api_account_id": 78, "email": "untested@example.com", "status": "healthy"}
        )

        response = client.get("/api/v1/accounts/78", headers=headers)

        assert response.status_code == 200
        body = response.json()
        assert body["automation_materials_checked"] is False
        assert body["automation_configured_count"] == 1


def test_dashboard_setting_profiles_can_switch_complete_configs(settings):
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        created = client.post(
            "/api/v1/settings/profiles",
            headers=headers,
            json={"name": "default-profile"},
        )
        assert created.status_code == 200
        profile = created.json()["profiles"][0]
        assert profile["name"] == "default-profile"
        assert profile["active"] is False
        assert b"admin-key" not in open(settings.database_path, "rb").read()

        changed = client.put(
            "/api/v1/settings",
            headers=headers,
            json={"values": {"scan_interval_seconds": 45}},
        )
        assert changed.status_code == 200
        assert settings.scan_interval_seconds == 45
        assert changed.json()["active_profile_id"] is None

        activated = client.post(
            f"/api/v1/settings/profiles/{profile['id']}/activate",
            headers=headers,
        )
        assert activated.status_code == 200
        assert settings.scan_interval_seconds == 10
        assert activated.json()["active_profile_id"] == profile["id"]

        deleted = client.delete(
            f"/api/v1/settings/profiles/{profile['id']}",
            headers=headers,
        )
        assert deleted.status_code == 200
        assert deleted.json()["profiles"] == []
