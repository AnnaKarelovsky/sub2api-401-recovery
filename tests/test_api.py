from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


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
