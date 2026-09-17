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
