from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app import main
from app.main import create_app


def _headers(client: TestClient) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_update_endpoints_require_dashboard_auth(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/update").status_code == 401
        assert client.post("/api/v1/update").status_code == 401
        assert client.get("/api/v1/update/status").status_code == 401


def test_source_deployment_reports_update_as_disabled(settings):
    with TestClient(create_app(settings)) as client:
        headers = _headers(client)

        checked = client.get("/api/v1/update", headers=headers)
        started = client.post("/api/v1/update", headers=headers)
        operation = client.get("/api/v1/update/status", headers=headers)

    assert checked.status_code == 200
    assert checked.json()["update_enabled"] is False
    assert started.status_code == 409
    assert operation.json()["status"] == "disabled"


def test_custom_image_deployment_disables_dashboard_updates(settings):
    settings.update_mode = "release"
    settings.update_agent_url = "http://recovery-update-agent:1456"
    settings.update_agent_token = "t" * 40
    settings.recovery_image = "custom/recovery:local"

    with TestClient(create_app(settings)) as client:
        response = client.get("/api/v1/update", headers=_headers(client))

    assert response.status_code == 200
    assert response.json()["update_enabled"] is False


def test_release_deployment_starts_only_the_latest_release(settings, monkeypatch):
    settings.update_mode = "release"
    settings.update_agent_url = "http://recovery-update-agent:1456"
    settings.update_agent_token = "t" * 40
    monkeypatch.setattr(
        main,
        "update_info",
        lambda **_kwargs: {
            "current_version": "v0.4.16",
            "latest_version": "v0.4.17",
            "update_available": True,
            "update_enabled": True,
        },
    )
    calls = []

    def request_agent(**kwargs):
        calls.append(kwargs)
        return {"status": "running", "target_version": "v0.4.17"}

    monkeypatch.setattr(main, "request_agent", request_agent)

    with TestClient(create_app(settings)) as client:
        response = client.post("/api/v1/update", headers=_headers(client))

    assert response.status_code == 202
    assert response.json()["status"] == "running"
    assert calls[0]["path"] == "/update"
    assert calls[0]["payload"] == {"version": "v0.4.17"}


def test_release_deployment_does_not_start_when_up_to_date(settings, monkeypatch):
    settings.update_mode = "release"
    settings.update_agent_url = "http://recovery-update-agent:1456"
    settings.update_agent_token = "t" * 40
    monkeypatch.setattr(
        main,
        "update_info",
        lambda **_kwargs: {
            "current_version": "v0.4.17",
            "latest_version": "v0.4.17",
            "update_available": False,
            "update_enabled": True,
        },
    )
    monkeypatch.setattr(main, "request_agent", lambda **_kwargs: pytest.fail("must not call updater"))

    with TestClient(create_app(settings)) as client:
        response = client.post("/api/v1/update", headers=_headers(client))

    assert response.status_code == 409
