from __future__ import annotations

import httpx

from app.sub2api import Sub2APIClient


def test_apply_credentials_uses_admin_key_and_current_payload(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["key"] = request.headers.get("x-api-key")
        captured["json"] = __import__("json").loads(request.content)
        return httpx.Response(200, json={"code": 0, "message": "success", "data": {"id": 7}})

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = client.apply_oauth_credentials(
            7,
            {"access_token": "secret", "refresh_token": "rotated", "expires_at": 123},
            {"plan_type": "plus"},
        )
    finally:
        client.close()
    assert result == {"id": 7}
    assert captured["path"].endswith("/accounts/7/apply-oauth-credentials")
    assert captured["key"] == "admin-key"
    assert captured["json"]["type"] == "oauth"
    assert captured["json"]["credentials"]["refresh_token"] == "rotated"


def test_create_account_posts_openai_oauth_credentials_to_admin_api(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["json"] = __import__("json").loads(request.content)
        return httpx.Response(200, json={"code": 0, "data": {"id": 292, "name": "owner@example.com"}})

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    payload = {
        "name": "owner@example.com",
        "platform": "openai",
        "type": "oauth",
        "credentials": {"access_token": "access", "refresh_token": "refresh"},
        "extra": {"email": "owner@example.com"},
    }
    try:
        result = client.create_account(payload)
    finally:
        client.close()

    assert result["id"] == 292
    assert captured == {"method": "POST", "path": "/api/v1/admin/accounts", "json": payload}


def test_account_status_check_reads_401_from_account_detail(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "id": 7,
                    "status": "error",
                    "error_message": "Authentication failed (401): token_revoked",
                },
            },
        )

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = client.inspect_account(7)
    finally:
        client.close()
    assert not result.success
    assert result.classification is not None
    assert result.status_code == 401
    assert captured == {"method": "GET", "path": "/api/v1/admin/accounts/7"}


def test_account_status_check_accepts_healthy_detail(settings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": 0, "data": {"id": 7, "status": "active", "schedulable": True}},
        )

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = client.inspect_account(7)
    finally:
        client.close()
    assert result.success
    assert result.reason == "Sub2API account status is healthy"
