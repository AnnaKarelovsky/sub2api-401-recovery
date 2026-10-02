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


def test_delete_account_uses_admin_delete_endpoint(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        return httpx.Response(200, json={"code": 0, "message": "deleted", "data": {}})

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    try:
        client.delete_account(302)
    finally:
        client.close()

    assert captured == {"method": "DELETE", "path": "/api/v1/admin/accounts/302"}


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


def test_dynamic_upstream_probe_uses_discovered_model_and_parses_sse_401(settings):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={"code": 0, "data": [{"id": "gpt-6-luna", "type": "model"}]},
            )
        captured["json"] = __import__("json").loads(request.content)
        return httpx.Response(
            200,
            text='data: {"type":"test_start","model":"gpt-6-luna"}\n\n'
            'data: {"type":"error","error":"API returned 401: token_revoked"}\n\n',
            headers={"content-type": "text/event-stream"},
        )

    client = Sub2APIClient(settings, transport=httpx.MockTransport(handler))
    try:
        models = client.list_account_models(7)
        result = client.probe_account_with_model(7, models[0]["id"])
    finally:
        client.close()
    assert models == [{"id": "gpt-6-luna", "type": "model"}]
    assert not result.success
    assert result.status_code == 401
    assert result.classification.category.value == "401_AUTH_FAILURE"
    assert captured["path"].endswith("/accounts/7/test")
    assert captured["json"] == {"model_id": "gpt-6-luna", "mode": "default"}
