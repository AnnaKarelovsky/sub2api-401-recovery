from __future__ import annotations

import base64
import json
import urllib.parse

import httpx

from app.oauth import OAuthError, OpenAIOAuthClient, build_authorization_url, extract_identity, generate_pkce


def fake_jwt(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def test_pkce_and_authorization_url(settings):
    pkce = generate_pkce()
    assert 43 <= len(pkce.code_verifier) <= 128
    assert len(pkce.code_challenge) == 43
    parsed = urllib.parse.urlparse(build_authorization_url(settings, pkce))
    query = urllib.parse.parse_qs(parsed.query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [pkce.state]
    assert query["client_id"] == [settings.openai_oauth_client_id]


def test_extract_identity_from_openai_namespace():
    token = fake_jwt(
        {
            "email": "user@example.com",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct-1",
                "chatgpt_user_id": "user-1",
                "chatgpt_plan_type": "plus",
                "organizations": [{"id": "org-1", "is_default": True}],
            },
        }
    )
    identity = extract_identity(token)
    assert identity["email"] == "user@example.com"
    assert identity["chatgpt_account_id"] == "acct-1"
    assert identity["organization_id"] == "org-1"


def test_extract_identity_merges_id_and_access_token_claims():
    id_token = fake_jwt({"email": "user@example.com"})
    access_token = fake_jwt(
        {
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct-2",
                "chatgpt_plan_type": "team",
            }
        }
    )

    identity = extract_identity(id_token, access_token)

    assert identity == {
        "email": "user@example.com",
        "chatgpt_account_id": "acct-2",
        "chatgpt_user_id": "",
        "organization_id": "",
        "plan_type": "team",
    }


def test_refresh_preserves_old_refresh_token_when_rotating_response_omits_it(settings):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/oauth/token"
        assert request.headers["content-type"].startswith("application/json")
        body = json.loads(request.content)
        assert body["grant_type"] == "refresh_token"
        assert body["refresh_token"] == "old-refresh"
        return httpx.Response(200, json={"access_token": "new-access", "expires_in": 3600})

    client = OpenAIOAuthClient(settings, transport=httpx.MockTransport(handler))
    try:
        tokens = client.refresh_token("old-refresh", previous={"refresh_token": "old-refresh"})
    finally:
        client.close()
    assert tokens.access_token == "new-access"
    assert tokens.refresh_token == "old-refresh"


def test_nested_invalidated_refresh_token_requires_reauthorization(settings):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "error": {
                    "message": "Your session has ended. Please log in again.",
                    "type": "invalid_request_error",
                    "code": "refresh_token_invalidated",
                }
            },
        )

    client = OpenAIOAuthClient(settings, transport=httpx.MockTransport(handler))
    try:
        try:
            client.refresh_token("old-refresh")
        except OAuthError as exc:
            assert exc.error_code == "refresh_token_invalidated"
            assert exc.reauth_required
            assert "session has ended" in str(exc)
        else:
            raise AssertionError("expected OAuthError")
    finally:
        client.close()
