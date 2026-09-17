from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings
from .redaction import safe_error


class OAuthError(Exception):
    def __init__(self, message: str, *, error_code: str = "", reauth_required: bool = False):
        super().__init__(message)
        self.error_code = error_code
        self.reauth_required = reauth_required


@dataclass(frozen=True)
class PKCE:
    state: str
    code_verifier: str
    code_challenge: str


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    refresh_token: str
    id_token: str
    expires_at: int
    expires_in: int
    client_id: str
    scope: str = ""
    email: str = ""
    chatgpt_account_id: str = ""
    chatgpt_user_id: str = ""
    organization_id: str = ""
    plan_type: str = ""

    def as_credentials(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "client_id": self.client_id,
        }
        for key, value in (
            ("id_token", self.id_token),
            ("scope", self.scope),
            ("email", self.email),
            ("chatgpt_account_id", self.chatgpt_account_id),
            ("chatgpt_user_id", self.chatgpt_user_id),
            ("organization_id", self.organization_id),
            ("plan_type", self.plan_type),
        ):
            if value:
                result[key] = value
        return result


def generate_pkce() -> PKCE:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(
        "ascii"
    )
    state = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    return PKCE(state=state, code_verifier=verifier, code_challenge=challenge)


def build_authorization_url(settings: Settings, pkce: PKCE, redirect_uri: str | None = None) -> str:
    redirect = redirect_uri or settings.openai_oauth_redirect_uri
    params = {
        "response_type": "code",
        "client_id": settings.openai_oauth_client_id,
        "redirect_uri": redirect,
        "scope": settings.openai_oauth_scope,
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "state": pkce.state,
        "originator": settings.openai_originator,
    }
    return f"{settings.openai_oauth_authorize_url}?{urllib.parse.urlencode(params)}"


class OpenAIOAuthClient:
    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self.client = httpx.Client(
            timeout=settings.openai_oauth_timeout_seconds,
            trust_env=True,
            transport=transport,
            headers={
                "User-Agent": "codex_cli_rs/sub2api-401-recovery",
                "Originator": settings.openai_originator,
            },
        )

    def close(self) -> None:
        self.client.close()

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> TokenSet:
        form = {
            "grant_type": "authorization_code",
            "client_id": self.settings.openai_oauth_client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        return self._token_request(form, previous_refresh_token="")

    def refresh_token(self, refresh_token: str, *, previous: dict[str, Any] | None = None) -> TokenSet:
        if not refresh_token.strip():
            raise OAuthError("refresh token is missing", error_code="missing_refresh_token", reauth_required=True)
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.settings.openai_oauth_client_id,
        }
        return self._token_request(
            form,
            previous_refresh_token=refresh_token,
            previous=previous,
            json_body=True,
        )

    def _token_request(
        self,
        form: dict[str, str],
        *,
        previous_refresh_token: str,
        previous: dict[str, Any] | None = None,
        json_body: bool = False,
    ) -> TokenSet:
        try:
            request_kwargs = {"json": form} if json_body else {"data": form}
            response = self.client.post(self.settings.openai_oauth_token_url, **request_kwargs)
        except httpx.HTTPError as exc:
            raise OAuthError(f"OpenAI OAuth request failed: {safe_error(exc)}") from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if response.status_code >= 400:
            error_code, description = _oauth_error_fields(payload)
            reason = description or error_code or response.reason_phrase or "token endpoint rejected request"
            permanent = error_code in {
                "invalid_grant",
                "invalid_refresh_token",
                "token_expired",
                "refresh_token_reused",
                "refresh_token_invalidated",
                "app_session_terminated",
            }
            raise OAuthError(
                safe_error(reason), error_code=error_code, reauth_required=permanent
            )
        if not isinstance(payload, dict) or not payload.get("access_token"):
            raise OAuthError("token endpoint returned no access token")
        return _token_set_from_payload(
            payload,
            self.settings.openai_oauth_client_id,
            previous_refresh_token=previous_refresh_token,
            previous=previous,
        )


def _oauth_error_fields(payload: Any) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", ""
    raw_error = payload.get("error")
    if isinstance(raw_error, dict):
        error_code = str(
            raw_error.get("code")
            or raw_error.get("error_code")
            or raw_error.get("type")
            or payload.get("code")
            or ""
        )
        description = str(
            raw_error.get("message")
            or raw_error.get("error_description")
            or payload.get("error_description")
            or payload.get("message")
            or ""
        )
        return error_code, description
    return (
        str(raw_error or payload.get("code") or ""),
        str(payload.get("error_description") or payload.get("message") or ""),
    )


def _token_set_from_payload(
    payload: dict[str, Any],
    client_id: str,
    *,
    previous_refresh_token: str = "",
    previous: dict[str, Any] | None = None,
) -> TokenSet:
    previous = previous or {}
    access_token = str(payload.get("access_token") or "")
    refresh_token = str(payload.get("refresh_token") or previous_refresh_token or previous.get("refresh_token") or "")
    id_token = str(payload.get("id_token") or previous.get("id_token") or "")
    now = int(time.time())
    access_claims = decode_jwt_payload(access_token)
    id_claims = decode_jwt_payload(id_token)
    explicit_expires_at = _int(payload.get("expires_at"), 0)
    expires_at = explicit_expires_at or (
        now + _int(payload.get("expires_in"), 0)
        if payload.get("expires_in") is not None
        else _int(access_claims.get("exp"), 0) or _int(id_claims.get("exp"), 0)
    )
    if not expires_at:
        expires_at = _int(previous.get("expires_at"), 0)
    expires_in = max(0, expires_at - now) if expires_at else 0
    claims = extract_identity(id_token, access_token)
    return TokenSet(
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        expires_at=expires_at,
        expires_in=expires_in,
        client_id=str(payload.get("client_id") or previous.get("client_id") or client_id),
        scope=str(payload.get("scope") or previous.get("scope") or ""),
        email=claims.get("email") or str(previous.get("email") or ""),
        chatgpt_account_id=claims.get("chatgpt_account_id") or str(previous.get("chatgpt_account_id") or ""),
        chatgpt_user_id=claims.get("chatgpt_user_id") or str(previous.get("chatgpt_user_id") or ""),
        organization_id=claims.get("organization_id") or str(previous.get("organization_id") or ""),
        plan_type=claims.get("plan_type") or str(previous.get("plan_type") or ""),
    )


def extract_identity(*tokens: str) -> dict[str, str]:
    identity = {
        "email": "",
        "chatgpt_account_id": "",
        "chatgpt_user_id": "",
        "organization_id": "",
        "plan_type": "",
    }
    for token in tokens:
        claims = decode_jwt_payload(token)
        if not claims:
            continue
        auth = claims.get("https://api.openai.com/auth")
        auth = auth if isinstance(auth, dict) else {}
        organizations = auth.get("organizations") or claims.get("organizations") or []
        organization_id = ""
        if isinstance(organizations, list):
            for item in organizations:
                if isinstance(item, dict) and item.get("is_default"):
                    organization_id = str(item.get("id") or "")
                    break
            if not organization_id and organizations and isinstance(organizations[0], dict):
                organization_id = str(organizations[0].get("id") or "")
        candidates = {
            "email": claims.get("email") or auth.get("email"),
            "chatgpt_account_id": claims.get("chatgpt_account_id") or auth.get("chatgpt_account_id"),
            "chatgpt_user_id": claims.get("chatgpt_user_id") or auth.get("chatgpt_user_id"),
            "organization_id": claims.get("organization_id") or organization_id or auth.get("poid"),
            "plan_type": claims.get("chatgpt_plan_type") or claims.get("plan_type") or auth.get("chatgpt_plan_type"),
        }
        for key, value in candidates.items():
            if not identity[key] and value:
                identity[key] = str(value)
    return identity


def decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (binascii.Error, ValueError, TypeError, UnicodeDecodeError):
        return {}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _remaining_seconds(expires_at: Any) -> int:
    return max(0, _int(expires_at) - int(time.time()))
