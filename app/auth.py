from __future__ import annotations

from fastapi import HTTPException, Request, status

from .config import Settings
from .security import SessionToken, issue_session_token, verify_session_token


def login(settings: Settings, username: str, password: str) -> str | None:
    if username != settings.dashboard_username:
        return None
    if not password or not _constant_time(password, settings.dashboard_password):
        return None
    return issue_session_token(
        settings.dashboard_secret,
        username,
        settings.dashboard_session_minutes * 60,
    )


def current_session(request: Request, settings: Settings) -> SessionToken:
    token = _extract_token(request)
    session = verify_session_token(settings.dashboard_secret, token) if token else None
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return session


def auth_dependency(settings: Settings):
    def dependency(request: Request) -> SessionToken:
        return current_session(request, settings)

    return dependency


def _extract_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.cookies.get("recovery_session", "")


def _constant_time(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())
