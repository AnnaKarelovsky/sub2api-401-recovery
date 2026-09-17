from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from .redaction import safe_error


class FailureClass(StrEnum):
    AUTH_FAILURE = "401_AUTH_FAILURE"
    RATE_LIMIT = "429_RATE_LIMIT"
    PERMISSION = "403_PERMISSION"
    NETWORK = "NETWORK_ERROR"
    ACCOUNT_ERROR = "ACCOUNT_ERROR"
    UNKNOWN = "UNKNOWN"


AUTH_MARKERS = (
    "unauthorized",
    "invalid_token",
    "token_invalidated",
    "token_revoked",
    "token expired",
    "token_expired",
    "access token expired",
    "authentication failed",
    "authentication_failure",
    "invalid_grant",
    "refresh_token_invalidated",
    "refresh_token_reused",
    "app_session_terminated",
    "oauth token",
)
NETWORK_MARKERS = (
    "timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "proxy",
    "dns",
    "network",
    "transport",
    "tls",
    "no route to host",
)
ACCOUNT_ERROR_MARKERS = (
    "deactivated_workspace",
    "workspace_deactivated",
    "account_deactivated",
    "account_disabled",
    "account_deleted",
)


@dataclass(frozen=True)
class Classification:
    category: FailureClass
    reason: str
    recoverable: bool
    needs_reauthorization: bool = False


def _has_http_status(text: str, status: int) -> bool:
    return bool(re.search(rf"(?<!\d){status}(?!\d)", text))


def classify_failure(
    *,
    http_status: int | None = None,
    message: str = "",
    oauth_error: str = "",
    token_expired: bool = False,
) -> Classification:
    """Classify upstream account failures without treating a generic error as 401.

    A 401 is considered account-auth related when it comes from the account test or an
    upstream error message. Generic Sub2API admin authentication errors never reach this
    function because the caller only passes account-level observations.
    """

    combined = " ".join(str(part or "") for part in (message, oauth_error)).lower()
    if token_expired:
        return Classification(FailureClass.AUTH_FAILURE, "OAuth access token is expired", True)
    if http_status == 401 or _has_http_status(combined, 401) or any(
        marker in combined for marker in AUTH_MARKERS
    ):
        needs_reauth = any(
            marker in combined
            for marker in (
                "invalid_grant",
                "refresh_token_invalidated",
                "refresh_token_reused",
                "app_session_terminated",
            )
        )
        return Classification(
            FailureClass.AUTH_FAILURE,
            "OAuth authentication failure" if not combined else _compact_reason(message or oauth_error),
            True,
            needs_reauthorization=needs_reauth,
        )
    if http_status == 429 or _has_http_status(combined, 429) or "rate limit" in combined:
        return Classification(FailureClass.RATE_LIMIT, _compact_reason(message), False)
    if any(marker in combined for marker in ACCOUNT_ERROR_MARKERS):
        if "deactivated_workspace" in combined or "workspace_deactivated" in combined:
            reason = "Sub2API workspace is deactivated"
        elif "account_deleted" in combined:
            reason = "Sub2API account is deleted"
        elif "account_disabled" in combined or "account_deactivated" in combined:
            reason = "Sub2API account is disabled"
        else:
            reason = _compact_reason(message) or "Sub2API account is unavailable"
        return Classification(FailureClass.ACCOUNT_ERROR, reason, False)
    if http_status == 403 or _has_http_status(combined, 403) or any(
        marker in combined for marker in ("forbidden", "permission denied", "not allowed")
    ):
        return Classification(FailureClass.PERMISSION, _compact_reason(message), False)
    if any(marker in combined for marker in NETWORK_MARKERS):
        return Classification(FailureClass.NETWORK, _compact_reason(message), True)
    return Classification(FailureClass.UNKNOWN, _compact_reason(message) or "Unclassified account error", False)


def classify_account_snapshot(snapshot: dict[str, Any]) -> Classification | None:
    """Return a recovery-relevant classification for one Sub2API account snapshot."""

    credentials = snapshot.get("credentials") or {}
    expires_at = _as_epoch(credentials.get("expires_at"))
    import time

    expired = expires_at is not None and expires_at <= int(time.time())
    message_parts: list[str] = []
    for key in (
        "error_message",
        "temp_unschedulable_reason",
        "last_error",
        "message",
        "failure_reason",
        "reason",
        "token_status",
    ):
        value = snapshot.get(key)
        if value:
            message_parts.append(str(value))
    nested_error = snapshot.get("error")
    if isinstance(nested_error, dict):
        message_parts.extend(str(nested_error[key]) for key in ("message", "reason", "detail") if nested_error.get(key))
    oauth_error = " ".join(
        str(snapshot.get(key) or "")
        for key in ("oauth_error", "oauth_error_code", "error_code")
        if snapshot.get(key)
    )
    if isinstance(credentials, dict):
        oauth_error = " ".join(
            part
            for part in (
                oauth_error,
                str(credentials.get("error") or ""),
                str(credentials.get("token_status") or ""),
            )
            if part
        )
    message = " ".join(message_parts)
    http_status = _snapshot_status(snapshot, nested_error)
    status = str(snapshot.get("status") or "").lower()
    if not message and not oauth_error and http_status is None and status not in {"error", "inactive", "disabled"} and not expired:
        return None
    result = classify_failure(
        http_status=http_status,
        message=message,
        oauth_error=oauth_error,
        token_expired=expired,
    )
    if result.category == FailureClass.UNKNOWN and status not in {"error", "inactive", "disabled"}:
        return None
    return result


def _snapshot_status(snapshot: dict[str, Any], nested_error: Any) -> int | None:
    statuses: list[int] = []
    for source in (snapshot, nested_error if isinstance(nested_error, dict) else {}):
        for key in ("http_status", "status_code", "upstream_status", "upstream_status_code"):
            value = source.get(key)
            try:
                if value is not None:
                    statuses.append(int(value))
            except (TypeError, ValueError):
                continue
    for preferred in (401, 429, 403):
        if preferred in statuses:
            return preferred
    return statuses[0] if statuses else None


def _as_epoch(value: Any) -> int | None:
    if value is None:
        return None
    try:
        numeric = float(value)
        if numeric > 10_000_000_000:
            numeric /= 1000
        return int(numeric)
    except (TypeError, ValueError):
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return int(parsed.timestamp())
            except ValueError:
                pass
        return None


def _compact_reason(value: str, max_length: int = 300) -> str:
    text = " ".join(safe_error(value, max_length=max_length).split())
    return text[:max_length]
