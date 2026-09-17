from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .classifier import Classification, classify_account_snapshot, classify_failure
from .config import Settings
from .redaction import safe_error


@dataclass
class Sub2APIError(Exception):
    operation: str
    status_code: int | None
    reason: str
    retryable: bool = False
    classification: Classification | None = None

    def __str__(self) -> str:
        return f"{self.operation}: {self.reason}"


class Sub2APIClient:
    """Admin API client for the current Sub2API account contract."""

    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None):
        # The Dashboard can configure Sub2API after the first boot.
        base_url = settings.sub2api_base_url.rstrip("/") or "http://127.0.0.1"
        self.settings = settings
        self.client = httpx.Client(
            base_url=base_url,
            timeout=settings.sub2api_timeout_seconds,
            trust_env=True,
            transport=transport,
        )
        self.test_timeout = settings.sub2api_test_timeout_seconds

    def close(self) -> None:
        self.client.close()

    def _headers(self) -> dict[str, str]:
        if self.settings.sub2api_admin_key.strip():
            return {"x-api-key": self.settings.sub2api_admin_key.strip()}
        if self.settings.sub2api_jwt.strip():
            return {"Authorization": f"Bearer {self.settings.sub2api_jwt.strip()}"}
        raise Sub2APIError("authentication", None, "Sub2API admin credentials are not configured")

    def _request(self, method: str, path: str, *, operation: str, **kwargs: Any) -> Any:
        if not self.settings.sub2api_base_url.strip():
            raise Sub2APIError(
                operation,
                None,
                "Sub2API Admin API address is not configured",
                classification=classify_failure(
                    message="Sub2API Admin API address is not configured"
                ),
            )
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self._headers())
        headers.setdefault("Accept", "application/json")
        try:
            response = self.client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise Sub2APIError(
                operation,
                None,
                safe_error(exc),
                retryable=True,
                classification=classify_failure(message=str(exc)),
            ) from exc
        payload = _decode_response(response)
        if response.status_code >= 400:
            message = _payload_message(payload) or response.reason_phrase or "request failed"
            raise Sub2APIError(
                operation,
                response.status_code,
                safe_error(message),
                retryable=response.status_code >= 500 or response.status_code == 429,
                classification=classify_failure(http_status=response.status_code, message=message),
            )
        if isinstance(payload, dict) and payload.get("code") not in (None, 0, "0"):
            message = _payload_message(payload) or "Sub2API returned an application error"
            raise Sub2APIError(
                operation,
                response.status_code,
                safe_error(message),
                retryable=response.status_code >= 500,
                classification=classify_failure(http_status=response.status_code, message=message),
            )
        return _unwrap_data(payload)

    def list_accounts(self) -> list[dict[str, Any]]:
        accounts: list[dict[str, Any]] = []
        seen: set[int] = set()
        for account_type in ("oauth", "setup-token"):
            page = 1
            received = 0
            while True:
                data = self._request(
                    "GET",
                    "/api/v1/admin/accounts",
                    operation="list_accounts",
                    params={
                        "page": page,
                        "page_size": self.settings.scan_page_size,
                        "platform": "openai",
                        "type": account_type,
                        "lite": "false",
                    },
                )
                items, total = _items_and_total(data)
                received += len(items)
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_id = _account_id(item)
                    if item_id is None or item_id not in seen:
                        if item_id is not None:
                            seen.add(item_id)
                        accounts.append(item)
                if not items or received >= total or len(items) < self.settings.scan_page_size:
                    break
                page += 1
        return accounts

    def get_account(self, account_id: int) -> dict[str, Any]:
        data = self._request(
            "GET", f"/api/v1/admin/accounts/{account_id}", operation="get_account"
        )
        return data if isinstance(data, dict) else {}

    def export_account_credentials(self, account_id: int) -> dict[str, Any] | None:
        data = self._request(
            "GET",
            "/api/v1/admin/accounts/data",
            operation="export_account_credentials",
            params={"ids": str(account_id), "include_proxies": "false"},
        )
        items = data.get("accounts") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return None
        for item in items:
            if isinstance(item, dict) and _account_id(item) == account_id:
                return item
        return items[0] if len(items) == 1 and isinstance(items[0], dict) else None

    def native_refresh(self, account_id: int) -> dict[str, Any]:
        return self._request(
            "POST", f"/api/v1/admin/accounts/{account_id}/refresh", operation="native_refresh"
        )

    def apply_oauth_credentials(
        self,
        account_id: int,
        credentials: dict[str, Any],
        extra: dict[str, Any] | None = None,
        *,
        credential_type: str = "oauth",
    ) -> dict[str, Any]:
        payload = {"type": credential_type, "credentials": credentials}
        if extra:
            payload["extra"] = extra
        return self._request(
            "POST",
            f"/api/v1/admin/accounts/{account_id}/apply-oauth-credentials",
            operation="apply_oauth_credentials",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    def inspect_account(self, account_id: int) -> "AccountTestResult":
        try:
            account = self.get_account(account_id)
        except Sub2APIError as exc:
            return AccountTestResult(False, exc.status_code, safe_error(exc), exc.classification)
        classification = classify_account_snapshot(account)
        status = str(account.get("status") or "").lower()
        if classification is not None:
            status_code = 401 if classification.category.value == "401_AUTH_FAILURE" else None
            return AccountTestResult(False, status_code, classification.reason, classification)
        if status in {"error", "inactive", "disabled"}:
            classification = classify_failure(message=str(account.get("error_message") or status))
            return AccountTestResult(False, None, classification.reason, classification)
        if status not in {"active", "healthy", "ready"}:
            classification = classify_failure(message=f"Sub2API account status is {status or 'unknown'}")
            return AccountTestResult(False, None, classification.reason, classification)
        return AccountTestResult(True, 200, "Sub2API account status is healthy", None)

    def recover_state(self, account_id: int) -> dict[str, Any]:
        return self._request(
            "POST", f"/api/v1/admin/accounts/{account_id}/recover-state", operation="recover_state"
        )

    def set_schedulable(self, account_id: int, schedulable: bool = True) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/v1/admin/accounts/{account_id}/schedulable",
            operation="set_schedulable",
            json={"schedulable": schedulable},
            headers={"Content-Type": "application/json"},
        )


@dataclass(frozen=True)
class AccountTestResult:
    success: bool
    status_code: int | None
    reason: str
    classification: Classification | None
    body: str = ""


def _decode_response(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError):
        return response.text


def _unwrap_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _payload_message(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("message", "error", "reason", "detail"):
            value = payload.get(key)
            if isinstance(value, dict):
                nested = _payload_message(value)
                if nested:
                    return nested
            elif value:
                return str(value)
    elif isinstance(payload, str):
        return payload
    return ""


def _items_and_total(data: Any) -> tuple[list[Any], int]:
    if isinstance(data, list):
        return data, len(data)
    if not isinstance(data, dict):
        return [], 0
    items = data.get("items")
    if not isinstance(items, list):
        items = data.get("accounts") if isinstance(data.get("accounts"), list) else []
    total = int(data.get("total") or len(items))
    return items, total


def _account_id(item: dict[str, Any]) -> int | None:
    for key in ("id", "account_id", "sub2api_account_id"):
        try:
            if item.get(key) is not None:
                return int(item[key])
        except (TypeError, ValueError):
            continue
    return None
