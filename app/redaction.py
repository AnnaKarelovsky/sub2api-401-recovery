from __future__ import annotations

import json
import re
from typing import Any


SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "authorization_code",
    "code",
    "code_verifier",
    "cookie",
    "password",
    "email_password",
    "openai_password",
    "totp_secret",
    "verification_code",
    "otp",
    "notes",
    "client_secret",
    "api_key",
    "state",
}


def _is_sensitive(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS or any(
        marker in normalized
        for marker in ("token", "password", "cookie", "secret", "verification", "otp")
    )


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "***" if _is_sensitive(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


def redact_text(value: str) -> str:
    text = str(value or "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        try:
            return _redact_patterns(json.dumps(redact(parsed), ensure_ascii=True, separators=(",", ":")))
        except (TypeError, ValueError):
            return "<redacted>"
    return _redact_patterns(text)


def _redact_patterns(text: str) -> str:
    key_pattern = (
        r"(?i)(access_token|refresh_token|id_token|password|cookie|secret|"
        r"authorization_code|code_verifier|verification_code|otp|code|state)(\s*[:=]\s*)([^\s,;&]+)"
    )
    text = re.sub(key_pattern, r"\1\2***", text)
    text = re.sub(r"(?i)(\bauthorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;&]+", r"\1***", text)
    text = re.sub(r"(?i)(\bbearer\s+)[^\s,;&]+", r"\1***", text)
    return re.sub(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@", r"\1***:***@", text)


def safe_error(value: Any, max_length: int = 500) -> str:
    result = redact_text(str(value or "")).strip()
    return result[:max_length]
