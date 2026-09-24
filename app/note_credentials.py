from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NoteCredentials:
    email: str = ""
    email_password: str = ""
    openai_password: str = ""
    totp_secret: str = ""

    @property
    def complete(self) -> bool:
        return all((self.email, self.email_password, self.openai_password, self.totp_secret))

    @property
    def ready_for_automation(self) -> bool:
        """The browser can start; mailbox and MFA values are flow-dependent."""
        return bool(self.email and self.openai_password)

    @property
    def configured_count(self) -> int:
        return sum(bool(value) for value in (self.email, self.email_password, self.openai_password, self.totp_secret))

    @property
    def missing_fields(self) -> tuple[str, ...]:
        labels = {
            "email": "登录邮箱",
            "email_password": "邮箱密码",
            "openai_password": "OpenAI 密码",
            "totp_secret": "2FA 密钥",
        }
        return tuple(label for field, label in labels.items() if not getattr(self, field))

    @property
    def missing_required_fields(self) -> tuple[str, ...]:
        required = {"email": "登录邮箱", "openai_password": "OpenAI 密码"}
        return tuple(label for field, label in required.items() if not getattr(self, field))

    def as_dict(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "email": self.email,
                "email_password": self.email_password,
                "openai_password": self.openai_password,
                "totp_secret": self.totp_secret,
            }.items()
            if value
        }


_LABELS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "email_password",
        (
            "邮箱登录密码",
            "邮箱密码",
            "email login password",
            "email password",
            "mail password",
            "email pwd",
            "mail pwd",
        ),
    ),
    (
        "openai_password",
        (
            "openai 登录密码",
            "openai密码",
            "chatgpt密码",
            "gpt密码",
            "openai password",
            "chatgpt password",
            "gpt password",
            "openai pwd",
            "gpt pwd",
        ),
    ),
    (
        "totp_secret",
        (
            "2fa密钥",
            "2fa key",
            "2fa secret",
            "totp密钥",
            "totp key",
            "totp secret",
            "authenticator key",
            "verification key",
            "验证码密钥",
        ),
    ),
    (
        "email",
        (
            "邮箱",
            "email",
            "e-mail",
            "mail",
            "登录邮箱",
        ),
    ),
)


def parse_account_notes(notes: Any, *, fallback_email: str = "") -> NoteCredentials:
    text = str(notes or "")
    values: dict[str, str] = {}
    for candidate in _json_objects(text):
        _collect_json_values(candidate, values)

    labels = [(field, label) for field, aliases in _LABELS for label in aliases]
    labels.sort(key=lambda item: len(item[1]), reverse=True)
    pending: str | None = None
    for line in text.splitlines():
        cleaned = _clean_line(line)
        if not cleaned:
            continue
        matched = False
        for field, label in labels:
            pattern = rf"^(?:{re.escape(label)})(?:\s*[:：=]\s*|\s+)(.*?)\s*$"
            match = re.match(pattern, cleaned, re.IGNORECASE)
            if match:
                value = _clean_value(match.group(1))
                if value:
                    values.setdefault(field, value)
                    pending = None
                else:
                    pending = field
                matched = True
                break
        if matched:
            continue
        if pending:
            value = _clean_value(cleaned)
            if value:
                values.setdefault(pending, value)
                pending = None

    if not values.get("email"):
        match = re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.IGNORECASE)
        if match:
            values["email"] = match.group(0)
    values["email"] = (values.get("email") or fallback_email).strip().lower()
    return NoteCredentials(
        email=values.get("email", ""),
        email_password=values.get("email_password", ""),
        openai_password=values.get("openai_password", ""),
        totp_secret=values.get("totp_secret", ""),
    )


def _clean_line(value: str) -> str:
    return re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", value).strip().strip("`")


def _clean_value(value: str) -> str:
    result = value.strip().strip("` ")
    if len(result) >= 2 and result[0] == result[-1] and result[0] in "\"'":
        result = result[1:-1].strip()
    return result


def _json_objects(text: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return []
    return [parsed] if isinstance(parsed, dict) else []


def _collect_json_values(value: dict[str, Any], values: dict[str, str], context: str = "") -> None:
    context_key = _normalize_key(context)
    for key, item in value.items():
        key_text = str(key)
        normalized_key = _normalize_key(key_text)
        field = _json_field(normalized_key, context_key)
        if field and isinstance(item, str):
            value_text = _clean_value(item)
            if value_text:
                values.setdefault(field, value_text)
        if isinstance(item, dict):
            _collect_json_values(item, values, normalized_key)


def _json_field(key: str, context: str) -> str:
    if key in {"email", "mail", "bindemail", "primaryemail", "loginemail", "邮箱"}:
        return "email"
    if key in {"emailpassword", "mailpassword", "邮箱密码"}:
        return "email_password"
    if key == "password":
        if context in {"mailbox", "email", "mail", "邮箱"}:
            return "email_password"
        if context in {"gpt", "openai", "chatgpt", "openaiauth"}:
            return "openai_password"
    if key in {"openaipassword", "chatgptpassword", "gptpassword", "gpt密码"}:
        return "openai_password"
    if key in {"totp", "totpsecret", "2fasecret", "2fakey", "totp密钥", "secret"}:
        if context in {"twofactor", "2fa", "totp", "authenticator", "mfa"} or key != "secret":
            return "totp_secret"
    return ""


def _normalize_key(value: str) -> str:
    return re.sub(r"[\W_]", "", value.lower())
