from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Mapping
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# These are operational settings that can be changed after the service has booted.
# Bootstrap values such as the encryption key, database path, and session signing
# secret intentionally stay in the environment.
DASHBOARD_SETTING_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "key": "sub2api",
        "label": "Sub2API 连接",
        "fields": (
            {"key": "sub2api_base_url", "label": "Admin API 地址", "type": "text"},
            {"key": "sub2api_admin_key", "label": "Admin API 密钥", "type": "secret"},
            {"key": "sub2api_jwt", "label": "JWT（可选）", "type": "secret"},
            {
                "key": "sub2api_timeout_seconds",
                "label": "请求超时（秒）",
                "type": "number",
                "step": "0.1",
                "min": 1,
                "max": 600,
            },
        ),
    },
    {
        "key": "scheduler",
        "label": "扫描与恢复",
        "fields": (
            {"key": "scan_interval_seconds", "label": "扫描间隔（秒）", "type": "integer", "min": 10, "max": 86400},
            {"key": "scan_page_size", "label": "每页账号数", "type": "integer", "min": 1, "max": 1000},
            {"key": "scan_probe_active_accounts", "label": "检查正常账号", "type": "boolean"},
            {"key": "scan_probe_interval_seconds", "label": "正常账号检查间隔（秒）", "type": "integer", "min": 10, "max": 604800},
            {"key": "recovery_max_attempts", "label": "恢复重试次数", "type": "integer", "min": 1, "max": 20},
            {"key": "recovery_backoff_seconds", "label": "任务重试等待（秒）", "type": "integer", "min": 0, "max": 86400},
            {"key": "worker_poll_seconds", "label": "worker 轮询间隔（秒）", "type": "integer", "min": 1, "max": 300},
        ),
    },
    {
        "key": "automation",
        "label": "自动重新授权",
        "fields": (
            {"key": "playwright_enabled", "label": "启用浏览器自动授权", "type": "boolean"},
            {"key": "playwright_headless", "label": "无头浏览器", "type": "boolean"},
            {"key": "playwright_timeout_seconds", "label": "浏览器超时（秒）", "type": "integer", "min": 30, "max": 3600},
            {"key": "playwright_proxy", "label": "浏览器代理", "type": "secret"},
            {"key": "automation_require_complete_notes", "label": "备注信息不完整时阻止自动化", "type": "boolean"},
            {"key": "automation_browser_retries", "label": "浏览器启动重试次数", "type": "integer", "min": 1, "max": 10},
            {"key": "automation_challenge_timeout_seconds", "label": "安全挑战等待（秒）", "type": "integer", "min": 10, "max": 3600},
            {"key": "automation_retry_forever", "label": "可重试问题持续重试", "type": "boolean"},
            {"key": "automation_retry_backoff_seconds", "label": "自动重试等待（秒）", "type": "integer", "min": 60, "max": 604800},
            {"key": "automation_cdp_url", "label": "Chromium CDP 地址", "type": "secret"},
            {"key": "automation_chromium_path", "label": "Chromium 可执行文件", "type": "text"},
        ),
    },
    {
        "key": "mail",
        "label": "邮箱验证码",
        "fields": (
            {"key": "mail_imap_host", "label": "IMAP 地址", "type": "text"},
            {"key": "mail_imap_port", "label": "IMAP 端口", "type": "integer", "min": 1, "max": 65535},
            {"key": "mail_imap_folder", "label": "邮箱文件夹", "type": "text"},
            {"key": "mail_code_timeout_seconds", "label": "验证码等待（秒）", "type": "integer", "min": 10, "max": 1800},
            {"key": "mail_poll_seconds", "label": "邮箱轮询间隔（秒）", "type": "integer", "min": 1, "max": 120},
            {"key": "outlook_webmail_enabled", "label": "允许网页邮箱验证码兜底", "type": "boolean"},
        ),
    },
    {
        "key": "proxy",
        "label": "服务网络代理",
        "fields": (
            {"key": "http_proxy", "label": "HTTP 代理", "type": "secret"},
            {"key": "https_proxy", "label": "HTTPS 代理", "type": "secret"},
            {"key": "all_proxy", "label": "全协议代理", "type": "secret"},
            {"key": "no_proxy", "label": "不使用代理的地址", "type": "text"},
        ),
    },
    {
        "key": "dashboard",
        "label": "Dashboard 登录",
        "fields": (
            {"key": "dashboard_username", "label": "管理员账号", "type": "text"},
            {"key": "dashboard_password", "label": "管理员密码", "type": "secret"},
            {"key": "dashboard_session_minutes", "label": "会话有效期（分钟）", "type": "integer", "min": 60, "max": 43200},
        ),
    },
)

DASHBOARD_SETTING_DEFINITIONS: dict[str, dict[str, Any]] = {
    field["key"]: field
    for group in DASHBOARD_SETTING_GROUPS
    for field in group["fields"]
}
_DASHBOARD_SECRET_KEYS = {
    key for key, definition in DASHBOARD_SETTING_DEFINITIONS.items() if definition["type"] == "secret"
}
_DASHBOARD_BOOLEAN_KEYS = {
    key for key, definition in DASHBOARD_SETTING_DEFINITIONS.items() if definition["type"] == "boolean"
}
_DASHBOARD_INTEGER_KEYS = {
    key for key, definition in DASHBOARD_SETTING_DEFINITIONS.items() if definition["type"] == "integer"
}
_DASHBOARD_NUMBER_KEYS = {
    key for key, definition in DASHBOARD_SETTING_DEFINITIONS.items() if definition["type"] == "number"
}


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables.

    Secrets intentionally have no usable production defaults. ``validate_runtime`` is
    called during application startup so importing modules and running unit tests does
    not require a local deployment configuration.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    app_name: str = "Sub2API 401 Recovery"
    app_host: str = "0.0.0.0"
    app_port: int = 1455
    log_level: str = "INFO"
    database_path: str = "./data/recovery.db"
    backup_dir: str = "./backups"

    encryption_key: str = Field(default="", validation_alias="ENCRYPTION_KEY")
    dashboard_username: str = Field(default="admin", validation_alias="DASHBOARD_USERNAME")
    dashboard_password: str = Field(default="", validation_alias="DASHBOARD_PASSWORD")
    dashboard_secret: str = Field(default="", validation_alias="DASHBOARD_SECRET")
    dashboard_session_minutes: int = 720

    sub2api_base_url: str = Field(default="", validation_alias="SUB2API_BASE_URL")
    sub2api_admin_key: str = Field(default="", validation_alias="SUB2API_ADMIN_KEY")
    sub2api_jwt: str = Field(default="", validation_alias="SUB2API_JWT")
    sub2api_timeout_seconds: float = 30.0
    sub2api_test_timeout_seconds: float = 90.0

    http_proxy: str = Field(default="", validation_alias="HTTP_PROXY")
    https_proxy: str = Field(default="", validation_alias="HTTPS_PROXY")
    all_proxy: str = Field(default="", validation_alias="ALL_PROXY")
    no_proxy: str = Field(default="", validation_alias="NO_PROXY")

    scan_interval_seconds: int = 60
    scan_page_size: int = 100
    scan_probe_active_accounts: bool = True
    scan_probe_interval_seconds: int = 900
    recovery_max_attempts: int = 3
    recovery_backoff_seconds: int = 30
    worker_poll_seconds: int = 3
    worker_stale_seconds: int = 900

    openai_oauth_authorize_url: str = "https://auth.openai.com/oauth/authorize"
    openai_oauth_token_url: str = "https://auth.openai.com/oauth/token"
    openai_oauth_client_id: str = "app_EMoamEEZ73f0CkXaXp7hrann"
    openai_oauth_scope: str = (
        "openid profile email offline_access api.connectors.read api.connectors.invoke"
    )
    openai_oauth_redirect_uri: str = "http://localhost:1455/auth/callback"
    openai_oauth_timeout_seconds: float = 120.0
    openai_originator: str = "codex_cli_rs"

    playwright_enabled: bool = False
    playwright_headless: bool = True
    playwright_timeout_seconds: int = 600
    playwright_proxy: str = ""

    automation_require_complete_notes: bool = True
    automation_browser_retries: int = 2
    automation_challenge_timeout_seconds: int = 90
    automation_retry_forever: bool = True
    automation_retry_backoff_seconds: int = 900
    automation_cdp_url: str = ""
    automation_chromium_path: str = ""
    mail_imap_host: str = "outlook.office365.com"
    mail_imap_port: int = 993
    mail_imap_folder: str = "INBOX"
    mail_code_timeout_seconds: int = 150
    mail_poll_seconds: int = 5
    outlook_webmail_enabled: bool = True

    def validate_runtime(self, *, require_sub2api: bool = True) -> None:
        if not self.encryption_key.strip():
            raise ValueError("ENCRYPTION_KEY must be configured")
        if not self.dashboard_password.strip():
            raise ValueError("DASHBOARD_PASSWORD must be configured")
        if not self.dashboard_secret.strip():
            raise ValueError("DASHBOARD_SECRET must be configured")
        if require_sub2api:
            if not self.sub2api_base_url.strip():
                raise ValueError("SUB2API_BASE_URL must be configured")
            if not (self.sub2api_admin_key.strip() or self.sub2api_jwt.strip()):
                raise ValueError("SUB2API_ADMIN_KEY or SUB2API_JWT must be configured")
        if self.scan_interval_seconds < 10:
            raise ValueError("SCAN_INTERVAL_SECONDS must be at least 10")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def coerce_dashboard_setting(key: str, value: Any) -> Any:
    """Validate and normalize one Dashboard setting before it reaches SQLite."""
    definition = DASHBOARD_SETTING_DEFINITIONS.get(key)
    if not definition:
        raise ValueError(f"setting is not editable: {key}")
    setting_type = definition["type"]
    if setting_type == "boolean":
        if isinstance(value, bool):
            normalized = value
        elif isinstance(value, str) and value.lower() in {"true", "false"}:
            normalized = value.lower() == "true"
        else:
            raise ValueError(f"{key} must be a boolean")
    elif setting_type == "integer":
        if isinstance(value, bool):
            raise ValueError(f"{key} must be an integer")
        try:
            normalized = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be an integer") from exc
    elif setting_type == "number":
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a number")
        try:
            normalized = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a number") from exc
    else:
        if not isinstance(value, str):
            raise ValueError(f"{key} must be text")
        normalized = value.strip()

    minimum = definition.get("min")
    maximum = definition.get("max")
    if minimum is not None and normalized < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    if maximum is not None and normalized > maximum:
        raise ValueError(f"{key} must be at most {maximum}")
    if key == "sub2api_base_url" and normalized:
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("sub2api_base_url must be an http(s) URL")
    return normalized


def apply_dashboard_settings(
    settings: Settings,
    overrides: Mapping[str, Any],
    *,
    base_settings: Settings | None = None,
) -> None:
    """Apply encrypted Dashboard overrides to a Settings object in place."""
    if base_settings is not None:
        for key in DASHBOARD_SETTING_DEFINITIONS:
            setattr(settings, key, getattr(base_settings, key))
    for key, value in overrides.items():
        if key not in DASHBOARD_SETTING_DEFINITIONS:
            continue
        setattr(settings, key, coerce_dashboard_setting(key, value))


def dashboard_setting_values(settings: Settings) -> dict[str, Any]:
    """Return the complete editable configuration for an encrypted profile snapshot."""
    return {
        key: coerce_dashboard_setting(key, getattr(settings, key))
        for key in DASHBOARD_SETTING_DEFINITIONS
    }


def configure_process_proxy(settings: Settings) -> None:
    """Make DB-backed proxy settings visible to httpx in this process."""
    for env_key, value in (
        ("HTTP_PROXY", settings.http_proxy),
        ("HTTPS_PROXY", settings.https_proxy),
        ("ALL_PROXY", settings.all_proxy),
        ("NO_PROXY", settings.no_proxy),
    ):
        if value.strip():
            os.environ[env_key] = value.strip()
        else:
            os.environ.pop(env_key, None)
            os.environ.pop(env_key.lower(), None)


def dashboard_settings_payload(settings: Settings, overrides: Mapping[str, Any], revision: int) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []
    for group in DASHBOARD_SETTING_GROUPS:
        fields: list[dict[str, Any]] = []
        for definition in group["fields"]:
            key = definition["key"]
            value = getattr(settings, key)
            field = {
                **definition,
                "secret": key in _DASHBOARD_SECRET_KEYS,
                "value": "" if key in _DASHBOARD_SECRET_KEYS else value,
                "configured": bool(str(value).strip()) if key in _DASHBOARD_SECRET_KEYS else True,
                "source": "dashboard" if key in overrides else "env/default",
            }
            fields.append(field)
        groups.append({"key": group["key"], "label": group["label"], "fields": fields})
    return {
        "groups": groups,
        "revision": revision,
        "bootstrap_only": [
            "ENCRYPTION_KEY",
            "DATABASE_PATH",
            "APP_HOST",
            "APP_PORT",
            "DASHBOARD_SECRET",
        ],
    }


def is_dashboard_secret(key: str) -> bool:
    return key in _DASHBOARD_SECRET_KEYS
