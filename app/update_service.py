from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

import httpx

from .version import APP_VERSION

REPOSITORY = "AnnaKarelovsky/sub2api-401-recovery"
RELEASES_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
_VERSION_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_CHECK_TTL_SECONDS = 900
_check_lock = threading.Lock()
_cached_release: tuple[float, dict[str, Any] | None, str] | None = None


def _version_key(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.fullmatch(value.strip())
    return tuple(int(part) for part in match.groups()) if match else None


def latest_release(*, force: bool = False) -> tuple[dict[str, Any] | None, str]:
    global _cached_release
    now = time.monotonic()
    with _check_lock:
        if not force and _cached_release and now - _cached_release[0] < _CHECK_TTL_SECONDS:
            return _cached_release[1], _cached_release[2]
        request = urllib.request.Request(
            RELEASES_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "sub2api-401-recovery-update-check/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.load(response)
            tag = payload.get("tag_name") if isinstance(payload, dict) else None
            if not isinstance(tag, str) or not _version_key(tag):
                raise ValueError("release tag is not a supported version")
            url = payload.get("html_url", "")
            if not isinstance(url, str) or not url.startswith(
                f"https://github.com/{REPOSITORY}/releases/tag/"
            ):
                url = f"https://github.com/{REPOSITORY}/releases/tag/{quote(tag, safe='vV.-')}"
            release = {
                "version": tag if tag.startswith("v") else f"v{tag}",
                "url": url,
                "published_at": str(payload.get("published_at") or ""),
                "notes": str(payload.get("body") or "")[:6000],
            }
            result = (release, "")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            reason = "GitHub Release 暂时不可用" if isinstance(exc, urllib.error.URLError) else "版本信息暂时无法读取"
            result = (None, reason)
        _cached_release = (now, result[0], result[1])
        return result


def update_info(
    *,
    enabled: bool,
    current_version: str = APP_VERSION,
    force: bool = False,
) -> dict[str, Any]:
    if not enabled:
        return {
            "current_version": f"v{current_version.removeprefix('v')}",
            "latest_version": None,
            "update_available": False,
            "update_enabled": False,
            "release_url": None,
            "release_notes": "",
            "check_error": "此部署方式不支持 Dashboard 一键更新",
        }
    release, error = latest_release(force=force)
    current_key = _version_key(current_version)
    latest_key = _version_key(release["version"]) if release else None
    return {
        "current_version": f"v{current_version.removeprefix('v')}",
        "latest_version": release["version"] if release else None,
        "update_available": bool(current_key and latest_key and latest_key > current_key),
        "update_enabled": True,
        "release_url": release["url"] if release else None,
        "release_notes": release["notes"] if release else "",
        "published_at": release["published_at"] if release else None,
        "check_error": error,
    }


def request_agent(
    *,
    base_url: str,
    token: str,
    method: str = "GET",
    path: str = "/status",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not base_url or not token:
        raise RuntimeError("update agent is not configured")
    with httpx.Client(trust_env=False, timeout=8) as client:
        response = client.request(
            method,
            f"{base_url.rstrip('/')}{path}",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
    if response.status_code >= 400:
        detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else None
        raise RuntimeError(str(detail or "update agent request failed"))
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("update agent returned an invalid response")
    return value
