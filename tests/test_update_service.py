from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import update_service


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("v1.2.3", (1, 2, 3)),
        ("1.2.3", (1, 2, 3)),
        ("v01.2.3", None),
        ("v1.2", None),
        ("main", None),
        ("v1.2.3-rc.1", None),
    ],
)
def test_version_key_accepts_only_stable_semver(value, expected):
    assert update_service._version_key(value) == expected


def test_update_info_disables_updates_for_source_deployments():
    result = update_service.update_info(enabled=False, current_version="v0.4.16")

    assert result["current_version"] == "v0.4.16"
    assert result["update_available"] is False
    assert result["update_enabled"] is False
    assert result["latest_version"] is None


def test_update_info_compares_numeric_versions_and_exposes_release_metadata(monkeypatch):
    monkeypatch.setattr(
        update_service,
        "latest_release",
        lambda force=False: (
            {
                "version": "v0.4.17",
                "url": "https://github.com/AnnaKarelovsky/sub2api-401-recovery/releases/tag/v0.4.17",
                "published_at": "2026-10-09T00:00:00Z",
                "notes": "Fixes and updates",
            },
            "",
        ),
    )

    result = update_service.update_info(enabled=True, current_version="v0.4.9")

    assert result["update_available"] is True
    assert result["latest_version"] == "v0.4.17"
    assert result["release_notes"] == "Fixes and updates"


def test_latest_release_rejects_non_version_tags(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"tag_name": "main"}).encode()

    monkeypatch.setattr(update_service.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    update_service._cached_release = None

    release, error = update_service.latest_release(force=True)

    assert release is None
    assert error == "版本信息暂时无法读取"


def test_latest_release_caches_successful_release(monkeypatch):
    calls = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(
                {
                    "tag_name": "v0.4.17",
                    "html_url": "https://github.com/AnnaKarelovsky/sub2api-401-recovery/releases/tag/v0.4.17",
                    "body": "Release notes",
                    "published_at": "2026-10-09T00:00:00Z",
                }
            ).encode()

    def urlopen(*_args, **_kwargs):
        calls.append(True)
        return Response()

    monkeypatch.setattr(update_service.urllib.request, "urlopen", urlopen)
    update_service._cached_release = None

    first = update_service.latest_release(force=True)
    second = update_service.latest_release()

    assert first == second
    assert first[0]["version"] == "v0.4.17"
    assert len(calls) == 1


def test_request_agent_disables_environment_proxy_and_sends_bearer(monkeypatch):
    seen = {}

    class Client:
        def __init__(self, **kwargs):
            seen["client_options"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def request(self, method, url, **kwargs):
            seen.update(method=method, url=url, request=kwargs)
            return SimpleNamespace(
                status_code=200,
                headers={"content-type": "application/json"},
                json=lambda: {"status": "idle"},
            )

    monkeypatch.setattr(update_service.httpx, "Client", Client)

    result = update_service.request_agent(
        base_url="http://recovery-update-agent:1456/",
        token="a" * 40,
    )

    assert result == {"status": "idle"}
    assert seen["client_options"]["trust_env"] is False
    assert seen["request"]["headers"]["Authorization"] == f"Bearer {'a' * 40}"
