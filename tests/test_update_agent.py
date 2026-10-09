from __future__ import annotations

import os

import pytest

from app import update_agent


@pytest.mark.parametrize(
    ("value", "expected"),
    [("v1.2.3", (1, 2, 3)), ("1.2.3", (1, 2, 3)), ("01.2.3", None), ("main", None)],
)
def test_update_agent_accepts_only_numeric_release_versions(value, expected):
    assert update_agent._version_key(value) == expected


def test_compose_commands_include_the_deployment_project_name(monkeypatch, tmp_path):
    monkeypatch.setattr(update_agent, "PROJECT_NAME", "sub2api-recovery")
    monkeypatch.setattr(update_agent, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(update_agent, "COMPOSE_FILE", tmp_path / "docker-compose.release.yml")

    command = update_agent._compose_command("ps")

    assert command[2:4] == ["--project-name", "sub2api-recovery"]


def test_write_version_preserves_env_values_and_file_permissions(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DASHBOARD_PASSWORD=keep-me\nRECOVERY_VERSION=v0.4.16\n", encoding="utf-8")
    env_file.chmod(0o600)
    monkeypatch.setattr(update_agent, "ENV_FILE", env_file)
    monkeypatch.setattr(update_agent, "PROJECT_DIR", tmp_path)

    update_agent._write_version("v0.4.17")

    assert env_file.read_text(encoding="utf-8") == (
        "DASHBOARD_PASSWORD=keep-me\nRECOVERY_VERSION=v0.4.17\n"
    )
    assert os.stat(env_file).st_mode & 0o777 == 0o600


def test_run_update_refuses_custom_image_deployments(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("RECOVERY_VERSION=v0.4.16\nRECOVERY_IMAGE=custom/recovery:local\n", encoding="utf-8")
    monkeypatch.setattr(update_agent, "ENV_FILE", env_file)
    monkeypatch.setattr(update_agent, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(update_agent, "COMPOSE_FILE", tmp_path / "docker-compose.release.yml")

    with pytest.raises(update_agent.UpdateError, match="自定义镜像部署"):
        update_agent.run_update("v0.4.17")


def test_run_update_backs_up_before_pull_and_recreates_target_version(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    compose_file = tmp_path / "docker-compose.release.yml"
    env_file.write_text("RECOVERY_VERSION=v0.4.16\n", encoding="utf-8")
    compose_file.write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setattr(update_agent, "ENV_FILE", env_file)
    monkeypatch.setattr(update_agent, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(update_agent, "COMPOSE_FILE", compose_file)
    monkeypatch.setattr(update_agent, "PROJECT_NAME", "test-project")
    calls = []
    monkeypatch.setattr(
        update_agent,
        "_run",
        lambda args, version=None, timeout=300: calls.append((args, version, timeout)),
    )
    monkeypatch.setattr(update_agent, "_wait_healthy", lambda: True)

    update_agent.run_update("v0.4.17")

    assert "backup" in calls[0][0]
    assert calls[1][0][-3:] == ["pull", "recovery-api", "recovery-worker"]
    assert calls[1][1] == "v0.4.17"
    assert calls[2][0][-2:] == ["recovery-api", "recovery-worker"]
    assert calls[2][1] == "v0.4.17"
    assert "RECOVERY_VERSION=v0.4.17" in env_file.read_text(encoding="utf-8")


def test_run_update_restores_old_version_when_health_check_fails(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    compose_file = tmp_path / "docker-compose.release.yml"
    env_file.write_text("RECOVERY_VERSION=v0.4.16\n", encoding="utf-8")
    compose_file.write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setattr(update_agent, "ENV_FILE", env_file)
    monkeypatch.setattr(update_agent, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(update_agent, "COMPOSE_FILE", compose_file)
    monkeypatch.setattr(update_agent, "PROJECT_NAME", "test-project")
    calls = []
    monkeypatch.setattr(
        update_agent,
        "_run",
        lambda args, version=None, timeout=300: calls.append((args, version, timeout)),
    )
    health_results = iter((False, True))
    monkeypatch.setattr(update_agent, "_wait_healthy", lambda: next(health_results))

    with pytest.raises(update_agent.UpdateError, match="已恢复到原版本"):
        update_agent.run_update("v0.4.17")

    assert env_file.read_text(encoding="utf-8") == "RECOVERY_VERSION=v0.4.16\n"
    assert calls[-1][1] == "v0.4.16"
