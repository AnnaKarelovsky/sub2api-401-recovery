from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


VERSION_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
PROJECT_DIR = Path(os.environ.get("UPDATE_PROJECT_DIR", "/workspace")).resolve()
COMPOSE_FILE = PROJECT_DIR / "docker-compose.release.yml"
ENV_FILE = PROJECT_DIR / ".env"
TOKEN = os.environ.get("UPDATE_AGENT_TOKEN", "")
CURRENT_VERSION = os.environ.get("UPDATE_CURRENT_VERSION", "v0.4.19")
PORT = int(os.environ.get("UPDATE_AGENT_PORT", "1456"))
PROJECT_NAME = os.environ.get("UPDATE_COMPOSE_PROJECT_NAME", "").strip()
STATE_LOCK = threading.Lock()
UPDATE_LOCK = threading.Lock()
STATE: dict[str, Any] = {
    "status": "idle",
    "current_version": CURRENT_VERSION,
    "target_version": None,
    "started_at": None,
    "finished_at": None,
    "message": "",
}


class UpdateError(RuntimeError):
    pass


def _version_key(value: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.fullmatch(value.strip())
    return tuple(int(part) for part in match.groups()) if match else None


def _read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.is_file():
        return values
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _write_version(version: str) -> None:
    original = ENV_FILE.read_text(encoding="utf-8") if ENV_FILE.exists() else ""
    lines = original.splitlines(keepends=True)
    found = False
    for index, line in enumerate(lines):
        if line.startswith("RECOVERY_VERSION="):
            lines[index] = f"RECOVERY_VERSION={version}\n"
            found = True
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"RECOVERY_VERSION={version}\n")
    original_stat = ENV_FILE.stat() if ENV_FILE.exists() else None
    mode = original_stat.st_mode & 0o777 if original_stat else 0o600
    descriptor, temporary_name = tempfile.mkstemp(prefix=".env.update.", dir=PROJECT_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if original_stat:
                temporary_stat = os.fstat(handle.fileno())
                if (temporary_stat.st_uid, temporary_stat.st_gid) != (
                    original_stat.st_uid,
                    original_stat.st_gid,
                ):
                    os.fchown(handle.fileno(), original_stat.st_uid, original_stat.st_gid)
            os.fchmod(handle.fileno(), mode)
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, ENV_FILE)
        directory_fd = os.open(PROJECT_DIR, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _compose_command(*args: str) -> list[str]:
    global PROJECT_NAME
    if not PROJECT_NAME:
        container_id = os.environ.get("HOSTNAME", "")
        if container_id:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format={{index .Config.Labels \"com.docker.compose.project\"}}",
                    container_id,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            discovered = result.stdout.strip()
            if result.returncode == 0 and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", discovered):
                PROJECT_NAME = discovered
    if not PROJECT_NAME:
        raise UpdateError("无法读取当前 Docker Compose 项目名称")
    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT_NAME,
        "--project-directory",
        str(PROJECT_DIR),
        "-f",
        str(COMPOSE_FILE),
        *args,
    ]


def _run(args: list[str], *, version: str | None = None, timeout: int = 300) -> None:
    environment = os.environ.copy()
    environment.pop("RECOVERY_IMAGE", None)
    if version:
        environment["RECOVERY_VERSION"] = version
    result = subprocess.run(
        args,
        cwd=PROJECT_DIR,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise UpdateError("更新命令执行失败")


def _wait_healthy(timeout: int = 150) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        api_id_result = subprocess.run(
            _compose_command("ps", "-q", "recovery-api"),
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
        worker_id_result = subprocess.run(
            _compose_command("ps", "-q", "recovery-worker"),
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
        api_id = api_id_result.stdout.strip().splitlines()[-1:] or [""]
        worker_id = worker_id_result.stdout.strip().splitlines()[-1:] or [""]
        if api_id[0] and worker_id[0]:
            api_health = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                    api_id[0],
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
            ).stdout.strip()
            worker_state = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", worker_id[0]],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
            ).stdout.strip()
            if api_health == "healthy" and worker_state == "running":
                return True
        time.sleep(3)
    return False


def _set_state(**values: Any) -> None:
    with STATE_LOCK:
        STATE.update(values)


def run_update(target_version: str) -> None:
    old_version = _read_env().get("RECOVERY_VERSION", CURRENT_VERSION)
    old_version = old_version if _version_key(old_version) else CURRENT_VERSION
    env_values = _read_env()
    if env_values.get("RECOVERY_IMAGE"):
        raise UpdateError("自定义镜像部署不支持自动更新")
    if not COMPOSE_FILE.is_file() or not ENV_FILE.is_file():
        raise UpdateError("未找到发布版 Compose 配置")
    if not _version_key(target_version) or not _version_key(old_version):
        raise UpdateError("版本号无效")
    if _version_key(target_version) <= _version_key(old_version):
        raise UpdateError("目标版本必须高于当前版本")

    _run(_compose_command("exec", "-T", "recovery-api", "python", "-m", "app.cli", "backup"), timeout=120)
    _run(_compose_command("pull", "recovery-api", "recovery-worker"), version=target_version, timeout=900)
    try:
        _write_version(target_version)
        _run(
            _compose_command("up", "-d", "--no-deps", "--force-recreate", "recovery-api", "recovery-worker"),
            version=target_version,
            timeout=300,
        )
        if not _wait_healthy():
            raise UpdateError("新版本健康检查未通过")
    except Exception as exc:
        try:
            _write_version(old_version)
            _run(
                _compose_command("up", "-d", "--no-deps", "--force-recreate", "recovery-api", "recovery-worker"),
                version=old_version,
                timeout=300,
            )
            rolled_back = _wait_healthy()
        except Exception:
            rolled_back = False
        if rolled_back:
            raise UpdateError("更新未通过健康检查，已恢复到原版本") from exc
        raise UpdateError("更新失败，自动恢复也未通过；请检查服务器容器状态") from exc


def _update_worker(target_version: str) -> None:
    try:
        run_update(target_version)
        _set_state(
            status="succeeded",
            current_version=target_version,
            target_version=target_version,
            finished_at=datetime.now(timezone.utc).isoformat(),
            message=f"已更新到 {target_version}",
        )
    except Exception as exc:
        message = exc.args[0] if isinstance(exc, UpdateError) and exc.args else "更新失败"
        _set_state(
            status="failed",
            target_version=target_version,
            finished_at=datetime.now(timezone.utc).isoformat(),
            message=str(message),
        )
    finally:
        UPDATE_LOCK.release()


class UpdateHandler(BaseHTTPRequestHandler):
    server_version = "RecoveryUpdateAgent/1"

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {TOKEN}"
        return bool(TOKEN) and hmac.compare_digest(supplied.encode(), expected.encode())

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"detail": "authentication required"})
            return
        if self.path != "/status":
            self._send(404, {"detail": "not found"})
            return
        with STATE_LOCK:
            payload = dict(STATE)
        payload["current_version"] = _read_env().get("RECOVERY_VERSION", CURRENT_VERSION)
        self._send(200, payload)

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"detail": "authentication required"})
            return
        if self.path != "/update":
            self._send(404, {"detail": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            target_version = payload.get("version") if isinstance(payload, dict) else None
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"detail": "invalid request"})
            return
        if not isinstance(target_version, str) or not _version_key(target_version):
            self._send(400, {"detail": "invalid target version"})
            return
        if not UPDATE_LOCK.acquire(blocking=False):
            self._send(409, {"detail": "an update is already running"})
            return
        _set_state(
            status="running",
            current_version=_read_env().get("RECOVERY_VERSION", CURRENT_VERSION),
            target_version=target_version,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            message=f"正在更新到 {target_version}",
        )
        thread = threading.Thread(target=_update_worker, args=(target_version,), daemon=True)
        thread.start()
        self._send(202, {"status": "running", "target_version": target_version})

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def main() -> None:
    if not TOKEN or len(TOKEN) < 32:
        raise SystemExit("UPDATE_AGENT_TOKEN must contain at least 32 characters")
    if not PROJECT_DIR.is_dir():
        raise SystemExit("UPDATE_PROJECT_DIR does not exist")
    ThreadingHTTPServer(("0.0.0.0", PORT), UpdateHandler).serve_forever()


if __name__ == "__main__":
    main()
