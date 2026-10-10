#!/usr/bin/env python3
"""Synchronize the Codex custom model catalog with an OpenAI-compatible API."""

from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
DEFAULT_CONFIG_PATH = DEFAULT_CODEX_HOME / "config.toml"
DEFAULT_AUTH_PATH = DEFAULT_CODEX_HOME / "auth.json"
INTERNAL_MODEL_SLUGS = {"codex-auto-review"}
MODEL_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class SyncError(RuntimeError):
    """Raised when a sync cannot safely complete."""


@dataclass(frozen=True)
class SyncResult:
    catalog_path: Path
    upstream_count: int
    added: tuple[str, ...]
    hidden: tuple[str, ...]
    restored: tuple[str, ...]
    changed: bool
    backup_path: Path | None
    restart_pending: bool = False


@dataclass(frozen=True)
class RestartResult:
    status: str
    detail: str
    app_server_pid: int | None = None
    last_activity_at: float | None = None


def _read_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            config = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise SyncError(f"Codex config not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SyncError(f"Invalid Codex config: {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise SyncError(f"Unexpected Codex config shape: {path}")
    return config


def resolve_paths(
    config_path: Path = DEFAULT_CONFIG_PATH,
    auth_path: Path = DEFAULT_AUTH_PATH,
    catalog_path: Path | None = None,
) -> tuple[Path, Path, str]:
    config = _read_config(config_path)
    base_url = str(config.get("openai_base_url") or "").strip().rstrip("/")
    if not base_url:
        raise SyncError(f"openai_base_url is not configured in {config_path}")
    if not (base_url.startswith("https://") or base_url.startswith("http://")):
        raise SyncError("openai_base_url must use http:// or https://")

    configured_catalog = str(config.get("model_catalog_json") or "").strip()
    resolved_catalog = catalog_path or Path(configured_catalog or DEFAULT_CODEX_HOME / "models-custom.json")
    if not resolved_catalog.is_absolute():
        resolved_catalog = config_path.parent / resolved_catalog
    return config_path, resolved_catalog, f"{base_url}/models"


def read_api_key(auth_path: Path) -> str:
    environment_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if environment_key:
        return environment_key
    try:
        with auth_path.open(encoding="utf-8") as handle:
            auth = json.load(handle)
    except FileNotFoundError as exc:
        raise SyncError(f"Codex auth file not found: {auth_path}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError(f"Invalid Codex auth file: {auth_path}: {exc}") from exc
    api_key = str(auth.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise SyncError(f"OPENAI_API_KEY is not present in {auth_path}")
    return api_key


def fetch_model_records(models_url: str, api_key: str, timeout: float) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        models_url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "codex-model-sync/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(300).decode("utf-8", errors="replace").strip()
        except OSError:
            pass
        suffix = f": {detail}" if detail else ""
        raise SyncError(f"Upstream models request failed with HTTP {exc.code}{suffix}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SyncError(f"Upstream models request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError(f"Upstream models response was not valid JSON: {exc}") from exc

    if isinstance(payload, dict):
        records = payload.get("data")
    else:
        records = payload
    if not isinstance(records, list):
        raise SyncError("Upstream models response must contain a list in 'data'")
    valid_records = [record for record in records if isinstance(record, dict) and record.get("id")]
    if not valid_records:
        raise SyncError("Upstream returned no usable models; refusing to change the catalog")
    return valid_records


def _model_slug(record: dict[str, Any]) -> str:
    slug = str(record.get("id") or "").strip()
    if not slug or not MODEL_SLUG_RE.fullmatch(slug):
        raise SyncError(f"Upstream returned an invalid model id: {slug!r}")
    return slug


def _display_name(slug: str) -> str:
    words = re.split(r"[-_:]+", slug)
    return "-".join(
        "GPT" if word.lower() == "gpt" else word.upper() if word.isdigit() else word.capitalize()
        for word in words
        if word
    )


def _default_priority(models: Iterable[dict[str, Any]]) -> int:
    priorities = [model.get("priority") for model in models]
    numeric = [value for value in priorities if isinstance(value, int) and not isinstance(value, bool)]
    return max(numeric, default=0) + 1


def _template_model(existing_models: list[dict[str, Any]]) -> dict[str, Any]:
    preferred = next(
        (model for model in existing_models if model.get("slug") == "gpt-5.6-luna"),
        None,
    )
    if preferred is None:
        preferred = next(
            (model for model in existing_models if model.get("model_messages")),
            None,
        )
    if preferred is None:
        raise SyncError("Catalog has no model metadata template")
    return copy.deepcopy(preferred)


def _new_model(slug: str, template: dict[str, Any], priority: int) -> dict[str, Any]:
    model = copy.deepcopy(template)
    model.update(
        {
            "slug": slug,
            "display_name": _display_name(slug),
            "description": "Model discovered from the configured API provider.",
            "visibility": "list",
            "supported_in_api": True,
            "priority": priority,
        }
    )
    return model


def _load_json(path: Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise SyncError(f"{label} not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError(f"Invalid {label}: {path}: {exc}") from exc


def _state_path(catalog_path: Path) -> Path:
    return catalog_path.with_name(f"{catalog_path.name}.sync-state.json")


@contextmanager
def _catalog_lock(catalog_path: Path):
    lock_path = catalog_path.with_name(f".{catalog_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        yield


def _read_proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()


def find_app_server_pid() -> int | None:
    """Find the native app-server child, excluding the stdio proxy."""
    candidates: list[int] = []
    for proc_path in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(proc_path.name)
        except ValueError:
            continue
        command = _read_proc_cmdline(pid)
        if "app-server --listen" not in command or "app-server proxy" in command:
            continue
        if "codex" in command:
            candidates.append(pid)
    return max(candidates) if candidates else None


def _activity_query(process_pattern: str) -> str:
    return """
        SELECT MAX(ts)
        FROM logs
        WHERE process_uuid LIKE ?
          AND (
            (target = 'codex_core::session::handlers' AND feedback_log_body LIKE '%op: TurnInput%')
            OR (target = 'codex_app_server::outgoing_message' AND (
                feedback_log_body LIKE 'app-server event: turn/%'
                OR feedback_log_body LIKE 'app-server event: item/%'
                OR feedback_log_body LIKE 'app-server event: command/%'
                OR feedback_log_body LIKE 'app-server event: process/%'
            ))
            OR (target IN (
                'codex_core::session::turn',
                'codex_core::tools::parallel',
                'codex_code_mode::timing',
                'codex_http_client::client'
            ) AND feedback_log_body LIKE '%turn{%')
          )
    """


def app_server_idle(
    codex_home: Path,
    *,
    quiet_seconds: float = 600.0,
) -> tuple[bool, str, int | None, float | None]:
    """Return idle only when current app-server activity has gone quiet."""
    pid = find_app_server_pid()
    if pid is None:
        return True, "app-server is not running", None, None

    logs_path = codex_home / "logs_2.sqlite"
    if not logs_path.exists():
        return False, f"activity log not found: {logs_path}", pid, None

    try:
        database = sqlite3.connect(f"file:{logs_path}?mode=ro", uri=True, timeout=2.0)
        try:
            row = database.execute(_activity_query(""), (f"pid:{pid}:%",)).fetchone()
        finally:
            database.close()
    except sqlite3.Error as exc:
        return False, f"cannot inspect activity log: {exc}", pid, None

    last_activity = float(row[0]) if row and row[0] is not None else None
    if last_activity is None:
        return True, "no activity recorded for this app-server process", pid, None
    quiet_for = max(0.0, time.time() - last_activity)
    if quiet_for < quiet_seconds:
        return False, f"app-server activity was recorded {quiet_for:.0f}s ago", pid, last_activity
    return True, f"app-server has been quiet for {quiet_for:.0f}s", pid, last_activity


def _wait_for_app_server_state(*, expected_running: bool, old_pid: int | None = None, timeout: float = 30.0) -> int | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid = find_app_server_pid()
        if not expected_running:
            if pid is None or (old_pid is not None and pid != old_pid):
                return pid
        elif pid is not None and (old_pid is None or pid != old_pid):
            return pid
        time.sleep(0.25)
    return find_app_server_pid()


def restart_app_server(codex_home: Path, *, old_pid: int | None) -> RestartResult:
    """Restart the app-server, using the managed CLI when available."""
    codex_binary = shutil.which("codex") or "/home/ricardo/.local/bin/codex"
    env = os.environ.copy()
    env.update({"CODEX_HOME": str(codex_home), "HOME": str(Path.home())})

    managed = subprocess.run(
        [codex_binary, "app-server", "daemon", "restart"],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if managed.returncode == 0:
        new_pid = _wait_for_app_server_state(expected_running=True, old_pid=old_pid)
        if new_pid is None:
            raise SyncError("managed app-server restart returned success but no server appeared")
        return RestartResult("restarted", "managed app-server restart succeeded", new_pid)

    if old_pid is None:
        return RestartResult("not-needed", "app-server is not running")

    parent_pid = None
    try:
        parent_pid = int(Path(f"/proc/{old_pid}/stat").read_text().split(") ", 1)[1].split()[1])
    except (FileNotFoundError, ValueError, OSError):
        pass
    if parent_pid in {None, 1} or "app-server" not in _read_proc_cmdline(parent_pid):
        parent_pid = None
    for pid in (old_pid, parent_pid):
        if pid and pid != os.getpid():
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise SyncError(f"cannot stop app-server process {pid}: {exc}") from exc
    _wait_for_app_server_state(expected_running=False, old_pid=old_pid)

    log_path = codex_home / "app-server-control" / "app-server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [codex_binary, "-c", "features.code_mode_host=true", "app-server", "--listen", "unix://"],
            cwd=str(Path.home()),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        log_handle.close()
        raise
    log_handle.close()
    new_pid = _wait_for_app_server_state(expected_running=True, old_pid=old_pid)
    if new_pid is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        raise SyncError("new app-server process did not appear within 30 seconds")
    return RestartResult("restarted", "ephemeral app-server restarted", new_pid)


def _atomic_write_json(path: Path, value: Any, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    original_mode = mode
    if original_mode is None and path.exists():
        original_mode = path.stat().st_mode & 0o777
    if original_mode is None:
        original_mode = 0o600
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, original_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _backup(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = path.with_name(f"{path.name}.backup-{timestamp}")
    counter = 1
    while backup_path.exists():
        backup_path = path.with_name(f"{path.name}.backup-{timestamp}-{counter}")
        counter += 1
    backup_path.write_bytes(path.read_bytes())
    os.chmod(backup_path, path.stat().st_mode & 0o777)
    return backup_path


def merge_catalog(
    catalog: dict[str, Any],
    upstream_records: list[dict[str, Any]],
    state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    existing_models = catalog.get("models")
    if not isinstance(existing_models, list) or not all(isinstance(model, dict) for model in existing_models):
        raise SyncError("Catalog must contain a 'models' list of objects")

    existing_by_slug: dict[str, dict[str, Any]] = {}
    for model in existing_models:
        slug = str(model.get("slug") or "").strip()
        if slug:
            existing_by_slug[slug] = model

    upstream_ids: list[str] = []
    upstream_by_slug: dict[str, dict[str, Any]] = {}
    for record in upstream_records:
        slug = _model_slug(record)
        if slug not in upstream_by_slug:
            upstream_ids.append(slug)
            upstream_by_slug[slug] = record

    old_managed = state.get("managed_models")
    if isinstance(old_managed, list):
        managed = {str(slug) for slug in old_managed if str(slug).strip()}
    else:
        managed = set(existing_by_slug) - INTERNAL_MODEL_SLUGS
    managed.update(set(existing_by_slug) - INTERNAL_MODEL_SLUGS)

    hidden_by_sync = state.get("hidden_by_sync")
    hidden_by_sync_set = {
        str(slug) for slug in (hidden_by_sync if isinstance(hidden_by_sync, list) else []) if str(slug).strip()
    }
    next_catalog = copy.deepcopy(catalog)
    next_models = copy.deepcopy(existing_models)
    next_by_slug = {
        str(model.get("slug")): model for model in next_models if str(model.get("slug") or "").strip()
    }
    added: list[str] = []
    hidden: list[str] = []
    restored: list[str] = []
    next_priority = _default_priority(next_models)
    template = _template_model(next_models)

    for slug in upstream_ids:
        model = next_by_slug.get(slug)
        if model is None:
            model = _new_model(slug, template, next_priority)
            next_priority += 1
            next_models.append(model)
            next_by_slug[slug] = model
            added.append(slug)
        elif slug in hidden_by_sync_set:
            model["visibility"] = "list"
            hidden_by_sync_set.remove(slug)
            restored.append(slug)
        if model.get("description") == "Model discovered from the configured API provider.":
            model["display_name"] = _display_name(slug)
        model["supported_in_api"] = True

    for slug in sorted(managed - set(upstream_ids)):
        model = next_by_slug.get(slug)
        if model is None or slug in INTERNAL_MODEL_SLUGS:
            continue
        if model.get("visibility") == "list":
            model["visibility"] = "hide"
            hidden.append(slug)
            hidden_by_sync_set.add(slug)

    next_catalog["models"] = next_models
    next_state = {
        key: value
        for key, value in state.items()
        if key not in {"managed_models", "hidden_by_sync", "last_upstream_models", "last_sync_at"}
    }
    next_state.update({
        "managed_models": sorted(managed | set(upstream_ids)),
        "hidden_by_sync": sorted(hidden_by_sync_set),
        "last_upstream_models": upstream_ids,
        "last_sync_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    return next_catalog, next_state, tuple(added), tuple(hidden), tuple(restored)


def sync_catalog(
    catalog_path: Path,
    upstream_records: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> SyncResult:
    with _catalog_lock(catalog_path):
        current = _load_json(catalog_path, "model catalog")
        if not isinstance(current, dict):
            raise SyncError("Model catalog must be a JSON object")
        state_path = _state_path(catalog_path)
        state = _load_json(state_path, "sync state") if state_path.exists() else {}
        if not isinstance(state, dict):
            raise SyncError("Sync state must be a JSON object")
        next_catalog, next_state, added, hidden, restored = merge_catalog(current, upstream_records, state)
        current_json = json.dumps(current, ensure_ascii=False, indent=2) + "\n"
        next_json = json.dumps(next_catalog, ensure_ascii=False, indent=2) + "\n"
        changed = current_json != next_json
        backup_path: Path | None = None
        if changed and not dry_run:
            next_state["restart_pending"] = True
            next_state["restart_requested_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            backup_path = _backup(catalog_path)
            _atomic_write_json(catalog_path, next_catalog)
        if not dry_run:
            _atomic_write_json(state_path, next_state)
        restart_pending = bool(next_state.get("restart_pending")) or (changed and dry_run)
        return SyncResult(
            catalog_path,
            len(upstream_records),
            added,
            hidden,
            restored,
            changed,
            backup_path,
            restart_pending,
        )


def apply_pending_restart(
    catalog_path: Path,
    codex_home: Path,
    *,
    quiet_seconds: float = 600.0,
    force: bool = False,
) -> RestartResult:
    state_path = _state_path(catalog_path)
    with _catalog_lock(catalog_path):
        state = _load_json(state_path, "sync state") if state_path.exists() else {}
        if not isinstance(state, dict):
            raise SyncError("Sync state must be a JSON object")
        if not state.get("restart_pending"):
            return RestartResult("not-pending", "no app-server restart is pending")

        if force:
            idle, reason, pid, last_activity = True, "forced by operator", find_app_server_pid(), None
        else:
            idle, reason, pid, last_activity = app_server_idle(codex_home, quiet_seconds=quiet_seconds)
        if not idle:
            state["restart_last_deferred_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            state["restart_last_defer_reason"] = reason
            _atomic_write_json(state_path, state)
            return RestartResult("deferred", reason, pid, last_activity)

        result = restart_app_server(codex_home, old_pid=pid)
        state["restart_pending"] = False
        state["last_restart_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        state["last_restart_status"] = result.status
        state["last_restart_detail"] = result.detail
        _atomic_write_json(state_path, state)
        return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Codex config.toml path")
    parser.add_argument("--auth-file", type=Path, default=DEFAULT_AUTH_PATH, help="Codex auth.json path")
    parser.add_argument("--catalog", type=Path, help="Override model catalog JSON path")
    parser.add_argument("--base-url", help="Override the configured API base URL")
    parser.add_argument("--api-key", help="Override the API key (discouraged; prefer auth.json)")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and report changes without writing files")
    parser.add_argument("--show-models", action="store_true", help="Print the fetched model ids")
    parser.add_argument(
        "--auto-restart-if-idle",
        action="store_true",
        help="Apply a pending app-server restart only when it is idle",
    )
    parser.add_argument(
        "--apply-pending",
        action="store_true",
        help="Apply a previously deferred app-server restart without fetching models",
    )
    parser.add_argument(
        "--force-restart",
        action="store_true",
        help="Restart a pending app-server even if activity is detected",
    )
    parser.add_argument(
        "--idle-after-seconds",
        type=float,
        default=600.0,
        help="Required quiet period before an automatic restart (default: 600)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.apply_pending:
            _, catalog_path, _ = resolve_paths(args.config, args.auth_file, args.catalog)
            result = apply_pending_restart(
                catalog_path,
                DEFAULT_CODEX_HOME,
                quiet_seconds=args.idle_after_seconds,
                force=args.force_restart,
            )
            print(f"App-server restart: {result.status} ({result.detail})")
            return 0
        if args.force_restart:
            raise SyncError("--force-restart requires --apply-pending")
        _, catalog_path, models_url = resolve_paths(args.config, args.auth_file, args.catalog)
        if args.base_url:
            base_url = args.base_url.rstrip("/")
            models_url = f"{base_url}/models"
        api_key = args.api_key or read_api_key(args.auth_file)
        records = fetch_model_records(models_url, api_key, args.timeout)
        if args.show_models:
            print("Upstream models:")
            for record in records:
                print(f"- {_model_slug(record)}")
        result = sync_catalog(catalog_path, records, dry_run=args.dry_run)
        if result.changed:
            action = "would update" if args.dry_run else "updated"
        else:
            action = "already current (dry-run)" if args.dry_run else "already current"
        print(f"Codex model catalog {action}: {catalog_path}")
        print(f"Upstream models: {result.upstream_count}; added: {len(result.added)}; hidden: {len(result.hidden)}; restored: {len(result.restored)}")
        if result.added:
            print(f"Added: {', '.join(result.added)}")
        if result.hidden:
            print(f"Hidden: {', '.join(result.hidden)}")
        if result.restored:
            print(f"Restored: {', '.join(result.restored)}")
        if result.backup_path:
            print(f"Backup: {result.backup_path}")
        if result.restart_pending:
            print("App-server restart: pending until an idle window")
        if args.auto_restart_if_idle and not args.dry_run:
            restart = apply_pending_restart(
                catalog_path,
                DEFAULT_CODEX_HOME,
                quiet_seconds=args.idle_after_seconds,
            )
            print(f"App-server restart: {restart.status} ({restart.detail})")
        return 0
    except SyncError as exc:
        print(f"codex-model-sync: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("codex-model-sync: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
