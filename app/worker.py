from __future__ import annotations

import os
import threading
import time

from .config import Settings, apply_dashboard_settings, configure_process_proxy
from .oauth import OpenAIOAuthClient
from .recovery import RecoveryCoordinator
from .redaction import safe_error
from .sub2api import Sub2APIClient


class RecoveryWorker:
    def __init__(self, coordinator: RecoveryCoordinator, *, base_settings: Settings | None = None):
        self.coordinator = coordinator
        self.settings = coordinator.settings
        self.base_settings = base_settings or self.settings.model_copy(deep=True)
        self.settings_revision = coordinator.db.runtime_settings_revision()
        self.worker_id = f"worker-{os.getpid()}"
        self.stop_event = threading.Event()
        self.last_scan = 0.0

    def run_forever(self) -> None:
        recovered = self.coordinator.db.requeue_stale_tasks(
            stale_after_seconds=self.settings.worker_stale_seconds
        )
        if recovered:
            self.coordinator.db.record_event(
                "stale_tasks_requeued",
                "Recovery tasks abandoned by a previous worker were requeued",
                {"count": recovered},
            )
        while not self.stop_event.is_set():
            self._reload_settings_if_changed()
            now = time.monotonic()
            if now - self.last_scan >= self.settings.scan_interval_seconds:
                try:
                    self.coordinator.scan()
                except Exception as exc:
                    self.coordinator.db.record_event(
                        "worker_scan_error", "Worker scan failed", {"reason": safe_error(exc)}
                    )
                self.last_scan = now
            processed = False
            for _ in range(10):
                try:
                    if not self.coordinator.process_one(self.worker_id):
                        break
                    processed = True
                except Exception as exc:
                    self.coordinator.db.record_event(
                        "worker_task_error", "Worker task loop failed", {"reason": safe_error(exc)}
                    )
                    break
            if not processed:
                self.stop_event.wait(self.settings.worker_poll_seconds)

    def _reload_settings_if_changed(self) -> None:
        revision = self.coordinator.db.runtime_settings_revision()
        if revision == self.settings_revision:
            return
        overrides = self.coordinator.db.load_runtime_settings()
        apply_dashboard_settings(self.settings, overrides, base_settings=self.base_settings)
        self.settings.validate_runtime(require_sub2api=False)
        configure_process_proxy(self.settings)
        old_sub2api = self.coordinator.sub2api
        old_oauth = self.coordinator.oauth
        sub2api = Sub2APIClient(self.settings)
        oauth = OpenAIOAuthClient(self.settings)
        self.coordinator.reconfigure(sub2api, oauth)
        old_sub2api.close()
        old_oauth.close()
        self.settings_revision = revision

    def stop(self) -> None:
        self.stop_event.set()
