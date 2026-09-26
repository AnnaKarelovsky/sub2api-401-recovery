from __future__ import annotations

import os
import threading
import time
from datetime import datetime, date, time as clock_time
from zoneinfo import ZoneInfo

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
        self.last_material_sync_date = self._load_last_material_sync_date()
        self.material_sync_retry_at = 0.0

    def run_forever(self) -> None:
        recovered = self.coordinator.db.requeue_stale_tasks(
            stale_after_seconds=self.settings.worker_stale_seconds
        )
        recovered_enrollments = self.coordinator.db.requeue_stale_account_enrollments(
            stale_after_seconds=self.settings.worker_stale_seconds
        )
        if recovered:
            self.coordinator.db.record_event(
                "stale_tasks_requeued",
                "Recovery tasks abandoned by a previous worker were requeued",
                {"count": recovered},
            )
        if recovered_enrollments:
            self.coordinator.db.record_event(
                "stale_enrollments_requeued",
                "Account enrollment requests abandoned by a previous worker were requeued",
                {"count": recovered_enrollments},
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
            if self._material_sync_due(now):
                try:
                    result = self.coordinator.sync_materials()
                    if result.get("skipped"):
                        self.material_sync_retry_at = now + 30
                    else:
                        self.last_material_sync_date = self._local_now().date()
                        self.material_sync_retry_at = 0.0
                except Exception as exc:
                    self.coordinator.db.record_event(
                        "worker_materials_sync_error",
                        "Worker material sync failed",
                        {"reason": safe_error(exc)},
                    )
                    self.last_material_sync_date = self._local_now().date()
                    self.material_sync_retry_at = 0.0
            try:
                processed = self.coordinator.process_one_account_enrollment()
            except Exception as exc:
                processed = False
                self.coordinator.db.record_event(
                    "worker_enrollment_error",
                    "Account enrollment worker failed",
                    {"reason": safe_error(exc)},
                )
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

    def _local_now(self) -> datetime:
        return datetime.now(ZoneInfo(self.settings.material_sync_timezone))

    def _load_last_material_sync_date(self) -> date | None:
        event_at = self.coordinator.db.latest_event_at(
            ("materials_sync_completed", "materials_sync_failed")
        )
        if not event_at:
            return None
        try:
            parsed = datetime.fromisoformat(event_at)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=ZoneInfo("UTC"))
            return parsed.astimezone(ZoneInfo(self.settings.material_sync_timezone)).date()
        except (TypeError, ValueError):
            return None

    def _material_sync_due(self, monotonic_now: float | None = None) -> bool:
        if not self.settings.material_sync_enabled:
            return False
        now = self._local_now()
        monotonic_now = time.monotonic() if monotonic_now is None else monotonic_now
        if monotonic_now < self.material_sync_retry_at:
            return False
        if self.last_material_sync_date is None:
            return True
        if self.last_material_sync_date == now.date():
            return False
        scheduled = datetime.combine(
            now.date(), clock_time(hour=self.settings.material_sync_hour), tzinfo=now.tzinfo
        )
        return now >= scheduled

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
