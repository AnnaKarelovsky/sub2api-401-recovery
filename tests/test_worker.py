from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from app.worker import RecoveryWorker


class WorkerCoordinatorStub:
    def __init__(self, database, settings):
        self.db = database
        self.settings = settings


def test_worker_material_sync_is_once_per_local_day(database, settings):
    database.record_event("materials_sync_completed", "Account material sync completed")

    worker = RecoveryWorker(WorkerCoordinatorStub(database, settings))

    assert worker.last_material_sync_date == datetime.now(ZoneInfo("Asia/Shanghai")).date()
    assert worker._material_sync_due(monotonic_now=0) is False
