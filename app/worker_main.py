from __future__ import annotations

import logging

from .config import apply_dashboard_settings, configure_process_proxy, get_settings
from .db import Database
from .oauth import OpenAIOAuthClient
from .recovery import RecoveryCoordinator, RecoveryRuntime
from .security import SecretBox
from .sub2api import Sub2APIClient
from .worker import RecoveryWorker


def main() -> None:
    settings = get_settings()
    base_settings = settings.model_copy(deep=True)
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(message)s")
    db = Database(settings.database_path, SecretBox(settings.encryption_key))
    db.initialize()
    apply_dashboard_settings(settings, db.load_runtime_settings(), base_settings=base_settings)
    settings.validate_runtime(require_sub2api=False)
    configure_process_proxy(settings)
    sub2api = Sub2APIClient(settings)
    oauth = OpenAIOAuthClient(settings)
    coordinator = RecoveryCoordinator(RecoveryRuntime(db, sub2api, oauth, settings))
    worker = RecoveryWorker(coordinator, base_settings=base_settings)
    try:
        worker.run_forever()
    finally:
        sub2api.close()
        oauth.close()


if __name__ == "__main__":
    main()
