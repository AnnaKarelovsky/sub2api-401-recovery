from __future__ import annotations

import argparse
from datetime import datetime, timezone

from .config import get_settings
from .db import Database
from .security import SecretBox


def main() -> None:
    parser = argparse.ArgumentParser(description="Sub2API 401 Recovery maintenance CLI")
    parser.add_argument("command", choices=("backup", "status"))
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    settings = get_settings()
    settings.validate_runtime(require_sub2api=False)
    db = Database(settings.database_path, SecretBox(settings.encryption_key))
    db.initialize()
    if args.command == "backup":
        output = args.output or f"{settings.backup_dir}/recovery-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.db"
        print(db.backup(output))
    else:
        print(db.dashboard_summary())


if __name__ == "__main__":
    main()
