from __future__ import annotations

import os
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _project_version() -> str | None:
    project_file = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        with project_file.open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    except (FileNotFoundError, KeyError, OSError, tomllib.TOMLDecodeError):
        return None
    return value if isinstance(value, str) else None


try:
    _installed_version = version("sub2api-401-recovery")
except PackageNotFoundError:
    _installed_version = None

APP_VERSION = (os.environ.get("APP_VERSION") or _project_version() or _installed_version or "0.4.19").removeprefix("v")
