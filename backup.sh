#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"
mkdir -p backups
docker compose run --rm recovery-api python -m app.cli backup
