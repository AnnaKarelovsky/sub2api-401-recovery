#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"
./backup.sh
docker compose build --pull
docker compose up -d
docker compose ps
