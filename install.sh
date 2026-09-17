#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required." >&2
  exit 1
fi

mkdir -p data backups
if [ ! -f .env ]; then
  cp .env.example .env
fi

python3 - <<'PY'
from pathlib import Path
import base64
import secrets

env_path = Path('.env')
text = env_path.read_text()
for key in ('ENCRYPTION_KEY', 'DASHBOARD_SECRET'):
    marker = key + '='
    current = next((line for line in text.splitlines() if line.startswith(marker)), '')
    if current == marker:
        value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        text = text.replace(marker, marker + value, 1)
env_path.write_text(text + ('\n' if not text.endswith('\n') else ''))
PY

chmod 700 data backups
chmod 600 .env

echo "Review .env and set SUB2API_BASE_URL, SUB2API_ADMIN_KEY, and DASHBOARD_PASSWORD."
docker compose build

if grep -Eq '^SUB2API_ADMIN_KEY=.+$|^SUB2API_JWT=.+$' .env \
  && grep -Eq '^SUB2API_BASE_URL=.+$' .env \
  && ! grep -Eq '^DASHBOARD_PASSWORD=(|change-this-password)$' .env; then
  docker compose up -d
  docker compose ps
else
  echo "Image built. Fill in .env, then run: docker compose up -d"
fi
