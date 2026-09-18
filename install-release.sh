#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

repository="AnnaKarelovsky/sub2api-401-recovery"
release_version="${RECOVERY_VERSION:-v0.1.1}"
image="${RECOVERY_IMAGE:-ghcr.io/annakarelovsky/sub2api-401-recovery:${release_version}}"
raw_base="https://raw.githubusercontent.com/${repository}/${release_version}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

require_command curl
require_command docker
require_command openssl

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required." >&2
  exit 1
fi

download_if_missing() {
  local file="$1"
  if [ ! -f "$file" ]; then
    curl -fsSL "${raw_base}/${file}" -o "$file"
  fi
}

download_if_missing .env.example
download_if_missing docker-compose.release.yml

mkdir -p data backups
if [ ! -f .env ]; then
  cp .env.example .env
fi

generate_secret() {
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

set_generated_value() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=$" .env; then
    sed -i "s|^${key}=.*$|${key}=${value}|" .env
  elif ! grep -q "^${key}=" .env; then
    printf '\n%s=%s\n' "$key" "$value" >> .env
  fi
}

set_generated_value ENCRYPTION_KEY "$(generate_secret)"
set_generated_value DASHBOARD_SECRET "$(generate_secret)"

chmod 700 data backups
chmod 600 .env

compose=(docker compose -f docker-compose.release.yml)
export RECOVERY_IMAGE="$image"
"${compose[@]}" pull

env_value() {
  sed -n "s/^$1=//p" .env | tail -n 1
}

missing_config=0
if [ -z "$(env_value SUB2API_BASE_URL)" ]; then
  missing_config=1
fi
if [ -z "$(env_value SUB2API_ADMIN_KEY)" ] && [ -z "$(env_value SUB2API_JWT)" ]; then
  missing_config=1
fi
if [ -z "$(env_value DASHBOARD_PASSWORD)" ] || [ "$(env_value DASHBOARD_PASSWORD)" = "change-this-password" ]; then
  missing_config=1
fi

if [ "$missing_config" -eq 1 ]; then
  echo "Image pulled and .env initialized. Fill in SUB2API_BASE_URL, SUB2API_ADMIN_KEY or SUB2API_JWT, and DASHBOARD_PASSWORD, then run this script again."
  exit 0
fi

"${compose[@]}" up -d
"${compose[@]}" ps
echo "Dashboard: http://127.0.0.1:${APP_PORT:-1455}/"
