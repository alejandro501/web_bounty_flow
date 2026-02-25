#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
PLACEHOLDER="base64-32-byte-key"

generate_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
    return
  fi
  head -c 32 /dev/urandom | base64
}

open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
    return
  fi
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
    return
  fi
  if command -v wslview >/dev/null 2>&1; then
    wslview "$url" >/dev/null 2>&1 || true
    return
  fi
  if command -v cmd.exe >/dev/null 2>&1; then
    cmd.exe /c start "$url" >/dev/null 2>&1 || true
  fi
}

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
  else
    touch "$ENV_FILE"
  fi
fi

current_key="$(grep -E '^BFLOW_CONFIG_KEY=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)"
current_key="${current_key//[$'\r\n\t ']}"

if [[ -z "$current_key" || "$current_key" == "$PLACEHOLDER" ]]; then
  new_key="$(generate_key)"
  if grep -q -E '^BFLOW_CONFIG_KEY=' "$ENV_FILE"; then
    tmp_file="$(mktemp)"
    awk -v key="$new_key" '
      BEGIN { replaced = 0 }
      /^BFLOW_CONFIG_KEY=/ && replaced == 0 {
        print "BFLOW_CONFIG_KEY=" key
        replaced = 1
        next
      }
      { print }
    ' "$ENV_FILE" >"$tmp_file"
    mv "$tmp_file" "$ENV_FILE"
  else
    printf '\nBFLOW_CONFIG_KEY=%s\n' "$new_key" >>"$ENV_FILE"
  fi
  echo "Generated BFLOW_CONFIG_KEY in $ENV_FILE"
else
  echo "BFLOW_CONFIG_KEY already set in $ENV_FILE"
fi

echo "Starting Docker services..."
docker compose up --build -d

UI_URL="http://localhost:5001"
open_browser "$UI_URL"

echo "Startup complete."
echo "UI: $UI_URL"
echo "API: http://localhost:5050/"
