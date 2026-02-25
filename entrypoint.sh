#!/bin/sh
set -euo pipefail

export RESOURCES_DIR=${RESOURCES_DIR:-/app/resources/resources}

ensure_resources() {
  mkdir -p /app/resources
  clone_if_missing() {
    local repo=$1
    local dest=$2
    if [ ! -d "$dest" ]; then
      echo "cloning $repo"
      git clone --depth 1 "$repo" "$dest"
    fi
    chown -R app:app "$dest"
  }
  clone_if_missing https://github.com/alejandro501/resources.git /app/resources/resources
  mkdir -p "${RESOURCES_DIR}/wordlists"
  # SecLists is large and can block API startup for a long time.
  # Keep startup fast by default; clone only when explicitly requested.
  if [ "${ENABLE_SECLISTS_CLONE:-false}" = "true" ]; then
    clone_if_missing https://github.com/danielmiessler/SecLists.git "${RESOURCES_DIR}/wordlists/SecLists"
  else
    mkdir -p "${RESOURCES_DIR}/wordlists/SecLists"
  fi
  mkdir -p /home/app/hack
  ln -sfn /app/resources/resources /home/app/hack/resources
  mkdir -p /home/rojo/hack
  ln -sfn /app/resources/resources /home/rojo/hack/resources
  chown -R app:app /home/app/hack
  chown -R app:app /app/resources
  mkdir -p /app/data || true
  touch /app/data/wildcards /app/data/domains /app/data/apidomains /app/data/ips /app/data/out-of-scope
  chown -R app:app /app/data
}

ensure_resources

if [ "$#" -eq 0 ]; then
  set -- bflow-server --config /app/flow.yaml
fi

exec su-exec app "$@"
