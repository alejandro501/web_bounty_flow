#!/bin/sh
set -euo pipefail

GOPATH=/go
GOBIN=/usr/local/bin
export GOPATH GOBIN PATH="$GOBIN:/usr/local/go/bin:$PATH"
export RESOURCES_DIR=${RESOURCES_DIR:-/app/resources/resources}

GO_TOOLS=$(cat <<'EOF'
github.com/alejandro501/generate_dork_links@latest
github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
github.com/tomnomnom/httprobe@latest
github.com/ffuf/ffuf@latest
github.com/assetnote/h2csmuggler/cmd/h2csmuggler@latest
github.com/tomnomnom/anew@latest
github.com/tomnomnom/waybackurls@latest
EOF
)

install_go_tools() {
  for pkg in $GO_TOOLS; do
    bin=$(basename "${pkg%%@*}")
    if command -v "$bin" >/dev/null 2>&1; then
      continue
    fi
    echo "installing $pkg"
    go install "$pkg"
  done
}

install_searchsploit() {
  EXPLOITDB_DIR=/opt/exploitdb
  if [ -x "$EXPLOITDB_DIR/searchsploit" ]; then
    return
  fi

  echo "downloading exploitdb"
  rm -rf "$EXPLOITDB_DIR"
  git clone --depth 1 https://github.com/offensive-security/exploitdb.git "$EXPLOITDB_DIR"
  ln -sf "$EXPLOITDB_DIR/searchsploit" /usr/local/bin/searchsploit
}

install_go_tools
install_searchsploit

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
  clone_if_missing https://github.com/danielmiessler/SecLists.git "${RESOURCES_DIR}/wordlists/SecLists"
  mkdir -p /home/app/hack
  ln -sfn /app/resources/resources /home/app/hack/resources
  mkdir -p /home/rojo/hack
  ln -sfn /app/resources/resources /home/rojo/hack/resources
  chown -R app:app /home/app/hack
  chown -R app:app /app/resources
}

ensure_resources

if [ "$#" -eq 0 ]; then
  set -- bflow-server --config /app/flow.yaml
fi

exec su-exec app "$@"
