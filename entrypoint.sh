#!/bin/sh
set -euo pipefail

GOPATH=/go
GOBIN=/usr/local/bin
export GOPATH GOBIN PATH="$GOBIN:/usr/local/go/bin:$PATH"

GO_TOOLS=$(cat <<'EOF'
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

if [ "$#" -eq 0 ]; then
  set -- bflow-server --config /app/flow.yaml
fi

exec su-exec app "$@"
