# Web Bounty Flow

Go backend + static web UI for running recon flow tasks.

## Steps
1. Input and config setup
- load config and input lists (`organizations`, `wildcards`, `domains`, `out-of-scope`, etc.)
- verify required recon files are loaded in `data/` (`organizations`, `wildcards`, `domains`, `out-of-scope`)

2. Subdomain discovery (combined tools)
- generate org-level dork links (API-focused)
- run `subfinder`, `assetfinder`, and `amass` on wildcard entries and append to `data/domains`
- filter out-of-scope domains from discovered results
- resolve/live-check domains with `dnsx` + `httpx` (`httprobe` fallback) and build `data/domains_http`
- select API-focused targets into `data/apidomains`

3. Passive recon enrichment
- generate dork links for `wildcards`, `domains`, and `apidomains`
- bucket dork outputs into `dorking/github`, `dorking/google`, `dorking/shodan`, `dorking/wayback`
- optional GitHub dork automation (token-based API search + hits)
- fetch `robots.txt` and extract disallowed paths/sitemaps for wildcard/domain/api targets
- run `sort_http` on domains to keep live HTTP targets organized

4. URL discovery (combined tools)
- run `waybackurls`, `gau`, and `katana` against live targets
- save outputs under `data/recon/`:
- `urls_waybackurls.txt`, `urls_gau.txt`, `urls_katana.txt`
- consolidated `urls_all.txt` and API-like subset `urls_api_like.txt`

## Quick Start (recommended)
```bash
./startup.sh
```

`startup.sh` will:
- create `.env` from `.env.example` if missing
- set `BFLOW_CONFIG_KEY` if missing (base64 string for 32-byte key)
- run `docker compose up --build -d`
- open `http://localhost:5001`

## Docker (manual)
```bash
docker compose up --build
```

Open:
- UI: http://localhost:5001
- API health: http://localhost:5050/

## Docker Dev Hot Reload
Use this when editing backend Go code frequently.

Start with hot reload:
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Watch backend logs (you will see rebuild/restart on `.go` and `flow.yaml` changes):
```bash
docker compose logs -f backend
```

Notes:
- Frontend is already live-mounted (`./ui`), so UI edits are instant.
- In hot-reload mode, backend source is bind-mounted and rebuilt by `air` inside the container.
- Full rebuild is only needed when Dockerfile-level dependencies change.

## Local Run (no Docker)
```bash
go run ./cmd/server -config flow.yaml -addr :8080
```
Then serve `ui/` with any static server and set `data-backend-url` in `ui/index.html` if needed.

## Notes
- `BFLOW_CONFIG_KEY` encrypts/decrypts provider tokens in the config store.
- Generate one manually if needed:
```bash
openssl rand -base64 32
```
- Main config is `flow.yaml`.
- Persistent data is under `data/`.
