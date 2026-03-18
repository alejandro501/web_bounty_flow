# Web Bounty Flow

## 0. What This Is
Web Bounty Flow is a Go backend + static UI that runs a recon and security-testing pipeline from scope seeds to triageable findings.
It automates discovery, enrichment, fuzzing, and lead generation while keeping artifacts in `data/` for manual follow-up.
Use it as an operator console for repeatable bounty workflows, not as a “fire-and-forget” scanner.

## 1. Setup + Useful Commands

### Quick Start
```bash
./startup.sh
```
This bootstraps `.env` if needed, sets `BFLOW_CONFIG_KEY` if missing, prepares local X11 access for Docker when available, starts Docker services, and opens the UI.

### Docker (manual)
```bash
docker compose up --build
```
- UI: `http://localhost:5001`
- API: `http://localhost:5050`

Notes:
- The backend container now also runs the manual Playwright XSS runner.
- If you change backend code, scripts under `scripts/`, or Node/Playwright dependencies, rebuild the backend image.
- `./startup.sh` handles the usual Linux X11 preparation automatically. Use the manual Docker command only if you deliberately do not want the startup helper.

### Dev hot reload
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f backend
```

Notes:
- The dev override mounts the whole repo into `/app`, so backend code and `scripts/` changes are picked up there.
- If `package.json` / `package-lock.json` change, restart or rebuild the backend service so Node dependencies are present inside the container.

### Local backend (no Docker)
```bash
go run ./cmd/server -config flow.yaml -addr :8080
```

Requirements for the manual Playwright XSS runner:
```bash
npm install
npx playwright install chromium
```

Browser mode also needs a working desktop/X display. Headless mode does not.

### Useful checks
```bash
go test ./...
node -e "import('playwright').then(() => console.log('playwright-ok'))"
rg -n "TODO|FIXME" .
```

## 2. Steps
1. **Input + validation**: load scope files (`wildcards`, `domains`, `organizations`, `out-of-scope`) and verify prerequisites.
2. **Subdomain discovery**: run passive tools (e.g., `subfinder`, `assetfinder`, `amass`, etc.), merge and deduplicate domains.
3. **HTTP probing + API extraction**: identify live web targets (`domains_http`) and API-like live targets (`apidomains_http`).
4. **Recon enrichment**: generate dorks, collect robots/sitemap signals, gather URL intel from sources like `gau`/Wayback/katana.
5. **Fuzzing + checks**: run parameter/injection/workflow/CORS/CSRF/clickjacking/open-redirect and related modules.
6. **Leads + triage**: group findings in Leads, review evidence, replay requests, and move items to `Hits`, `Further Investigation`, or `Archive`.
