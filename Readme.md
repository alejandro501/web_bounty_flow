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
This bootstraps `.env` if needed, sets `BFLOW_CONFIG_KEY` if missing, starts Docker services, and opens the UI.

### Docker (manual)
```bash
docker compose up --build
```
- UI: `http://localhost:5001`
- API: `http://localhost:5050`

### Dev hot reload
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f backend
```

### Local backend (no Docker)
```bash
go run ./cmd/server -config flow.yaml -addr :8080
```

### Useful checks
```bash
go test ./...
rg -n "TODO|FIXME" .
```

## 2. Steps
1. **Input + validation**: load scope files (`wildcards`, `domains`, `organizations`, `out-of-scope`) and verify prerequisites.
2. **Subdomain discovery**: run passive tools (e.g., `subfinder`, `assetfinder`, `amass`, etc.), merge and deduplicate domains.
3. **HTTP probing + API extraction**: identify live web targets (`domains_http`) and API-like live targets (`apidomains_http`).
4. **Recon enrichment**: generate dorks, collect robots/sitemap signals, gather URL intel from sources like `gau`/Wayback/katana.
5. **Fuzzing + checks**: run parameter/injection/workflow/CORS/CSRF/clickjacking/open-redirect and related modules.
6. **Leads + triage**: group findings in Leads, review evidence, replay requests, and move items to `Hits`, `Further Investigation`, or `Archive`.
