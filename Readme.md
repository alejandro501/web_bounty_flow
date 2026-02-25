# Web Bounty Flow

Go backend + static web UI for running recon flow tasks.

## Run Web Interface (recommended)
1. Create env file:
```bash
cp .env.example .env
# set BFLOW_CONFIG_KEY to a base64-encoded 32-byte key
```
2. Start services:
```bash
docker compose up --build
```
3. Open:
- UI: http://localhost:5001
- API health: http://localhost:5050/

## Local Run (without Docker)
Backend API:
```bash
go run ./cmd/server -config flow.yaml -addr :8080
```
Then serve `ui/` with any static server and set `data-backend-url` in `ui/index.html` if needed.

## Notes
- Old `flow.sh`-based docs are obsolete; this project now runs via Go binaries (`cmd/server`, `cmd/bflow`) and the web UI.
- Main config is `flow.yaml`.
- Persistent data is under `data/`.
