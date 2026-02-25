# Web Bounty Flow

Go backend + static web UI for running recon flow tasks.

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
