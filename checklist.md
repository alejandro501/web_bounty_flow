# Web Application Hacker's Handbook - Automation Flow Checklist

Scope: End-to-end automation opportunities aligned to WAHH (2nd ed.), organized in execution order.

Legend:
- `[x]` Implemented in current project flow
- `[ ]` Automatable but not currently implemented (always marked `(Not Implemented)`)

## 0) Preflight and Run Controls
- [x] Validate at least one scope input exists (`organizations`, `wildcards`, `domains`, `apidomains`, `ips`).
- [x] Create required runtime directories before execution.
- [x] Normalize legacy list files (`*.txt` migration/merge).
- [x] Expose tool preflight endpoint (`/api/tools`) to show installed/missing binaries.
- [x] Block run when required tools are missing.
- [x] Per-step retry policy with backoff and max-attempt config.
- [ ] Persist per-step runtime metrics and success/failure counters (Not Implemented).

## 1) Chapter 4 - Mapping the Application (Primary Recon)

### 1.1 Subdomain Enumeration
- [x] Run `amass` for each wildcard.
- [x] Run `sublist3r` in parallel with other passive tools.
- [x] Run `assetfinder` in parallel with other passive tools.
- [x] Run `gau` in parallel with other passive tools.
- [x] Query certificate transparency logs (`crt.sh`) in parallel.
- [x] Run `subfinder` in parallel with other passive tools.
- [x] Consolidate all discovered hosts and remove duplicates.
- [x] Continue with partial results when one tool fails.
- [ ] Add `dnsx` validation stage before consolidation (Not Implemented).
- [ ] Add per-tool raw output files in `data/recon/<tool>/` for auditability (Not Implemented).

### 1.2 Host and Surface Classification
- [x] Derive API-like hosts into `data/apidomains` using naming heuristics.
- [x] Probe live web servers via `httpx` and write `data/domains_http`.
- [x] Write normalized live web metadata CSV (`live-webservers.csv`).
- [ ] Add non-API host segmentation (auth/admin/uploads/static/cdn) (Not Implemented).
- [ ] Add technology-confidence scoring per host (Not Implemented).

### 1.3 Robots/Sitemaps/Content Discovery
- [ ] Run robots.txt discovery automatically in active pipeline (Not Implemented).
- [ ] Parse and dedupe `Disallow` and `Sitemap` endpoints into structured artifacts (Not Implemented).
- [ ] Auto-follow sitemap URLs and extract candidate endpoints (Not Implemented).
- [ ] Integrate `waybackurls` into active pipeline (Not Implemented).
- [ ] Integrate `katana` crawling into active pipeline (Not Implemented).
- [ ] Consolidate URL corpus (`gau` + `wayback` + `katana`) into unified endpoint inventory (Not Implemented).

### 1.4 Public Resource Enrichment
- [x] Optional GitHub dorking automation with token rotation and usage tracking.
- [ ] Auto-generate dork links for org/wildcard/domain/api-domain seeds in active flow (Not Implemented).
- [ ] Integrate Shodan/Censys enrichment into active flow (Not Implemented).

## 2) Chapter 5 - Bypassing Client-Side Controls
- [ ] Auto-capture hidden form parameters and replay tampering permutations (Not Implemented).
- [ ] Automated disabled-field and client-validation bypass checks (Not Implemented).
- [ ] Automated integrity checks for client-supplied business values (price/role/flags) (Not Implemented).
- [ ] Browser extension/thick client artifact extraction pipeline (Not Implemented).

## 3) Chapters 6-8 - Authentication, Session, Access Control

### 3.1 Authentication Automation
- [ ] Username enumeration differential analysis (status/body/timing) (Not Implemented).
- [ ] Password policy quality checks (length/complexity/reuse signals) (Not Implemented).
- [ ] Login brute-force safety test module with throttled profile (Not Implemented).
- [ ] Account recovery flow weakness checks (token reuse/entropy/expiry) (Not Implemented).
- [ ] Remember-me token security checks (Not Implemented).

### 3.2 Session Automation
- [ ] Session token entropy and predictability analyzer (Not Implemented).
- [ ] Cookie security scanner (`Secure`, `HttpOnly`, `SameSite`, scope/path) (Not Implemented).
- [ ] Session fixation automation checks across login transitions (Not Implemented).
- [ ] Logout/session invalidation verification workflow (Not Implemented).

### 3.3 Access Control Automation
- [ ] Role matrix replay engine (same request across multiple accounts/roles) (Not Implemented).
- [ ] IDOR/BOLA differential checker for object identifiers (Not Implemented).
- [ ] HTTP method authorization mismatch checker (`GET/POST/PUT/DELETE`) (Not Implemented).
- [ ] Static resource ACL bypass checks (Not Implemented).

## 4) Chapters 9-10 - Input and Back-End Injection Testing

### 4.1 Generic Fuzzing
- [x] Documentation endpoint fuzzing via `ffuf`.
- [x] Directory/API path fuzzing via `ffuf` with merged wordlists.
- [x] CeWL custom wordlist generation for project-specific fuzzing enrichment.
- [ ] Request parameter fuzzing beyond path fuzz (`query`, `body`, `headers`, `cookies`) (Not Implemented).
- [ ] Response-diff engine for anomaly clustering (status/length/keywords/timing) (Not Implemented).

### 4.2 Specific Injection Families
- [ ] SQLi payload packs and detection heuristics (error/boolean/time-based) (Not Implemented).
- [ ] NoSQL injection checks (Not Implemented).
- [ ] XPath/LDAP injection checks (Not Implemented).
- [ ] OS command injection checks (Not Implemented).
- [ ] Path traversal checks (Not Implemented).
- [ ] File inclusion checks (LFI/RFI) (Not Implemented).
- [ ] XXE checks (Not Implemented).
- [ ] SOAP/XML injection checks (Not Implemented).
- [ ] SSRF/back-end request injection checks (Not Implemented).
- [ ] SMTP/header injection checks (Not Implemented).

## 5) Chapter 11 - Application Logic Automation
- [ ] Multi-step workflow state-machine runner (Not Implemented).
- [ ] Sequence enforcement and step-skipping checks (Not Implemented).
- [ ] Incomplete-input and boundary-condition logic checks (Not Implemented).
- [ ] Business limit abuse automation (quantity/discount/rate/credit) (Not Implemented).
- [ ] Race-condition harness for concurrent state transitions (Not Implemented).

## 6) Chapters 12-13 - Attacking Users (Client-Side)

### 6.1 XSS Automation
- [ ] Reflected XSS context discovery and payload adaptation (Not Implemented).
- [ ] Stored XSS sink crawler and replay checks (Not Implemented).
- [ ] DOM XSS source-sink static + dynamic checks (Not Implemented).

### 6.2 Other Client-Side Attack Automation
- [ ] CSRF token presence/validation checks (Not Implemented).
- [ ] Clickjacking header/frame policy checks (Not Implemented).
- [ ] CORS/SOP misconfiguration scanner (Not Implemented).
- [ ] Open redirect automated validation and chaining potential (Not Implemented).
- [ ] Client-side privacy exposure checks (cache/autocomplete/storage artifacts) (Not Implemented).

## 7) Chapter 14 - Automating Customized Attacks
- [x] Parallelized discovery architecture per wildcard seed.
- [x] Reusable command wrappers and captured outputs.
- [x] Run status and step status exposed via API/UI.
- [ ] Session-aware macro engine for stateful replay (Not Implemented).
- [ ] CAPTCHA-aware workflow branching (Not Implemented).
- [ ] Template-driven custom attack runner (Not Implemented).

## 8) Chapter 15 - Information Disclosure Automation
- [x] Collect live host metadata (title/server/tech/content-length).
- [x] Persist fuzzing hits and live host artifacts for analyst review.
- [ ] Automatic error-page/stack-trace harvester from discovered endpoints (Not Implemented).
- [ ] Secret pattern scanner on responses/artifacts (keys/tokens/credentials) (Not Implemented).
- [ ] Differential response leakage scoring (debug/internal identifiers) (Not Implemented).

## 9) Chapters 16-18 - Native, Architecture, Server-Side Platform

### 9.1 Server/Infrastructure Checks
- [x] Utilities exist for request smuggling/h2c/hop-by-hop/toxicache/SSI-ESI/cloudflare checks.
- [ ] Integrate `utils/*` checks into active orchestrated flow (Not Implemented).
- [ ] Normalize utility outputs into machine-readable findings JSON (Not Implemented).
- [ ] Add dangerous HTTP method scanner (`OPTIONS/TRACE/PUT/DELETE`) (Not Implemented).
- [ ] Add default-content/default-credential probes for known server panels (Not Implemented).

### 9.2 Nmap/Service Correlation
- [ ] Reintroduce automated Nmap scans in active flow (Not Implemented).
- [ ] Parse `.gnmap` outputs into service summaries and pointers (Not Implemented).
- [ ] Run `searchsploit` enrichment automatically on discovered services (Not Implemented).

### 9.3 Architecture/Segmentation
- [ ] Tier-segmentation verification checks (edge/app/data trust boundaries) (Not Implemented).
- [ ] Shared-hosting and virtual-host isolation checks (Not Implemented).

## 10) Chapter 19 - Source Code Review Automation
- [ ] Integrate `semgrep` rules by WAHH category (Not Implemented).
- [ ] Integrate language-specific SAST (`gosec`, etc.) (Not Implemented).
- [ ] Correlate static findings with live endpoints/parameters (Not Implemented).

## 11) Chapter 20 - Toolkit and Workflow Orchestration
- [x] Dockerized toolchain and backend API orchestration.
- [x] UI views for scope, run status, logs, and artifacts.
- [ ] Add run manifest (tool versions + params + hashes) (Not Implemented).
- [ ] Add resumable runs/checkpoints for long workflows (Not Implemented).
- [ ] Add export bundle (JSON + Markdown + CSV) per run (Not Implemented).

## 12) Chapter 21 - Integrated Methodology Runner
- [x] Early methodology stages automated (mapping + host discovery + probing + fuzzing bootstrap).
- [ ] Build chapter-aligned stage gates with required evidence per gate (Not Implemented).
- [ ] Completion scorecard by chapter and subchapter (Not Implemented).
- [ ] Auto-generate analyst action queue from failed/missing automation stages (Not Implemented).

## Current Active Flow (Segmented Summary)

### Segment A - Discovery
- [x] Run `amass` for wildcard seeds.
- [x] Run `sublist3r` for wildcard seeds.
- [x] Run `assetfinder` for wildcard seeds.
- [x] Run `gau` for wildcard seeds.
- [x] Query `crt.sh` for wildcard seeds.
- [x] Run `subfinder` for wildcard seeds.
- [x] Consolidate and dedupe discovered domains.

### Segment B - Classification + Live Host Detection
- [x] Build API-domain subset from discovered domains.
- [x] Probe live hosts and write `domains_http`.
- [x] Save `live-webservers.csv` artifact.

### Segment C - Fuzzing Bootstrap
- [x] Generate CeWL project-specific wordlist.
- [x] Run docs endpoint fuzzing (`ffuf`).
- [x] Run directory/API path fuzzing (`ffuf`).

### Segment D - Enrichment
- [x] Optional GitHub dork run.
- [ ] Robots/sitemaps automated in main run (Not Implemented).
- [ ] Wayback/Katana URL discovery in main run (Not Implemented).
- [ ] Nmap/service enrichment in main run (Not Implemented).
- [ ] `utils/` server attack checks in main run (Not Implemented).
