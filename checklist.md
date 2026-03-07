# Web Application Hacker's Handbook - Automation Flow Checklist

Scope: End-to-end automation opportunities aligned to WAHH (2nd ed.), organized in execution order.

Legend:
- `[ ]` Default checklist state (unchecked until explicitly marked done)
- `(Not Implemented)` marks items that are currently missing from the project flow

## 0) Preflight and Run Controls
- [ ] Validate at least one scope input exists (`organizations`, `wildcards`, `domains`, `apidomains`, `ips`).
- [ ] Create required runtime directories before execution.
- [ ] Normalize legacy list files (`*.txt` migration/merge).
- [ ] Expose tool preflight endpoint (`/api/tools`) to show installed/missing binaries.
- [ ] Block run when required tools are missing.
- [ ] Per-step retry policy with backoff and max-attempt config.
- [ ] Persist per-step runtime metrics and success/failure counters (Not Implemented).

## 1) Chapter 4 - Mapping the Application (Primary Recon)

### 1.1 Subdomain Enumeration
- [ ] Run `amass` for each wildcard.
- [ ] Run `sublist3r` in parallel with other passive tools.
- [ ] Run `assetfinder` in parallel with other passive tools.
- [ ] Run `gau` in parallel with other passive tools.
- [ ] Query certificate transparency logs (`crt.sh`) in parallel.
- [ ] Run `subfinder` in parallel with other passive tools.
- [ ] Consolidate all discovered hosts and remove duplicates.
- [ ] Continue with partial results when one tool fails.
- [ ] Add `dnsx` validation stage before consolidation.
- [ ] Add per-tool raw output files in `data/recon/raw/<tool>/` for auditability.

### 1.2 Host and Surface Classification
- [ ] Derive API-like hosts into `data/apidomains` using naming heuristics.
- [ ] Probe live web servers via `httpx` and write live protocol URLs to `data/domains_http` (preserve discovered hosts in `data/domains`).
- [ ] Write normalized live web metadata CSV (`live-webservers.csv`).
- [ ] Add non-API host segmentation (auth/admin/uploads/static/cdn) (Not Implemented).
- [ ] Add technology-confidence scoring per host (Not Implemented).

### 1.3 Robots/Sitemaps/Content Discovery
- [ ] Run robots.txt discovery automatically in active pipeline.
- [ ] Parse and dedupe `Disallow` and `Sitemap` endpoints into structured artifacts (Not Implemented).
- [ ] Auto-follow sitemap URLs and extract candidate endpoints.
- [ ] Integrate `waybackurls` into active pipeline.
- [ ] Integrate `katana` crawling into active pipeline.
- [ ] Consolidate URL corpus (`gau` + `wayback` + `katana`) into unified endpoint inventory.

### 1.4 Public Resource Enrichment
- [ ] Optional GitHub dorking automation with token rotation and usage tracking.
- [ ] Auto-generate dork links for org/wildcard/domain/api-domain seeds in active flow.
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
- [ ] Documentation endpoint fuzzing via `ffuf`.
- [ ] Directory/API path fuzzing via `ffuf` with merged wordlists.
- [ ] CeWL custom wordlist generation for project-specific fuzzing enrichment.
- [ ] Request parameter fuzzing beyond path fuzz (`query`, `body`, `headers`, `cookies`).
- [ ] Response-diff engine for anomaly clustering (status/length/keywords/timing) (Not Implemented).

### 4.2 Specific Injection Families
- [ ] SQLi payload packs and detection heuristics (error/boolean-based).
- [ ] NoSQL injection checks.
- [ ] XPath/LDAP injection checks.
- [ ] OS command injection checks.
- [ ] Path traversal checks.
- [ ] File inclusion checks (LFI/RFI).
- [ ] XXE checks.
- [ ] SOAP/XML injection checks.
- [ ] SSRF/back-end request injection checks.
- [ ] SMTP/header injection checks.

## 5) Chapter 11 - Application Logic Automation
- [ ] Multi-step workflow state-machine runner (semi-automated signals + manual validation).
- [ ] Sequence enforcement and step-skipping checks (Not Implemented).
- [ ] Incomplete-input and boundary-condition logic checks (Not Implemented).
- [ ] Business limit abuse automation (quantity/discount/rate/credit) (Not Implemented).
- [ ] Race-condition checks tracked as manual testing item (Manual-first; helper automation only).

## 6) Chapters 12-13 - Attacking Users (Client-Side)

### 6.1 XSS Automation
- [ ] Reflected XSS context discovery and payload adaptation (manual Playwright runner + manual validation).
- [ ] Stored XSS sink crawler and replay checks (manual Playwright runner + manual validation).
- [ ] DOM XSS source-sink static + dynamic checks (manual Playwright runner + manual validation).

### 6.2 Other Client-Side Attack Automation
- [ ] CSRF token presence/validation checks (baseline/cross-origin replay + manual validation).
- [ ] Clickjacking header/frame policy checks.
- [ ] CORS/SOP misconfiguration scanner.
- [ ] Open redirect automated validation and chaining potential.
- [ ] Client-side privacy exposure checks (cache/autocomplete/storage artifacts) (Not Implemented).

## 7) Chapter 14 - Automating Customized Attacks
- [ ] Parallelized discovery architecture per wildcard seed.
- [ ] Reusable command wrappers and captured outputs.
- [ ] Run status and step status exposed via API/UI.
- [ ] Session-aware macro engine for stateful replay (Not Implemented).
- [ ] CAPTCHA-aware workflow branching (Not Implemented).
- [ ] Template-driven custom attack runner (Not Implemented).

## 8) Chapter 15 - Information Disclosure Automation
- [ ] Collect live host metadata (title/server/tech/content-length).
- [ ] Persist fuzzing hits and live host artifacts for analyst review.
- [ ] Automatic error-page/stack-trace harvester from discovered endpoints (Not Implemented).
- [ ] Secret pattern scanner on responses/artifacts (keys/tokens/credentials) (Not Implemented).
- [ ] Differential response leakage scoring (debug/internal identifiers) (Not Implemented).

## 9) Chapters 16-18 - Native, Architecture, Server-Side Platform

### 9.1 Server/Infrastructure Checks
- [ ] Utilities exist for request smuggling/h2c/hop-by-hop/toxicache/SSI-ESI/cloudflare checks.
- [ ] Integrate `utils/*` checks into active orchestrated flow (Semi-automated: machine detection + manual exploit validation).
- [ ] Normalize utility outputs into machine-readable findings JSON (Not Implemented).
- [ ] Add dangerous HTTP method scanner (`OPTIONS/TRACE/PUT/DELETE`) (Not Implemented).
- [ ] Add default-content/default-credential probes for known server panels (Not Implemented).

### 9.2 Nmap/Service Correlation
- [ ] Reintroduce automated Nmap scans in active flow.
- [ ] Parse `.gnmap` outputs into service summaries and pointers.
- [ ] Run `searchsploit` enrichment automatically on discovered services.

### 9.3 Architecture/Segmentation
- [ ] Tier-segmentation verification checks (edge/app/data trust boundaries) (semi-automated + manual validation).
- [ ] Shared-hosting and virtual-host isolation checks (semi-automated + manual validation).

## 10) Chapter 19 - Source Code Review Automation
- [ ] Integrate `semgrep` rules by WAHH category.
- [ ] Integrate language-specific SAST (`gosec`, etc.).
- [ ] Correlate static findings with live endpoints/parameters.

## 11) Chapter 20 - Toolkit and Workflow Orchestration
- [ ] Dockerized toolchain and backend API orchestration.
- [ ] UI views for scope, run status, logs, and artifacts.
- [ ] Add run manifest (tool versions + params + hashes).
- [ ] Add resumable runs/checkpoints for long workflows (step-state snapshots).
- [ ] Add export bundle (JSON + Markdown + CSV) per run.

## 12) Chapter 21 - Integrated Methodology Runner
- [ ] Early methodology stages automated (mapping + host discovery + probing + fuzzing bootstrap).
- [ ] Build chapter-aligned stage gates with required evidence per gate.
- [ ] Completion scorecard by chapter and subchapter.
- [ ] Auto-generate analyst action queue from failed/missing automation stages (Not Implemented).

## Current Active Flow (Segmented Summary)

### Segment A - Discovery
- [ ] Run `amass` for wildcard seeds.
- [ ] Run `sublist3r` for wildcard seeds.
- [ ] Run `assetfinder` for wildcard seeds.
- [ ] Run `gau` for wildcard seeds.
- [ ] Query `crt.sh` for wildcard seeds.
- [ ] Run `subfinder` for wildcard seeds.
- [ ] Consolidate and dedupe discovered domains.

### Segment B - Classification + Live Host Detection
- [ ] Build API-domain subset from discovered domains.
- [ ] Probe live hosts and write live protocol URLs to `domains_http`.
- [ ] Save `live-webservers.csv` artifact.

### Segment C - Fuzzing Bootstrap
- [ ] Generate CeWL project-specific wordlist.
- [ ] Run docs endpoint fuzzing (`ffuf`).
- [ ] Run directory/API path fuzzing (`ffuf`).

### Segment D - Enrichment
- [ ] Optional GitHub dork run.
- [ ] Robots/sitemaps automated in main run.
- [ ] Wayback/Katana URL discovery in main run.
- [ ] Nmap/service enrichment in main run.
- [ ] `utils/` server attack checks in main run.
