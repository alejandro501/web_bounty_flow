# Flow Order (from _backup/flow.sh)

- Load `flow.conf` and parse `--organization` / `--org-list` inputs.
- Passive recon: `generate_dork_links` for organizations (API-focused queries).
- Passive recon: `subfinder` on wildcards -> append to `domains`.
- Passive recon: filter out-of-scope entries from `domains`.
- Passive recon: `httprobe` API domains (grep `api` -> `apidomains`).
- Passive recon: `generate_dork_links` for wildcards, domains, apidomains; move outputs into `dorking/` buckets.
- Passive recon: `robots` fetch + sitemap extraction for wildcards/domains/apidomains.
- Passive recon: `sort_http` on `domains`.
- Documentation fuzzing: `ffuf` against orgs/wildcards/apidomains.
- Directory fuzzing: `ffuf` against apidomains/wildcards.
- Nmap scans: domains, apidomains, then IPs.
- Process `.gnmap` summaries and run `searchsploit` mapping.
- Security checks: `toxicache`, hop-by-hop, request smuggling, h2csmuggler, ssi/esi, cloudflare checks.
