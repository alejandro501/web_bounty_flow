export const FLOW_SEGMENTS = [
  {
    title: "0) Preflight and Runtime",
    items: [
      { label: "Load flow.yaml and initialize recon runtime.", stepId: "load-config", implemented: true },
      { label: "Validate scope readiness.", stepId: "validate-inputs", implemented: true },
    ],
  },
  {
    title: "1) Mapping - Subdomain Enumeration (Chapter 4)",
    items: [
      { label: "Subdomain enumeration (uses enabled tools from Flow configuration).", stepId: "subdomain-enumeration", implemented: true },
      { label: "Persist per-tool raw outputs in dedicated folders.", stepId: "persist-raw-outputs", implemented: true },
      { label: "Validate discovered hosts with dnsx before consolidation.", stepId: "dnsx-validate", implemented: true },
      { label: "Consolidate all discovered hosts and remove duplicates.", stepId: "consolidate", implemented: true },
    ],
  },
  {
    title: "2) Mapping - URL and Content Discovery (Chapter 4)",
    items: [
      { label: "Probe consolidated hosts with httpx for live web servers.", stepId: "httpx", implemented: true },
      { label: "Run robots.txt and sitemap discovery in main flow.", stepId: "robots-sitemaps", implemented: true },
      { label: "Integrate waybackurls into active flow.", stepId: "waybackurls", implemented: true },
      { label: "Integrate katana crawling into active flow.", stepId: "katana", implemented: true },
      { label: "Consolidate URL corpus from all sources.", stepId: "url-corpus", implemented: true },
      { label: "Auto-generate dork links for org/wildcard/domain/api-domain seeds.", stepId: "dork-links", implemented: true },
    ],
  },
  {
    title: "3) Input and Injection Fuzzing (Chapters 9-10)",
    items: [
      { label: "Generate custom CeWL wordlist from live web servers.", stepId: "cewl", implemented: true },
      { label: "Run ffuf documentation endpoint fuzzing.", stepId: "fuzz-docs", implemented: true },
      { label: "Run ffuf directory/API path fuzzing.", stepId: "fuzz-dirs", implemented: true },
      { label: "Fuzz query/body/header/cookie parameters.", stepId: "param-fuzz", implemented: true },
      { label: "Automate SQLi/NoSQL/XPath/LDAP checks.", stepId: "injection-checks", implemented: true },
      { label: "Automate OS command/path traversal/file inclusion checks.", stepId: "server-input-checks", implemented: true },
      { label: "Automate XXE/SOAP/SSRF/SMTP injection checks.", stepId: "adv-injection-checks", implemented: true },
    ],
  },
  {
    title: "4) Client-Side Attack Classes (Chapters 12-13)",
    items: [
      { label: "Reflected/stored/DOM XSS tracked in manual testing.", implemented: true },
      { label: "Automate CSRF token validation checks.", stepId: "csrf-checks", implemented: true },
      { label: "Automate clickjacking and frame policy checks.", stepId: "clickjacking-checks", implemented: true },
      { label: "Automate CORS/SOP misconfiguration scanning.", stepId: "cors-checks", implemented: true },
      { label: "Automate open redirect validation and chaining checks.", stepId: "open-redirect-checks", implemented: true },
    ],
  },
  {
    title: "5) Logic, Architecture, and Server Platform (Chapters 11, 16-18)",
    items: [
      { label: "Semi-automate multi-step workflow logic checks.", stepId: "workflow-logic-checks", implemented: true },
      { label: "Semi-automate request smuggling/h2c/hop-by-hop/SSI-ESI checks in main flow.", stepId: "smuggling-stack-checks", implemented: true },
      { label: "Reintroduce automated Nmap scan + service enrichment + searchsploit.", stepId: "nmap-enrichment-checks", implemented: true },
      { label: "Run nuclei template scans against live web targets.", stepId: "nuclei-scan", implemented: true },
      { label: "Semi-automate tier-segmentation and shared-hosting isolation checks.", stepId: "tier-isolation-checks", implemented: true },
    ],
  },
  {
    title: "6) Source Review and Methodology Orchestration (Chapters 19-21)",
    items: [
      { label: "Integrate semgrep/gosec and correlate static findings with live endpoints.", stepId: "static-review-correlation", implemented: true },
      { label: "Add run manifest, checkpointing, and export bundle.", stepId: "runops-manifest-export", implemented: true },
      { label: "Build chapter-aligned stage gates and completion scorecard.", stepId: "stage-gates-scorecard", implemented: true },
    ],
  },
];

export const FLOW_SUBDOMAIN_TOOLS = [
  { provider: "amass", label: "Amass", notes: "Passive DNS + graph-based discovery." },
  { provider: "sublist3r", label: "Sublist3r", notes: "OSINT-based subdomain enumeration." },
  { provider: "assetfinder", label: "Assetfinder", notes: "Fast passive domain discovery." },
  { provider: "gau", label: "GAU", notes: "Extract hosts from archived URL sources." },
  { provider: "ctl", label: "Certificate Transparency Logs", notes: "Collect domains from CT log search." },
  { provider: "subfinder", label: "Subfinder", notes: "ProjectDiscovery passive subdomain discovery." },
  { provider: "chaos", label: "Chaos", notes: "ProjectDiscovery DNS subdomain API source." },
];
