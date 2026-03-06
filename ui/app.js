const BACKEND_URL = document.body.dataset.backendUrl || "http://localhost:8080";

const runButton = document.getElementById("run-flow");
const pauseButton = document.getElementById("pause-flow");
const stopButton = document.getElementById("stop-flow");
const clearResultsButton = document.getElementById("clear-results");
const flowStatus = document.getElementById("flow-status");
const flowLogOutput = document.getElementById("flow-log-output");
const flowStepsList = document.getElementById("flow-steps-list");
const subdomainProgressBar = document.getElementById("subdomain-progress-bar");
const subdomainProgressText = document.getElementById("subdomain-progress-text");
const menuItems = document.querySelectorAll(".menu-item");
const views = document.querySelectorAll(".view");
const torRouteToggle = document.getElementById("tor-route-toggle");
const torNetworkIndicator = document.getElementById("tor-network-indicator");
const leadsStatus = document.getElementById("leads-status");
const leadsSummary = document.getElementById("leads-summary");
const leadsWildcards = document.getElementById("leads-wildcards");
const strideTabs = document.querySelectorAll(".stride-tab");
const strideSections = document.querySelectorAll(".stride-section");
const learnQuestion = document.getElementById("learn-question");
const learnAnswers = document.getElementById("learn-answers");
const learnPrev = document.getElementById("learn-prev");
const learnNext = document.getElementById("learn-next");
const learnIndex = document.getElementById("learn-index");
const strideAnswerText = document.getElementById("stride-answer-text");
const strideAnswerStatus = document.getElementById("stride-answer-status");
const strideExportAnswers = document.getElementById("stride-export-answers");
const manualWorkspaceRoots = document.querySelectorAll(".manual-recon[data-workspace]");
const githubAutoRun = document.getElementById("github-auto-run");
const githubKeyLabel = document.getElementById("github-key-label");
const githubKeyValue = document.getElementById("github-key-value");
const githubKeyActive = document.getElementById("github-key-active");
const githubKeyAdd = document.getElementById("github-key-add");
const githubKeysList = document.getElementById("github-keys-list");
const scopeCards = document.getElementById("scope-cards");
const scopeCardsStatus = document.getElementById("scope-cards-status");
const fileViewerModal = document.getElementById("file-viewer-modal");
const fileViewerTitle = document.getElementById("file-viewer-title");
const fileViewerContent = document.getElementById("file-viewer-content");
const closeFileViewer = document.getElementById("close-file-viewer");
const exportFileViewer = document.getElementById("export-file-viewer");
const openAmassEnum = document.getElementById("open-amass-enum");
const amassEnumModal = document.getElementById("amass-enum-modal");
const closeAmassEnum = document.getElementById("close-amass-enum");
const exportAmassEnum = document.getElementById("export-amass-enum");
const amassSearchName = document.getElementById("amass-search-name");
const amassSearchDomain = document.getElementById("amass-search-domain");
const amassSearchIP = document.getElementById("amass-search-ip");
const amassTableBody = document.getElementById("amass-table-body");
const amassCount = document.getElementById("amass-count");
const openLiveWebservers = document.getElementById("open-live-webservers");
const liveWebserversModal = document.getElementById("live-webservers-modal");
const closeLiveWebservers = document.getElementById("close-live-webservers");
const lwsSearchURL = document.getElementById("lws-search-url");
const lwsFilterStatus = document.getElementById("lws-filter-status");
const lwsSearchTitle = document.getElementById("lws-search-title");
const lwsSearchWebServer = document.getElementById("lws-search-webserver");
const lwsSearchTech = document.getElementById("lws-search-tech");
const lwsTableBody = document.getElementById("lws-table-body");
const lwsCount = document.getElementById("lws-count");
const manualDomainSelect = document.getElementById("manual-domain-select");
const manualDomainStatusFilter = document.getElementById("manual-domain-status-filter");
const manualDomainUrl = document.getElementById("manual-domain-url");
const manualAuthHeader = document.getElementById("manual-auth-header");
const manualRunXSS = document.getElementById("manual-run-xss");
const manualXSSStatus = document.getElementById("manual-xss-status");
const manualXSSRunner = manualRunXSS?.closest(".manual-xss-runner") || null;
const manualChecklistList = document.getElementById("manual-checklist-list");
const manualChecklistProgress = document.getElementById("manual-checklist-progress");
const hybridChecklistList = document.getElementById("hybrid-checklist-list");
const hybridChecklistProgress = document.getElementById("hybrid-checklist-progress");
const scopeCardNodes = new Map();

let lastStatusText = "";
let lastStepsSignature = "";
let lastLogsSignature = "";
let lastScopeSignature = "";
let lastLeadsSignature = "";
let manualDomainOptions = [];
let manualDomainsReady = false;
let currentFileModalType = "";
let currentFileModalLabel = "";
let currentFileModalLines = [];

const LIST_FILES = [
  { type: "wildcards", label: "Wildcards", uploadable: true },
  { type: "domains", label: "Domains", uploadable: true },
  { type: "apidomains", label: "API Domains", uploadable: true },
  { type: "organizations", label: "Organizations", uploadable: true },
  { type: "ips", label: "IPs", uploadable: true },
  { type: "out_of_scope", label: "Out of scope", uploadable: true },
  { type: "live_webservers_csv", label: "Live Web Servers CSV", uploadable: false },
  { type: "robots_urls", label: "Robots URLs", uploadable: false },
  { type: "wayback_urls", label: "Wayback URLs", uploadable: false },
  { type: "katana_urls", label: "Katana URLs", uploadable: false },
  { type: "all_urls", label: "All URLs", uploadable: false },
  { type: "params_candidates", label: "Param Candidates", uploadable: false },
  { type: "param_fuzz_query_hits", label: "Param Fuzz Query Hits", uploadable: false },
  { type: "param_fuzz_body_hits", label: "Param Fuzz Body Hits", uploadable: false },
  { type: "param_fuzz_header_hits", label: "Param Fuzz Header Hits", uploadable: false },
  { type: "param_fuzz_cookie_hits", label: "Param Fuzz Cookie Hits", uploadable: false },
  { type: "param_fuzz_summary", label: "Param Fuzz Summary", uploadable: false },
  { type: "injection_sqli_hits", label: "Injection SQLi Hits", uploadable: false },
  { type: "injection_nosqli_hits", label: "Injection NoSQLi Hits", uploadable: false },
  { type: "injection_xpath_hits", label: "Injection XPath Hits", uploadable: false },
  { type: "injection_ldap_hits", label: "Injection LDAP Hits", uploadable: false },
  { type: "injection_summary", label: "Injection Summary", uploadable: false },
  { type: "server_input_os_command_hits", label: "Server Input OS Command Hits", uploadable: false },
  { type: "server_input_path_traversal_hits", label: "Server Input Path Traversal Hits", uploadable: false },
  { type: "server_input_file_inclusion_hits", label: "Server Input File Inclusion Hits", uploadable: false },
  { type: "server_input_summary", label: "Server Input Summary", uploadable: false },
  { type: "adv_injection_xxe_hits", label: "Advanced Injection XXE Hits", uploadable: false },
  { type: "adv_injection_soap_hits", label: "Advanced Injection SOAP Hits", uploadable: false },
  { type: "adv_injection_ssrf_hits", label: "Advanced Injection SSRF Hits", uploadable: false },
  { type: "adv_injection_smtp_hits", label: "Advanced Injection SMTP Hits", uploadable: false },
  { type: "adv_injection_summary", label: "Advanced Injection Summary", uploadable: false },
  { type: "csrf_candidates", label: "CSRF Candidates", uploadable: false },
  { type: "csrf_findings", label: "CSRF Findings", uploadable: false },
  { type: "csrf_replay_log", label: "CSRF Replay Log", uploadable: false },
  { type: "csrf_summary", label: "CSRF Summary", uploadable: false },
  { type: "clickjacking_headers", label: "Clickjacking Headers", uploadable: false },
  { type: "clickjacking_findings", label: "Clickjacking Findings", uploadable: false },
  { type: "clickjacking_summary", label: "Clickjacking Summary", uploadable: false },
  { type: "cors_replay_log", label: "CORS Replay Log", uploadable: false },
  { type: "cors_findings", label: "CORS Findings", uploadable: false },
  { type: "cors_summary", label: "CORS Summary", uploadable: false },
  { type: "open_redirect_candidates", label: "Open Redirect Candidates", uploadable: false },
  { type: "open_redirect_replay_log", label: "Open Redirect Replay Log", uploadable: false },
  { type: "open_redirect_findings", label: "Open Redirect Findings", uploadable: false },
  { type: "open_redirect_summary", label: "Open Redirect Summary", uploadable: false },
  { type: "workflow_logic_candidates", label: "Workflow Logic Candidates", uploadable: false },
  { type: "workflow_logic_findings", label: "Workflow Logic Findings", uploadable: false },
  { type: "workflow_logic_replay_log", label: "Workflow Logic Replay Log", uploadable: false },
  { type: "workflow_logic_summary", label: "Workflow Logic Summary", uploadable: false },
  { type: "smuggling_stack_tool_runs", label: "Smuggling Stack Tool Runs", uploadable: false },
  { type: "smuggling_stack_findings", label: "Smuggling Stack Findings", uploadable: false },
  { type: "smuggling_stack_summary", label: "Smuggling Stack Summary", uploadable: false },
  { type: "nmap_targets", label: "Nmap Targets", uploadable: false },
  { type: "nmap_services", label: "Nmap Services", uploadable: false },
  { type: "nmap_searchsploit", label: "Nmap Searchsploit Correlation", uploadable: false },
  { type: "nmap_summary", label: "Nmap Summary", uploadable: false },
  { type: "tier_isolation_ip_map", label: "Tier Isolation IP Map", uploadable: false },
  { type: "tier_isolation_findings", label: "Tier Isolation Findings", uploadable: false },
  { type: "tier_isolation_summary", label: "Tier Isolation Summary", uploadable: false },
  { type: "static_review_semgrep", label: "Static Review Semgrep", uploadable: false },
  { type: "static_review_gosec", label: "Static Review Gosec", uploadable: false },
  { type: "static_review_correlated", label: "Static Review Correlated", uploadable: false },
  { type: "static_review_summary", label: "Static Review Summary", uploadable: false },
  { type: "runops_scorecard_json", label: "RunOps Scorecard JSON", uploadable: false },
  { type: "runops_scorecard_md", label: "RunOps Scorecard Markdown", uploadable: false },
  { type: "xss_reflected_hits", label: "XSS Reflected Hits", uploadable: false },
  { type: "xss_dom_hits", label: "XSS DOM Hits", uploadable: false },
  { type: "xss_stored_hits", label: "XSS Stored Hits", uploadable: false },
  { type: "xss_summary", label: "XSS Summary", uploadable: false },
  { type: "xss_scan_log", label: "XSS Scan Log", uploadable: false },
  { type: "fuzzing_doc_hits", label: "Fuzzing Doc Hits", uploadable: false },
  { type: "fuzzing_dir_hits", label: "Fuzzing Dir Hits", uploadable: false },
];

const FLOW_SEGMENTS = [
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
      { label: "Run amass enum for each wildcard.", stepId: "amass", implemented: true },
      { label: "Run sublist3r in parallel with other passive tools.", stepId: "sublist3r", implemented: true },
      { label: "Run assetfinder in parallel with other passive tools.", stepId: "assetfinder", implemented: true },
      { label: "Run gau in parallel with other passive tools.", stepId: "gau", implemented: true },
      { label: "Query certificate transparency logs in parallel.", stepId: "ctl", implemented: true },
      { label: "Run subfinder in parallel with other passive tools.", stepId: "subfinder", implemented: true },
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

const MANUAL_DOMAIN_CHECKLIST_ITEMS = [
  {
    id: "username-policy",
    label: "Username enumeration and password policy checks",
  },
  {
    id: "recovery-rememberme",
    label: "Recovery and remember-me weakness testing",
  },
  {
    id: "session-entropy-cookie-policy",
    label: "Session token entropy and cookie policy analysis",
  },
  {
    id: "session-fixation-logout-invalidation",
    label: "Session fixation and logout invalidation checks",
  },
  {
    id: "authz-role-matrix-bola-idor",
    label: "Role-matrix authorization replay (BOLA/IDOR)",
  },
  {
    id: "authz-method-mismatch",
    label: "Method-based access control mismatch checks",
  },
  {
    id: "logic-race-conditions",
    label: "Race-condition checks on critical state transitions",
  },
];

const HYBRID_MANUAL_CHECKLIST_ITEMS = [
  {
    id: "hybrid-injection-sqli-nosqli-xpath-ldap",
    label: "SQLi/NoSQL/XPath/LDAP: validate findings manually and confirm impact",
  },
  {
    id: "hybrid-injection-os-path-file",
    label: "OS command/path traversal/file inclusion: manual exploitability validation",
  },
  {
    id: "hybrid-injection-xxe-soap-ssrf-smtp",
    label: "XXE/SOAP/SSRF/SMTP: manual triage of automated findings",
  },
  {
    id: "hybrid-xss",
    label: "XSS (reflected/stored/DOM): manual verification and proof-of-impact",
  },
  {
    id: "hybrid-csrf",
    label: "CSRF: validate automated findings with authenticated/manual replay PoC",
  },
  {
    id: "hybrid-clickjacking",
    label: "Clickjacking: confirm exploitable UI redress on sensitive actions",
  },
  {
    id: "hybrid-cors",
    label: "CORS/SOP: validate data-read impact with authenticated browser context",
  },
  {
    id: "hybrid-open-redirect",
    label: "Open redirect: manually test OAuth/phishing/chaining impact",
  },
  {
    id: "hybrid-workflow-logic",
    label: "Workflow logic: validate semi-automated step/sequence findings manually",
  },
  {
    id: "hybrid-smuggling-stack",
    label: "Request smuggling/h2c/hop-by-hop/SSI-ESI: confirm exploitability manually",
  },
  {
    id: "hybrid-tier-isolation",
    label: "Tier-segmentation/shared-hosting: verify trust-boundary impact manually",
  },
];

const STRIDE_LESSONS = {
  overview: [
    {
      question: "What stage are we at and what are we trying to accomplish?",
      answers: [
        "Build a reusable threat model baseline from recon findings.",
        "Map each mechanism/object to realistic STRIDE attack paths.",
        "Prioritize what can create customer, business, or trust impact."
      ]
    },
    {
      question: "How should I think about STRIDE while testing?",
      answers: [
        "Treat each flow as a trust boundary crossing.",
        "Ask what breaks if identity, data integrity, logging, confidentiality, availability, or authorization fails.",
        "Capture exploitability and business impact, not just technical weakness."
      ]
    }
  ],
  "high-level-questions": [
    {
      question: "What high-level questions matter first?",
      answers: [
        "What are critical assets and who can access them?",
        "Where are trust boundaries between user/client/service/provider?",
        "What actions must be auditable and non-repudiable?"
      ]
    }
  ],
  mechanisms: [
    {
      question: "Which mechanisms should I enumerate?",
      answers: [
        "AuthN/AuthZ, session lifecycle, token handling, and role transitions.",
        "Input handling, workflow state transitions, and async job triggers.",
        "Integrations such as webhooks, queues, third-party APIs, and cloud services."
      ]
    }
  ],
  "notable-objects": [
    {
      question: "Which objects are highest-value?",
      answers: [
        "Identity and permission objects (users, orgs, roles, API keys).",
        "Business-critical records (orders, payouts, moderation, billing).",
        "Security evidence objects (logs, events, policy changes, alerts)."
      ]
    }
  ],
  "security-controls": [
    {
      question: "How do I evaluate controls quickly?",
      answers: [
        "Verify preventive control exists and is server-side enforced.",
        "Verify detective control records enough evidence to investigate.",
        "Verify corrective control can revoke, rotate, and recover fast."
      ]
    }
  ],
  "threat-model": [
    {
      question: "How do I write a useful threat model entry?",
      answers: [
        "Describe preconditions, attack steps, and control bypass.",
        "Attach concrete impact: customer data, attacker scope, and company reputation.",
        "Record recommended mitigation and how to validate the fix."
      ]
    }
  ],
  spoofing: [
    {
      question: "What spoofing checks should I run?",
      answers: [
        "Identity impersonation via weak session/token validation.",
        "Header trust abuse (`Host`, forwarded headers, origin assumptions).",
        "Cross-tenant identity confusion and account-linking mistakes."
      ]
    }
  ],
  tampering: [
    {
      question: "Where does tampering usually appear?",
      answers: [
        "Client-controlled fields trusted by backend for state changes.",
        "Workflow transitions lacking server-side integrity checks.",
        "Object references mutable without ownership verification."
      ]
    }
  ],
  repudiation: [
    {
      question: "What proves repudiation risk?",
      answers: [
        "Sensitive actions with no stable actor/request traceability.",
        "Editable/deletable logs without tamper-evident controls.",
        "Missing event context for high-risk transactions."
      ]
    }
  ],
  "info-disclosure": [
    {
      question: "What information disclosure signals are high-value?",
      answers: [
        "Secrets in client bundles, logs, stack traces, or docs.",
        "Overly verbose API responses exposing internal fields.",
        "Cross-tenant data leakage via object ID or filtering flaws."
      ]
    }
  ],
  dos: [
    {
      question: "How should I model DoS risk?",
      answers: [
        "Find expensive endpoints lacking strict quotas and backpressure.",
        "Test queue/job amplification and retry storm behavior.",
        "Measure blast radius on critical auth and payment flows."
      ]
    }
  ],
  eop: [
    {
      question: "What elevation-of-privilege paths are common?",
      answers: [
        "Role/claim manipulation and stale authorization caches.",
        "Admin endpoints reachable from low-privileged contexts.",
        "Chained weak controls enabling horizontal to vertical escalation."
      ]
    }
  ],
  workflow: [
    {
      question: "How do I operationalize this during recon/testing?",
      answers: [
        "Map findings to mechanisms/objects first, then STRIDE categories.",
        "Track evidence and hypotheses per subsection in 'Your Answer'.",
        "Promote only threats with plausible exploit path and impact."
      ]
    }
  ]
};

const MANUAL_RECON_QUESTIONS = [
  {
    category: "Application Identity & Scope",
    questions: [
      "What is the primary function of the application?",
      "Is it consumer-facing, enterprise-facing, internal, or partner-facing?",
      "Is the application a single product or part of a larger platform?",
      "Are there multiple subdomains serving different functions?",
      "Are there multiple environments publicly accessible (prod, staging, beta)?",
      "Is the application region-specific or global?",
      "Are there mobile apps, desktop apps, or browser extensions associated with it?",
      "Is the web app a full product or a thin UI over APIs?",
      "Does the application expose public documentation or help portals?",
      "Is the app intended to be embedded or integrated into other sites?"
    ]
  },
  {
    category: "Technology Stack & Frameworks",
    questions: [
      "What frontend framework is used?",
      "Is the app a Single Page Application?",
      "Is server-side rendering used?",
      "What backend language(s) are implied?",
      "Is the backend REST, GraphQL, or mixed?",
      "Are API versioning patterns present?",
      "Are build tools identifiable from assets?",
      "Are framework or library versions exposed?",
      "Are deprecated or end-of-life libraries in use?",
      "Are custom client-side frameworks present?"
    ]
  },
  {
    category: "Hosting, Infrastructure & Delivery",
    questions: [
      "Is the application behind a CDN?",
      "Which CDN or edge provider is used?",
      "What server software is observable?",
      "Is a load balancer or reverse proxy in use?",
      "Is the app hosted in a public cloud?",
      "Can the cloud provider be identified?",
      "Are multiple services hosted on the same domain?",
      "Is virtual hosting used?",
      "Are containerization or serverless hints present?",
      "Are internal hostnames or regions leaked in responses?"
    ]
  },
  {
    category: "Network & Transport Security",
    questions: [
      "Is HTTPS enforced everywhere?",
      "Is HSTS enabled?",
      "Which TLS versions are supported?",
      "Are weak cipher suites accepted?",
      "Is HTTP/2 or HTTP/3 used?",
      "Are cookies marked Secure?",
      "Are cookies marked HttpOnly?",
      "Is SameSite set on cookies?",
      "Are authentication cookies scoped to subdomains?",
      "Are multiple domains involved in session handling?"
    ]
  },
  {
    category: "Traffic Controls & Abuse Protection",
    questions: [
      "Is a Web Application Firewall present?",
      "Can the WAF vendor be identified?",
      "Is bot detection or fingerprinting in use?",
      "Is rate limiting observable?",
      "Is CAPTCHA used anywhere in the app?",
      "Is CAPTCHA conditional or global?",
      "Are request challenges used (JS challenges, proof-of-work)?",
      "Are IP-based restrictions present?",
      "Does behavior differ for authenticated users?",
      "Are automated clients treated differently?"
    ]
  },
  {
    category: "Authentication & Identity Model",
    questions: [
      "Is authentication required to access core functionality?",
      "What authentication methods are supported?",
      "Are third-party IdPs used?",
      "Is OAuth or OIDC used?",
      "Are multiple login methods available?",
      "Is MFA supported?",
      "Is MFA optional or mandatory?",
      "Are long-lived sessions used?",
      "Are refresh tokens observable client-side?",
      "Are authentication flows shared across domains?"
    ]
  },
  {
    category: "Authorization, Roles & Data Model",
    questions: [
      "Are multiple user roles visible?",
      "Are role distinctions observable in the UI?",
      "Is the application multi-tenant?",
      "Are organizations, teams, or workspaces present?",
      "Are user identifiers exposed client-side?",
      "Are object identifiers exposed globally?",
      "Are shared resources visible?",
      "Are admin interfaces exposed?",
      "Are feature flags visible client-side?",
      "Are permissions enforced centrally or per-service?"
    ]
  },
  {
    category: "Client-Side, Integrations & Policies",
    questions: [
      "What third-party scripts are loaded?",
      "Are analytics platforms present?",
      "Are customer support widgets present?",
      "Are payment providers integrated?",
      "Are external APIs called from the browser?",
      "Are API keys present client-side?",
      "Is a Content Security Policy present?",
      "Is the CSP strict or permissive?",
      "Is CORS implemented?",
      "Is source code or documentation publicly available?"
    ]
  },
  {
    category: "Cloud Infrastructure & Services",
    questions: [
      "Are cloud storage buckets accessible (S3, Azure Blob, GCS)?",
      "Are bucket/container names discoverable or predictable?",
      "Are cloud metadata endpoints accessible?",
      "Are serverless functions identifiable?",
      "Are cloud service URLs exposed in client-side code?",
      "Is the cloud region/zone disclosed?",
      "Are CDN or object storage URLs structured predictably?",
      "Are cloud resource naming patterns consistent?",
      "Are AWS ARNs, Azure Resource IDs, or GCP project IDs leaked?",
      "Are infrastructure-as-code templates publicly accessible?"
    ]
  },
  {
    category: "API Architecture & GraphQL",
    questions: [
      "Does the application use GraphQL?",
      "Is GraphQL introspection enabled?",
      "Are API endpoints versioned?",
      "Are deprecated API versions still accessible?",
      "Is the API documentation publicly available?",
      "Are websockets or SSE used for real-time features?",
      "Are REST API endpoints discoverable through OPTIONS requests?",
      "Is there an API gateway or BFF (Backend for Frontend)?",
      "Are internal/debugging endpoints exposed?",
      "Are API responses verbose with metadata?"
    ]
  },
  {
    category: "Public Information & OSINT",
    questions: [
      "Are employee emails or usernames predictable?",
      "Is company GitHub/GitLab organization public?",
      "Are public repositories related to this application?",
      "Are commits containing secrets, keys, or credentials visible?",
      "Are subdomains enumerable through certificate transparency?",
      "Are job postings revealing tech stack details?",
      "Are error messages leaking internal paths or usernames?",
      "Are backup files, config files, or archives publicly accessible?",
      "Is sensitive information in JavaScript source maps?",
      "Are API docs, changelogs, or internal wikis indexed by search engines?"
    ]
  }
];

const MANUAL_WORKSPACE_QUESTIONS = {
  "high-level-questions": MANUAL_RECON_QUESTIONS,
  mechanisms: [
    {
      category: "Authentication Mechanisms",
      questions: [
        "How are login, MFA, and recovery flows implemented?",
        "Where can token/session lifecycle be abused?",
        "Are SSO boundaries clearly enforced across subdomains?",
        "What identity assumptions are trusted from the client?"
      ]
    },
    {
      category: "Authorization Mechanisms",
      questions: [
        "Is RBAC/ABAC enforced server-side for every sensitive action?",
        "Are role transitions and privilege grants audited?",
        "Can tenancy boundaries be crossed through object IDs?",
        "Are admin operations separated from normal user flows?"
      ]
    },
    {
      category: "State & Input Mechanisms",
      questions: [
        "Which workflow state changes depend on client-controlled fields?",
        "Where is validation/canonicalization inconsistent?",
        "Are deserialization/parsing paths hardened against malformed input?",
        "Can async jobs be triggered out-of-order or replayed?"
      ]
    }
  ],
  "notable-objects": [
    {
      category: "Identity & Access Objects",
      questions: [
        "Which identity objects can change scope/privilege?",
        "Where are API keys, tokens, or service credentials stored?",
        "Are role and permission objects mutable by low-privileged users?",
        "What ownership model protects account and org objects?"
      ]
    },
    {
      category: "Business-Critical Objects",
      questions: [
        "Which business objects would create highest impact if modified?",
        "Can payout/order/refund objects be tampered with?",
        "Are moderation or trust-safety objects weakly protected?",
        "Which object IDs are predictable/enumerable?"
      ]
    },
    {
      category: "Security Evidence Objects",
      questions: [
        "What audit records exist for critical actions?",
        "Can logs/events be altered, deleted, or suppressed?",
        "Are security events linked to stable actor context?",
        "Do stored events support incident reconstruction?"
      ]
    }
  ],
  "security-controls": [
    {
      category: "Preventive Controls",
      questions: [
        "Which controls block misuse before execution?",
        "Are authz, schema validation, and rate limits consistently enforced?",
        "Which endpoints bypass WAF/proxy policy unintentionally?",
        "Are secret-management and key-rotation controls effective?"
      ]
    },
    {
      category: "Detective Controls",
      questions: [
        "Which high-risk actions generate detections?",
        "Is telemetry sufficient to detect abuse patterns quickly?",
        "Are anomaly detections resistant to noisy false positives?",
        "Do alerts provide enough context for triage?"
      ]
    },
    {
      category: "Corrective Controls",
      questions: [
        "How fast can sessions/keys/tokens be revoked?",
        "Are rollback and incident playbooks tested regularly?",
        "Can compromised objects be quarantined without broad outage?",
        "Is there verified recovery for worst-case abuse paths?"
      ]
    }
  ],
  "threat-model": [
    {
      category: "Threat Enumeration",
      questions: [
        "What are the top STRIDE threats for this flow?",
        "Which preconditions and trust assumptions make exploitation feasible?",
        "What attack chains convert low-risk bugs into critical impact?",
        "Where do existing controls fail under adversarial input?"
      ]
    },
    {
      category: "Impact Modeling",
      questions: [
        "What customer data exposure is plausible and at what scale?",
        "How far can attacker scope expand (user, org, platform)?",
        "What business operations can be disrupted or manipulated?",
        "What reputational/legal impact is likely if exploited?"
      ]
    },
    {
      category: "Mitigation Planning",
      questions: [
        "What is the highest-leverage fix for this threat?",
        "How should detection be updated to catch repeats?",
        "What validation proves mitigation is complete?",
        "Who owns remediation and what is the deadline?"
      ]
    }
  ],
  spoofing: [
    {
      category: "Identity Impersonation",
      questions: [
        "Can attacker impersonate users through session/token flaws?",
        "Are password reset and recovery flows resistant to spoofing?",
        "Can account linking be abused to bind attacker identity to victim context?",
        "Do service-to-service calls verify caller identity strongly?",
        "Can OAuth/OIDC callback handling be spoofed via redirect confusion?"
      ]
    },
    {
      category: "Trust Boundary Assumptions",
      questions: [
        "Does backend trust spoofable headers (`Host`, `X-Forwarded-*`)?",
        "Are origin/referrer checks enforceable and tamper-resistant?",
        "Can tenant context be spoofed via client-side parameters?",
        "Can federated identity claims be forged or replayed?",
        "Do mTLS/internal-service assumptions break at edge proxies?"
      ]
    }
  ],
  tampering: [
    {
      category: "Request/Data Integrity",
      questions: [
        "Which request parameters can alter protected state?",
        "Are client-calculated values (price, role, scope) trusted by backend?",
        "Can stored records be modified without ownership checks?",
        "Are signed tokens/payloads validated consistently?",
        "Can file/object metadata be overwritten to influence downstream processing?"
      ]
    },
    {
      category: "Workflow Integrity",
      questions: [
        "Can state transitions be forced out of sequence?",
        "Can attacker replay old requests to tamper with current state?",
        "Are idempotency and anti-race controls in place for critical actions?",
        "Can background job payloads be manipulated before execution?",
        "Can webhook payload trust be abused to mutate internal state?"
      ]
    }
  ],
  repudiation: [
    {
      category: "Auditability",
      questions: [
        "Which privileged actions lack durable audit trails?",
        "Is actor attribution stable across proxies and services?",
        "Can users deny actions due to missing context in logs?",
        "Are audit logs immutable and protected from tampering?",
        "Are admin actions distinguishable from automation/service actions?"
      ]
    },
    {
      category: "Forensics Readiness",
      questions: [
        "Do events include request ID, subject, object, and outcome?",
        "Are timestamps and correlation IDs reliable across systems?",
        "Can incident responders reconstruct attack sequence from telemetry?",
        "Are failed/high-risk actions logged at sufficient detail?",
        "Are log retention windows sufficient for realistic incident timelines?"
      ]
    }
  ],
  "info-disclosure": [
    {
      category: "Data Exposure",
      questions: [
        "Which endpoints leak sensitive fields beyond least-privilege need?",
        "Can cross-tenant/object access reveal unauthorized data?",
        "Are secrets exposed via errors, logs, or debug endpoints?",
        "Do client bundles/source maps leak private implementation details?",
        "Are internal-only endpoints exposed through API documentation or schema?"
      ]
    },
    {
      category: "Storage/Infra Exposure",
      questions: [
        "Are buckets/backups/indexes publicly accessible?",
        "Are internal hostnames, regions, or metadata leaked in responses?",
        "Can generated documents/files expose private paths or identifiers?",
        "Are data retention and redaction controls enforced consistently?",
        "Are pre-signed URLs scoped and expired safely?"
      ]
    }
  ],
  dos: [
    {
      category: "Resource Exhaustion",
      questions: [
        "Which endpoints are computationally expensive without strict limits?",
        "Can attacker amplify backend work with cheap repeated requests?",
        "Are query size/depth limits enforced for API endpoints?",
        "Can attacker starve queues/workers through flooding?",
        "Can search/report exports be abused for CPU or memory pressure?"
      ]
    },
    {
      category: "Availability Resilience",
      questions: [
        "Are auth/payment/critical flows protected with backpressure controls?",
        "Do retries/circuit breakers avoid cascading failure?",
        "Can one tenant degrade service for all tenants?",
        "Is graceful degradation implemented for partial outages?",
        "Are anti-automation controls tuned to prevent low-cost request floods?"
      ]
    }
  ],
  eop: [
    {
      category: "Privilege Escalation Paths",
      questions: [
        "Can low-privileged users access admin-only endpoints?",
        "Are role changes and permission grants server-authorized?",
        "Can horizontal access become vertical privilege gain?",
        "Are feature flags/hidden routes exposing privileged capabilities?",
        "Can delegated access tokens exceed intended scope?"
      ]
    },
    {
      category: "Authorization Consistency",
      questions: [
        "Is authorization enforced uniformly across API, UI, and background tasks?",
        "Can stale caches or delayed propagation grant unintended privileges?",
        "Are object-level checks complete on read/write/delete actions?",
        "Can chained bugs bypass layered authorization design?",
        "Are emergency/admin bypasses constrained and auditable?"
      ]
    }
  ]
};

let activeStrideKey = "overview";
let learnSlideIndex = 0;
const manualWorkspaceState = {};
let amassRows = [];
let amassSortKey = "name";
let amassSortDir = "asc";
let liveWebserverRows = [];
let lwsSortKey = "url";
let lwsSortDir = "asc";

function escapeHTML(value) {
  return (value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;");
}

function ansiTextToHTML(raw) {
  const input = String(raw || "");
  const ansiPattern = /\u001b\[([0-9;]*)m/g;
  let html = "";
  let cursor = 0;
  const state = {
    fg: "",
    bold: false,
  };

  const renderChunk = (chunk) => {
    const escaped = escapeHTML(chunk);
    if (!escaped) {
      return;
    }
    const classes = [];
    if (state.fg) {
      classes.push(state.fg);
    }
    if (state.bold) {
      classes.push("ansi-bold");
    }
    if (classes.length === 0) {
      html += escaped;
      return;
    }
    html += `<span class="${classes.join(" ")}">${escaped}</span>`;
  };

  const setFG = (cls) => {
    state.fg = cls;
  };

  let match;
  while ((match = ansiPattern.exec(input)) !== null) {
    renderChunk(input.slice(cursor, match.index));
    cursor = match.index + match[0].length;
    const rawCodes = match[1] || "0";
    const codes = rawCodes.split(";").filter(Boolean).map((code) => Number(code));
    if (codes.length === 0) {
      state.fg = "";
      state.bold = false;
      continue;
    }
    for (const code of codes) {
      switch (code) {
        case 0:
          state.fg = "";
          state.bold = false;
          break;
        case 1:
          state.bold = true;
          break;
        case 22:
          state.bold = false;
          break;
        case 30:
          setFG("ansi-fg-black");
          break;
        case 31:
          setFG("ansi-fg-red");
          break;
        case 32:
          setFG("ansi-fg-green");
          break;
        case 33:
          setFG("ansi-fg-yellow");
          break;
        case 34:
          setFG("ansi-fg-blue");
          break;
        case 35:
          setFG("ansi-fg-magenta");
          break;
        case 36:
          setFG("ansi-fg-cyan");
          break;
        case 37:
          setFG("ansi-fg-white");
          break;
        case 90:
          setFG("ansi-fg-bright-black");
          break;
        case 91:
          setFG("ansi-fg-bright-red");
          break;
        case 92:
          setFG("ansi-fg-bright-green");
          break;
        case 93:
          setFG("ansi-fg-bright-yellow");
          break;
        case 94:
          setFG("ansi-fg-bright-blue");
          break;
        case 95:
          setFG("ansi-fg-bright-magenta");
          break;
        case 96:
          setFG("ansi-fg-bright-cyan");
          break;
        case 97:
          setFG("ansi-fg-bright-white");
          break;
        case 39:
          state.fg = "";
          break;
        default:
          break;
      }
    }
  }

  renderChunk(input.slice(cursor));
  return html.replace(/\n/g, "<br>");
}

menuItems.forEach((item) => {
  item.addEventListener("click", () => {
    menuItems.forEach((btn) => btn.classList.remove("is-active"));
    item.classList.add("is-active");
    const view = item.dataset.view;
    views.forEach((section) => section.classList.remove("is-active"));
    const active = document.querySelector(`.view-${view}`);
    if (active) {
      active.classList.add("is-active");
    }
    if (view === "leads") {
      void refreshLeads({ force: true });
    }
  });
});

strideTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const key = tab.dataset.strideTab;
    if (!key) {
      return;
    }
    strideTabs.forEach((node) => node.classList.remove("is-active"));
    tab.classList.add("is-active");
    strideSections.forEach((section) => {
      section.classList.toggle("is-active", section.dataset.strideContent === key);
    });
    activeStrideKey = key;
    learnSlideIndex = 0;
    renderStrideLearning();
    loadStrideAnswer();
  });
});

function renderStrideLearning() {
  if (!learnQuestion || !learnAnswers || !learnIndex) {
    return;
  }
  const lessons = STRIDE_LESSONS[activeStrideKey] || [];
  if (lessons.length === 0) {
    learnQuestion.textContent = "No learning prompts for this section yet.";
    learnAnswers.innerHTML = "";
    learnIndex.textContent = "0 / 0";
    return;
  }
  if (learnSlideIndex < 0) {
    learnSlideIndex = 0;
  }
  if (learnSlideIndex >= lessons.length) {
    learnSlideIndex = lessons.length - 1;
  }
  const lesson = lessons[learnSlideIndex];
  learnQuestion.textContent = lesson.question;
  learnAnswers.innerHTML = (lesson.answers || [])
    .map((answer) => `<li>${escapeHTML(answer)}</li>`)
    .join("");
  learnIndex.textContent = `${learnSlideIndex + 1} / ${lessons.length}`;
}

learnPrev?.addEventListener("click", () => {
  learnSlideIndex -= 1;
  renderStrideLearning();
});

learnNext?.addEventListener("click", () => {
  learnSlideIndex += 1;
  renderStrideLearning();
});

function strideAnswerStorageKey() {
  return `bflow_stride_answer_${activeStrideKey}`;
}

function loadStrideAnswer() {
  if (!strideAnswerText) {
    return;
  }
  strideAnswerText.value = localStorage.getItem(strideAnswerStorageKey()) || "";
  if (strideAnswerStatus) {
    strideAnswerStatus.textContent = "Loaded section notes.";
  }
}

let strideSaveTimer = null;
strideAnswerText?.addEventListener("input", () => {
  if (strideSaveTimer) {
    clearTimeout(strideSaveTimer);
  }
  strideSaveTimer = setTimeout(() => {
    localStorage.setItem(strideAnswerStorageKey(), strideAnswerText.value);
    if (strideAnswerStatus) {
      strideAnswerStatus.textContent = "Saved locally.";
    }
  }, 250);
});

function manualReconStorageKey() {
  return "bflow_manual_recon_answers";
}

function loadManualReconAnswers() {
  try {
    return JSON.parse(localStorage.getItem(manualReconStorageKey()) || "{}");
  } catch {
    return {};
  }
}

function saveManualReconAnswers(answers) {
  localStorage.setItem(manualReconStorageKey(), JSON.stringify(answers));
}

function workspaceDisplayName(workspaceKey) {
  const map = {
    "high-level-questions": "High Level Questions",
    mechanisms: "Mechanisms",
    "notable-objects": "Notable Objects",
    "security-controls": "Security Controls",
    "threat-model": "Threat Model",
    spoofing: "S - Spoofing",
    tampering: "T - Tampering",
    repudiation: "R - Repudiation",
    "info-disclosure": "I - Information Disclosure",
    dos: "D - Denial of Service",
    eop: "E - Elevation of Privilege",
    workflow: "Workflow"
  };
  return map[workspaceKey] || workspaceKey;
}

function exportAllAnswersMarkdown() {
  const answersMap = loadManualReconAnswers();
  const lines = [];
  const now = new Date().toISOString();
  lines.push("# STRIDE Answers Export");
  lines.push("");
  lines.push(`Generated: ${now}`);
  lines.push("");

  for (const [workspaceKey, workspaceData] of Object.entries(MANUAL_WORKSPACE_QUESTIONS)) {
    const allQuestions = [];
    for (const section of workspaceData) {
      for (const question of section.questions || []) {
        allQuestions.push({ category: section.category, question });
      }
    }
    lines.push(`## ${workspaceDisplayName(workspaceKey)}`);
    lines.push("");
    let workspaceHasContent = false;
    for (const item of allQuestions) {
      const key = workspaceQuestionKey(workspaceKey, item.question);
      const answers = Array.isArray(answersMap[key]) ? answersMap[key] : [];
      if (answers.length === 0) {
        continue;
      }
      workspaceHasContent = true;
      lines.push(`### ${item.question}`);
      lines.push(`Category: ${item.category}`);
      lines.push("");
      answers.forEach((entry, idx) => {
        lines.push(`${idx + 1}. ${entry.text || ""}`);
        if (entry.created_at) {
          lines.push(`   - Saved: ${entry.created_at}`);
        }
      });
      lines.push("");
    }
    const note = localStorage.getItem(`bflow_stride_answer_${workspaceKey}`) || "";
    if (note.trim()) {
      workspaceHasContent = true;
      lines.push("### Workspace Notes");
      lines.push(note.trim());
      lines.push("");
    }
    if (!workspaceHasContent) {
      lines.push("_No answers saved._");
      lines.push("");
    }
  }

  const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `stride_answers_${Date.now()}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

strideExportAnswers?.addEventListener("click", exportAllAnswersMarkdown);

function workspaceQuestionKey(workspaceKey, question) {
  return `${workspaceKey}::${question}`;
}

function manualHelpBullets(question, category) {
  if (!question) {
    return [];
  }
  return [
    `Why this matters: ${category} gaps often create exploitable trust assumptions.`,
    `How to investigate: capture concrete evidence (requests/responses, headers, and role context).`,
    `What to write down: exploit path, impacted object/flow, and business impact if abused.`
  ];
}

function normalizeSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\w\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function getWorkspaceHelp(workspaceKey, question, category) {
  const generic = manualHelpBullets(question, category);
  const workspaceHelp = {
    spoofing: [
      "Validate identity at every boundary: token, session, and trust headers.",
      "Attempt impersonation with crafted claims, swapped identifiers, and replayed artifacts.",
      "Document whether spoofing crosses user, org, or service boundaries."
    ],
    tampering: [
      "Try modifying state inputs server expects to be immutable.",
      "Probe race/replay paths around critical workflow transitions.",
      "Track data integrity failures and affected business objects."
    ],
    repudiation: [
      "Verify sensitive actions create immutable and attributable audit records.",
      "Look for missing request IDs, actor context, or timing integrity.",
      "Record what an attacker can deny and why defenders cannot prove otherwise."
    ],
    "info-disclosure": [
      "Map all fields returned by APIs and identify overexposure.",
      "Check error/debug/log channels for secrets or private metadata.",
      "Quantify disclosure scope: single record, tenant-wide, or platform-wide."
    ],
    dos: [
      "Identify high-cost endpoints lacking strict quota/complexity controls.",
      "Test amplification and queue saturation without harming production.",
      "Capture blast radius and recovery behavior for critical user flows."
    ],
    eop: [
      "Test authorization consistency across UI, API, and background paths.",
      "Chain horizontal access and role flaws toward admin capabilities.",
      "Describe final privilege gained and what controls failed."
    ],
    "threat-model": [
      "Express preconditions, steps, and control bypass clearly.",
      "Tie each threat to measurable customer/business impact.",
      "List validation criteria for mitigation completion."
    ]
  };

  return workspaceHelp[workspaceKey] || generic;
}
function initializeManualRecon() {
  for (const root of manualWorkspaceRoots) {
    const workspaceKey = root.dataset.workspace;
    const questionBank = MANUAL_WORKSPACE_QUESTIONS[workspaceKey] || [];
    if (!workspaceKey || questionBank.length === 0) {
      continue;
    }

    const search = root.querySelector(".manual-recon-search");
    const categories = root.querySelector(".manual-recon__categories");
    const questionTitle = root.querySelector(".manual-recon-question-title");
    const questionCategory = root.querySelector(".manual-recon-question-category");
    const helpList = root.querySelector(".manual-recon-help-list");
    const answersList = root.querySelector(".manual-recon__answers-list");
    const addAnswer = root.querySelector(".manual-recon-add-answer");
    const answerInput = root.querySelector(".manual-recon-answer-input");
    const saveAnswer = root.querySelector(".manual-recon-save-answer");
    const answerStatus = root.querySelector(".manual-recon-answer-status");
    if (!categories || !questionTitle || !questionCategory || !helpList || !answersList || !answerInput) {
      continue;
    }

    manualWorkspaceState[workspaceKey] = manualWorkspaceState[workspaceKey] || { query: "", selectedQuestion: "" };
    const state = manualWorkspaceState[workspaceKey];

    const getFiltered = () => {
      const needle = normalizeSearchText(state.query || "");
      if (!needle) {
        return questionBank;
      }
      const terms = needle.split(" ").filter(Boolean);
      const filtered = [];
      for (const entry of questionBank) {
        const categoryText = normalizeSearchText(entry.category);
        const matched = entry.questions.filter((q) => {
          const qText = normalizeSearchText(q);
          return terms.every((term) => qText.includes(term) || categoryText.includes(term));
        });
        if (matched.length > 0) {
          filtered.push({ category: entry.category, questions: matched.length > 0 ? matched : entry.questions });
        }
      }
      return filtered;
    };

    const firstQuestion = (filtered) => {
      for (const entry of filtered) {
        if (entry.questions.length > 0) {
          return entry.questions[0];
        }
      }
      return "";
    };

    const findCategory = (question) => {
      for (const entry of questionBank) {
        if (entry.questions.includes(question)) {
          return entry.category;
        }
      }
      return "";
    };

    const renderAnswers = () => {
      if (!state.selectedQuestion) {
        answersList.textContent = "No answers yet. Add your first answer below.";
        return;
      }
      const map = loadManualReconAnswers();
      const key = workspaceQuestionKey(workspaceKey, state.selectedQuestion);
      const answers = Array.isArray(map[key]) ? map[key] : [];
      if (answers.length === 0) {
        answersList.textContent = "No answers yet. Add your first answer below.";
        return;
      }
      answersList.innerHTML = answers.map((entry) => `
        <article class="manual-recon__answer-item">
          <div>${escapeHTML(entry.text || "")}</div>
          <small>${escapeHTML(entry.created_at || "")}</small>
        </article>
      `).join("");
    };

    const renderDetails = () => {
      if (!state.selectedQuestion) {
        questionTitle.textContent = "Select a question";
        questionCategory.textContent = "";
        helpList.innerHTML = "";
        renderAnswers();
        return;
      }
      const category = findCategory(state.selectedQuestion);
      questionTitle.textContent = state.selectedQuestion;
      questionCategory.textContent = category;
      helpList.innerHTML = getWorkspaceHelp(workspaceKey, state.selectedQuestion, category)
        .map((line) => `<li>${escapeHTML(line)}</li>`)
        .join("");
      renderAnswers();
    };

    const renderWorkspace = () => {
      const filtered = getFiltered();
      const visibleQuestions = new Set(filtered.flatMap((entry) => entry.questions));
      if (!state.selectedQuestion || !visibleQuestions.has(state.selectedQuestion)) {
        state.selectedQuestion = firstQuestion(filtered);
      }
      if (filtered.length === 0) {
        categories.innerHTML = '<p class="muted">No matching questions.</p>';
        renderDetails();
        return;
      }
      categories.innerHTML = filtered.map((entry) => {
        const buttons = entry.questions.map((question) => {
          const active = state.selectedQuestion === question ? "is-active" : "";
          return `<button type="button" class="manual-recon__question ${active}" data-manual-question="${escapeHTML(question)}">${escapeHTML(question)}</button>`;
        }).join("");
        return `<section class="manual-recon__category"><h5 class="manual-recon__category-title">${escapeHTML(entry.category)}</h5>${buttons}</section>`;
      }).join("");
      renderDetails();
    };

    categories.addEventListener("click", (event) => {
      const button = event.target.closest(".manual-recon__question");
      if (!button) {
        return;
      }
      state.selectedQuestion = button.dataset.manualQuestion || "";
      renderWorkspace();
    });

    search?.addEventListener("input", () => {
      state.query = search.value || "";
      renderWorkspace();
    });

    addAnswer?.addEventListener("click", () => {
      answerInput.focus();
    });

    const saveCurrentAnswer = () => {
      const text = (answerInput.value || "").trim();
      if (!text || !state.selectedQuestion) {
        return;
      }
      const map = loadManualReconAnswers();
      const key = workspaceQuestionKey(workspaceKey, state.selectedQuestion);
      const current = Array.isArray(map[key]) ? map[key] : [];
      current.unshift({ text, created_at: new Date().toLocaleString() });
      map[key] = current;
      saveManualReconAnswers(map);
      answerInput.value = "";
      if (answerStatus) {
        answerStatus.textContent = "Answer saved.";
      }
      renderAnswers();
    };

    saveAnswer?.addEventListener("click", saveCurrentAnswer);
    answerInput.addEventListener("keydown", (event) => {
      if (!(event.ctrlKey || event.metaKey) || event.key !== "Enter") {
        return;
      }
      event.preventDefault();
      saveCurrentAnswer();
    });

    state.selectedQuestion = firstQuestion(questionBank);
    renderWorkspace();
  }
}

function manualDomainChecklistStorageKey() {
  return "bflow_manual_domain_checklist_v2";
}

function loadManualDomainChecklistState() {
  try {
    return JSON.parse(localStorage.getItem(manualDomainChecklistStorageKey()) || "{}");
  } catch {
    return {};
  }
}

function saveManualDomainChecklistState(state) {
  localStorage.setItem(manualDomainChecklistStorageKey(), JSON.stringify(state));
}

function hybridChecklistStorageKey() {
  return "bflow_hybrid_manual_checklist_v1";
}

function loadHybridChecklistState() {
  try {
    return JSON.parse(localStorage.getItem(hybridChecklistStorageKey()) || "{}");
  } catch {
    return {};
  }
}

function saveHybridChecklistState(state) {
  localStorage.setItem(hybridChecklistStorageKey(), JSON.stringify(state));
}

function normalizeDomainEntry(entry) {
  const value = String(entry || "").trim();
  if (!value) {
    return "";
  }
  if (/^https?:\/\//i.test(value)) {
    return value;
  }
  return `https://${value}`;
}

function domainFromURL(urlText) {
  const normalized = normalizeDomainEntry(urlText);
  try {
    return new URL(normalized).host.toLowerCase();
  } catch {
    return normalized.replace(/^https?:\/\//i, "").replace(/\/+$/, "").toLowerCase();
  }
}

function selectedManualDomain() {
  const value = manualDomainSelect?.value || "";
  return value.trim();
}

function selectedManualStatusFilter() {
  const value = manualDomainStatusFilter?.value || "";
  return value.trim();
}

function updateManualStatusFilterOptions(rows) {
  if (!manualDomainStatusFilter) {
    return;
  }
  const current = manualDomainStatusFilter.value;
  const statuses = [...new Set((rows || []).map((row) => String(row.status_code || "").trim()).filter(Boolean))]
    .sort((a, b) => Number(a) - Number(b));
  manualDomainStatusFilter.innerHTML = [
    '<option value="">All status codes</option>',
    ...statuses.map((status) => `<option value="${escapeHTML(status)}">${escapeHTML(status)}</option>`),
  ].join("");
  if (current && statuses.includes(current)) {
    manualDomainStatusFilter.value = current;
  }
}

function renderManualChecklist() {
  if (!manualChecklistList || !manualChecklistProgress) {
    return;
  }

  const selected = selectedManualDomain();
  if (!selected) {
    manualChecklistList.innerHTML = '<p class="muted">Select a domain to track manual testing.</p>';
    manualChecklistProgress.textContent = "0 / 0 done";
    if (manualDomainUrl) {
      manualDomainUrl.textContent = "No domain selected";
      manualDomainUrl.removeAttribute("href");
    }
    applyManualXSSRunnerAvailability(false);
    return;
  }

  const url = normalizeDomainEntry(selected);
  const host = domainFromURL(url);
  if (manualDomainUrl) {
    manualDomainUrl.textContent = url;
    manualDomainUrl.href = url;
  }
  applyManualXSSRunnerAvailability(false);

  const state = loadManualDomainChecklistState();
  const domainState = state[host] || {};
  let done = 0;

  manualChecklistList.innerHTML = MANUAL_DOMAIN_CHECKLIST_ITEMS.map((item) => {
    const checked = Boolean(domainState[item.id]);
    if (checked) {
      done += 1;
    }
    return `
      <label class="manual-checklist-item">
        <input type="checkbox" data-manual-item-id="${escapeHTML(item.id)}" ${checked ? "checked" : ""} />
        <span>${escapeHTML(item.label)}</span>
      </label>
    `;
  }).join("");

  manualChecklistProgress.textContent = `${done} / ${MANUAL_DOMAIN_CHECKLIST_ITEMS.length} done`;
}

function updateManualXSSStatusText(statusData) {
  if (!manualXSSStatus) {
    return;
  }
  const status = String(statusData?.status || "idle");
  const running = Boolean(statusData?.running);
  const lastRun = String(statusData?.last_run || "");
  const lastRunText = lastRun ? ` | last run: ${new Date(lastRun).toLocaleString()}` : "";
  manualXSSStatus.textContent = running ? `running: ${status}${lastRunText}` : `${status}${lastRunText}`;
}

function applyManualXSSRunnerAvailability(running = false) {
  const hasSelectedDomain = Boolean(selectedManualDomain());
  const runnerEnabled = manualDomainsReady && hasSelectedDomain;

  if (manualXSSRunner) {
    manualXSSRunner.classList.toggle("manual-xss-runner--disabled", !manualDomainsReady);
  }
  if (manualAuthHeader) {
    manualAuthHeader.disabled = !manualDomainsReady || running;
  }
  if (manualRunXSS) {
    manualRunXSS.disabled = running || !runnerEnabled;
    manualRunXSS.textContent = running ? "Playwright running..." : "Launch Playwright XSS";
  }
  if (manualXSSStatus && !manualDomainsReady && !running) {
    manualXSSStatus.textContent = "Disabled until domains list is populated.";
  }
}

async function refreshManualXSSStatus() {
  if (!manualXSSStatus) {
    return;
  }
  try {
    const res = await fetch(`${BACKEND_URL}/api/manual/xss/status`);
    if (!res.ok) {
      throw new Error(await res.text());
    }
    const data = await res.json();
    updateManualXSSStatusText(data);
    applyManualXSSRunnerAvailability(Boolean(data.running));
  } catch (error) {
    manualXSSStatus.textContent = `status error: ${error.message}`;
  }
}

function renderHybridChecklist() {
  if (!hybridChecklistList || !hybridChecklistProgress) {
    return;
  }

  const selected = selectedManualDomain();
  if (!selected) {
    hybridChecklistList.innerHTML = '<p class="muted">Select a domain to track hybrid checks.</p>';
    hybridChecklistProgress.textContent = "0 / 0 done";
    return;
  }

  const host = domainFromURL(normalizeDomainEntry(selected));
  const state = loadHybridChecklistState();
  const domainState = state[host] || {};
  let done = 0;

  hybridChecklistList.innerHTML = HYBRID_MANUAL_CHECKLIST_ITEMS.map((item) => {
    const checked = Boolean(domainState[item.id]);
    if (checked) {
      done += 1;
    }
    return `
      <label class="manual-checklist-item">
        <input type="checkbox" data-hybrid-item-id="${escapeHTML(item.id)}" ${checked ? "checked" : ""} />
        <span>${escapeHTML(item.label)}</span>
      </label>
    `;
  }).join("");

  hybridChecklistProgress.textContent = `${done} / ${HYBRID_MANUAL_CHECKLIST_ITEMS.length} done`;
}

function populateManualDomainSelect(options) {
  if (!manualDomainSelect) {
    return;
  }
  const current = manualDomainSelect.value;
  const normalized = [...new Set((options || []).map((entry) => normalizeDomainEntry(entry)).filter(Boolean))];
  normalized.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  manualDomainOptions = normalized;
  manualDomainSelect.innerHTML = [
    '<option value="">Select domain...</option>',
    ...normalized.map((entry) => `<option value="${escapeHTML(entry)}">${escapeHTML(entry)}</option>`),
  ].join("");
  if (current && normalized.includes(current)) {
    manualDomainSelect.value = current;
  } else if (!manualDomainSelect.value && normalized.length > 0) {
    manualDomainSelect.value = normalized[0];
  }
  renderManualChecklist();
  renderHybridChecklist();
}

async function refreshManualDomainOptions() {
  const [liveData, domainsData] = await Promise.all([
    fetchLiveWebservers().catch(() => ({ present: false, rows: [] })),
    fetchListMeta("domains").catch(() => ({ present: false, entries: [] })),
  ]);
  const liveRows = Array.isArray(liveData.rows) ? liveData.rows : [];
  updateManualStatusFilterOptions(liveRows);
  const selectedStatus = selectedManualStatusFilter();
  const statusFilteredRows = selectedStatus
    ? liveRows.filter((row) => String(row.status_code || "").trim() === selectedStatus)
    : liveRows;
  const options = [];
  if (statusFilteredRows.length > 0) {
    options.push(...statusFilteredRows.map((row) => row.url).filter(Boolean));
  }
  if (Array.isArray(domainsData.entries) && domainsData.entries.length > 0) {
    options.push(...domainsData.entries.map((entry) => normalizeDomainEntry(entry)));
  }
  manualDomainsReady = Array.isArray(domainsData.entries) && domainsData.entries.length > 0;
  const signature = [...new Set(options.map((entry) => normalizeDomainEntry(entry)).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }))
    .join("|");
  const lastSignature = manualDomainOptions.join("|");
  if (signature !== lastSignature) {
    populateManualDomainSelect(options);
  } else {
    renderManualChecklist();
    renderHybridChecklist();
    applyManualXSSRunnerAvailability(false);
  }
  void refreshManualXSSStatus();
}

function initializeManualDomainChecklist() {
  if (!manualDomainSelect || !manualChecklistList) {
    return;
  }
  applyManualXSSRunnerAvailability(false);
  manualDomainSelect.addEventListener("change", () => {
    renderManualChecklist();
    renderHybridChecklist();
    void refreshManualXSSStatus();
  });
  manualDomainStatusFilter?.addEventListener("change", () => {
    void refreshManualDomainOptions();
  });

  manualChecklistList.addEventListener("change", (event) => {
    const input = event.target.closest("input[type='checkbox'][data-manual-item-id]");
    if (!input) {
      return;
    }
    const selected = selectedManualDomain();
    if (!selected) {
      return;
    }
    const host = domainFromURL(selected);
    const itemID = input.dataset.manualItemId;
    if (!itemID) {
      return;
    }
    const state = loadManualDomainChecklistState();
    state[host] = state[host] || {};
    state[host][itemID] = Boolean(input.checked);
    saveManualDomainChecklistState(state);
    renderManualChecklist();
  });

  hybridChecklistList?.addEventListener("change", (event) => {
    const input = event.target.closest("input[type='checkbox'][data-hybrid-item-id]");
    if (!input) {
      return;
    }
    const selected = selectedManualDomain();
    if (!selected) {
      return;
    }
    const host = domainFromURL(normalizeDomainEntry(selected));
    const itemID = input.dataset.hybridItemId || "";
    if (!itemID) {
      return;
    }
    const state = loadHybridChecklistState();
    if (!state[host]) {
      state[host] = {};
    }
    state[host][itemID] = Boolean(input.checked);
    saveHybridChecklistState(state);
    renderHybridChecklist();
  });

  manualRunXSS?.addEventListener("click", async () => {
    if (!manualDomainsReady) {
      if (manualXSSStatus) {
        manualXSSStatus.textContent = "Disabled until domains list is populated.";
      }
      applyManualXSSRunnerAvailability(false);
      return;
    }
    const target = selectedManualDomain();
    if (!target) {
      if (manualXSSStatus) {
        manualXSSStatus.textContent = "Select a target domain first.";
      }
      return;
    }
    const authHeader = (manualAuthHeader?.value || "").trim();
    if (manualRunXSS) {
      manualRunXSS.disabled = true;
      manualRunXSS.textContent = "Launching...";
    }
    if (manualXSSStatus) {
      manualXSSStatus.textContent = "queued";
    }
    try {
      const response = await fetch(`${BACKEND_URL}/api/manual/xss/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: normalizeDomainEntry(target), auth_header: authHeader }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      await refreshManualXSSStatus();
    } catch (error) {
      if (manualXSSStatus) {
        manualXSSStatus.textContent = `launch failed: ${error.message}`;
      }
      if (manualRunXSS) {
        manualRunXSS.disabled = !manualDomainsReady || !selectedManualDomain();
        manualRunXSS.textContent = "Launch Playwright XSS";
      }
    }
  });

  void refreshManualDomainOptions();
  void refreshManualXSSStatus();
}

runButton?.addEventListener("click", async () => {
  flowStatus.textContent = "requesting run...";
  if (torRouteToggle?.checked && torNetworkIndicator) {
    torNetworkIndicator.classList.remove("tor-indicator--ok", "tor-indicator--error");
    torNetworkIndicator.textContent = "Checking Tor egress...";
  }
  try {
    const response = await fetch(`${BACKEND_URL}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    flowStatus.textContent = "Flow queued";
    await loadNetworkSettings();
  } catch (error) {
    flowStatus.textContent = `Run failed: ${error.message}`;
  }
});

async function postFlowAction(path) {
  const response = await fetch(`${BACKEND_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  try {
    return await response.json();
  } catch {
    return {};
  }
}

pauseButton?.addEventListener("click", async () => {
  flowStatus.textContent = "requesting pause...";
  try {
    await postFlowAction("/api/run/pause");
    flowStatus.textContent = "Pause requested";
  } catch (error) {
    flowStatus.textContent = `Pause failed: ${error.message}`;
  }
});

stopButton?.addEventListener("click", async () => {
  flowStatus.textContent = "requesting stop...";
  try {
    await postFlowAction("/api/run/stop");
    flowStatus.textContent = "Stop requested";
  } catch (error) {
    flowStatus.textContent = `Stop failed: ${error.message}`;
  }
});

clearResultsButton?.addEventListener("click", async () => {
  flowStatus.textContent = "clearing results...";
  try {
    await postFlowAction("/api/run/clear");
    flowStatus.textContent = "Results cleared";
    await Promise.all([
      refreshScopeCards(),
      refreshSubdomainProgress(),
      refreshAmassEnum({ renderOnlyIfOpen: false }),
      refreshLiveWebservers({ renderOnlyIfOpen: false }),
      refreshSteps(),
      refreshStatus(),
    ]);
  } catch (error) {
    flowStatus.textContent = `Clear failed: ${error.message}`;
  }
});

async function fetchListMeta(type) {
  const response = await fetch(`${BACKEND_URL}/api/list?type=${encodeURIComponent(type)}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }

  const data = await response.json();
  if (Array.isArray(data.entries)) {
    const present = typeof data.present === "boolean" ? data.present : data.entries.length > 0;
    return { present, entries: data.entries };
  }

  return { present: false, entries: [] };
}

async function handleScopeUpload(type, file) {
  if (!file) {
    return;
  }

  const formData = new FormData();
  formData.append("list_type", type);
  formData.append("file", file);

  if (scopeCardsStatus) {
    scopeCardsStatus.textContent = `Uploading ${file.name} to ${type}...`;
  }

  const response = await fetch(`${BACKEND_URL}/api/upload`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  await Promise.all([
    refreshScopeCards(),
  ]);

  if (scopeCardsStatus) {
    scopeCardsStatus.textContent = `Uploaded ${file.name} to ${type}`;
  }
}

function initializeScopeCards() {
  if (!scopeCards) {
    return;
  }

  const renderCard = ({ type, label, uploadable }) => {
    const inputId = `scope-upload-${type}`;

    return `
      <article class="scope-card" data-type="${escapeHTML(type)}">
        <h3 class="scope-card__name"><button type="button" class="scope-card__open" data-type="${escapeHTML(type)}" data-label="${escapeHTML(label)}" data-base-label="${escapeHTML(label)}">${escapeHTML(label)} (0)</button></h3>
        <span class="scope-card__status scope-card__status--missing">Missing</span>
        ${uploadable ? `<input id="${inputId}" type="file" accept=".txt,.csv" />` : ""}
        ${uploadable ? `<button type="button" class="scope-card__upload" data-input-id="${inputId}">Upload</button>` : '<p class="muted">Auto-generated by flow.</p>'}
      </article>
    `;
  };

  const uploadableCards = LIST_FILES.filter((item) => item.uploadable).map(renderCard).join("");
  const generatedCards = LIST_FILES.filter((item) => !item.uploadable).map(renderCard).join("");

  scopeCards.innerHTML = `
    <section class="scope-group">
      <h3 class="scope-group__title">Manual / Uploadable</h3>
      <div class="scope-group__grid">
        ${uploadableCards}
      </div>
    </section>
    <details class="scope-group scope-group--generated">
      <summary class="scope-group__summary">Auto-generated</summary>
      <div class="scope-group__grid">
        ${generatedCards}
      </div>
    </details>
  `;

  scopeCards.querySelectorAll(".scope-card").forEach((card) => {
    const type = card.dataset.type;
    if (!type) {
      return;
    }
    scopeCardNodes.set(type, {
      card,
      open: card.querySelector(".scope-card__open"),
      status: card.querySelector(".scope-card__status"),
      input: card.querySelector("input[type='file']"),
    });
  });

  scopeCards.addEventListener("click", (event) => {
    const openButton = event.target.closest(".scope-card__open");
    if (openButton) {
      const type = openButton.dataset.type;
      const label = openButton.dataset.label || type || "Scope File";
      if (type) {
        void openScopeFileModal(type, label);
      }
      return;
    }
    const button = event.target.closest(".scope-card__upload");
    if (!button) {
      return;
    }
    const inputId = button.dataset.inputId;
    const input = document.getElementById(inputId);
    input?.click();
  });

  scopeCards.addEventListener("change", async (event) => {
    const input = event.target.closest(".scope-card input[type='file']");
    if (!input) {
      return;
    }
    const card = input.closest(".scope-card");
    const type = card?.dataset.type;
    const [file] = input.files || [];
    if (!type || !file) {
      return;
    }

    try {
      await handleScopeUpload(type, file);
    } catch (error) {
      if (scopeCardsStatus) {
        scopeCardsStatus.textContent = `Upload failed: ${error.message}`;
      }
    } finally {
      input.value = "";
    }
  });
}

async function openScopeFileModal(type, label) {
  if (!fileViewerModal || !fileViewerContent || !fileViewerTitle) {
    return;
  }
  currentFileModalType = type || "";
  currentFileModalLabel = label || type || "file";
  currentFileModalLines = [];
  fileViewerTitle.textContent = label;
  fileViewerContent.textContent = "Loading...";
  fileViewerModal.hidden = false;
  try {
    const data = await fetchListMeta(type);
    if (!data.present) {
      fileViewerContent.textContent = "File missing.";
      return;
    }
    currentFileModalLines = Array.isArray(data.entries) ? data.entries : [];
    fileViewerContent.textContent = data.entries && data.entries.length
      ? data.entries.join("\n")
      : "No entries yet.";
  } catch (error) {
    fileViewerContent.textContent = `Error: ${error.message}`;
  }
}

function updateScopeCards(states) {
  const signature = LIST_FILES
    .map(({ type }) => `${type}:${states[type]?.present ? "1" : "0"}:${states[type]?.entries?.length || 0}`)
    .join("|");
  if (signature === lastScopeSignature) {
    return false;
  }
  lastScopeSignature = signature;

  LIST_FILES.forEach(({ type }) => {
    const node = scopeCardNodes.get(type);
    if (!node || !node.status) {
      return;
    }
    const count = Array.isArray(states[type]?.entries) ? states[type].entries.length : 0;
    const present = Boolean(states[type]?.present);
    if (node.open) {
      const baseLabel = node.open.dataset.baseLabel || node.open.dataset.label || type;
      node.open.textContent = `${baseLabel} (${count})`;
    }
    node.status.textContent = present ? "Present" : "Missing";
    node.status.classList.toggle("scope-card__status--present", present);
    node.status.classList.toggle("scope-card__status--missing", !present);
  });

  return true;
}

async function fetchLiveWebservers() {
  const response = await fetch(`${BACKEND_URL}/api/live-webservers`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

async function fetchAmassEnum() {
  const response = await fetch(`${BACKEND_URL}/api/amass-enum`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

async function fetchSubdomainProgress() {
  const response = await fetch(`${BACKEND_URL}/api/progress/subdomain`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

async function fetchNetworkSettings() {
  const response = await fetch(`${BACKEND_URL}/api/network`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

async function updateNetworkSettings(payload) {
  const response = await fetch(`${BACKEND_URL}/api/network`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

function renderSubdomainProgress(data) {
  if (!subdomainProgressBar || !subdomainProgressText) {
    return;
  }
  const total = Number(data?.total_wildcards || 0);
  const done = Number(data?.overall_done || 0);
  const percent = Number(data?.overall_percent || 0);
  subdomainProgressBar.value = Math.max(0, Math.min(100, percent));
  subdomainProgressText.textContent = `${done} / ${total} (${percent}%)`;
}

async function refreshSubdomainProgress() {
  try {
    const data = await fetchSubdomainProgress();
    renderSubdomainProgress(data);
  } catch {
    if (subdomainProgressBar) {
      subdomainProgressBar.value = 0;
    }
    if (subdomainProgressText) {
      subdomainProgressText.textContent = "0 / 0";
    }
  }
}

async function fetchLeads() {
  const response = await fetch(`${BACKEND_URL}/api/leads`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

function severityPillClass(severity) {
  const normalized = normalizeFilterValue(severity);
  if (normalized === "high" || normalized === "critical") {
    return "lead-severity--high";
  }
  if (normalized === "medium") {
    return "lead-severity--medium";
  }
  return "lead-severity--low";
}

function renderLeads(data) {
  if (!leadsStatus || !leadsSummary || !leadsWildcards) {
    return;
  }

  const wildcards = Array.isArray(data?.wildcards) ? data.wildcards : [];
  const updated = data?.updated_at ? `Last update: ${data.updated_at}` : "No findings yet.";
  leadsStatus.textContent = updated;
  leadsSummary.innerHTML = `
    <div class="lead-summary-card">
      <span class="muted">Total Leads</span>
      <strong>${escapeHTML(String(data?.total_leads || 0))}</strong>
    </div>
    <div class="lead-summary-card">
      <span class="muted">Total ROI</span>
      <strong>${escapeHTML(String(data?.total_roi || 0))}</strong>
    </div>
    <div class="lead-summary-card">
      <span class="muted">Wildcards</span>
      <strong>${escapeHTML(String(wildcards.length))}</strong>
    </div>
  `;

  if (!wildcards.length) {
    leadsWildcards.innerHTML = '<p class="muted">No leads found yet. Run the flow to populate semi-automated findings.</p>';
    return;
  }

  leadsWildcards.innerHTML = wildcards.map((wc) => {
    const domains = Array.isArray(wc.domains) ? wc.domains : [];
    const domainHtml = domains.map((domain) => {
      const leads = Array.isArray(domain.leads) ? domain.leads : [];
      const leadsHtml = leads.map((lead) => `
        <article class="lead-item">
          <div class="lead-item__top">
            <span class="lead-roi">ROI ${escapeHTML(String(lead.roi || 0))}</span>
            <span class="lead-severity ${severityPillClass(lead.severity)}">${escapeHTML((lead.severity || "low").toUpperCase())}</span>
            <span class="lead-category">${escapeHTML(lead.category || "unknown")}${lead.family ? `/${escapeHTML(lead.family)}` : ""}</span>
          </div>
          <div class="lead-item__target"><code>${escapeHTML(lead.target || "")}</code></div>
          ${Array.isArray(lead.reasons) && lead.reasons.length ? `<div class="lead-item__reasons">${lead.reasons.slice(0, 4).map((reason) => `<span>${escapeHTML(reason)}</span>`).join("")}</div>` : ""}
          ${lead.manual_action ? `<p class="muted">${escapeHTML(lead.manual_action)}</p>` : ""}
        </article>
      `).join("");
      return `
        <details class="lead-domain-card" open>
          <summary>
            <span><strong>${escapeHTML(domain.domain || "")}</strong></span>
            <span class="lead-domain-meta">ROI ${escapeHTML(String(domain.roi || 0))} | Leads ${escapeHTML(String(domain.lead_count || 0))} | H:${escapeHTML(String(domain.high_count || 0))} M:${escapeHTML(String(domain.medium_count || 0))} L:${escapeHTML(String(domain.low_count || 0))}</span>
          </summary>
          <div class="lead-domain-items">${leadsHtml}</div>
        </details>
      `;
    }).join("");

    return `
      <section class="lead-wildcard-card">
        <h3>${escapeHTML(wc.wildcard || "(unmapped)")}</h3>
        <p class="muted">ROI ${escapeHTML(String(wc.roi || 0))} | Domains ${escapeHTML(String(wc.domain_count || 0))} | Leads ${escapeHTML(String(wc.lead_count || 0))}</p>
        <div class="lead-domain-list">${domainHtml}</div>
      </section>
    `;
  }).join("");
}

async function refreshLeads(options = {}) {
  if (!leadsStatus || !leadsSummary || !leadsWildcards) {
    return;
  }
  try {
    const data = await fetchLeads();
    const signature = JSON.stringify({
      total_leads: data?.total_leads || 0,
      total_roi: data?.total_roi || 0,
      updated_at: data?.updated_at || "",
      wildcards: (data?.wildcards || []).map((wc) => ({
        wildcard: wc.wildcard,
        roi: wc.roi,
        lead_count: wc.lead_count,
        domain_count: wc.domain_count,
      })),
    });
    if (!options.force && signature === lastLeadsSignature) {
      return;
    }
    lastLeadsSignature = signature;
    renderLeads(data);
  } catch (error) {
    leadsStatus.textContent = `Leads fetch error: ${error.message}`;
  }
}

function updateAmassEnumButton(present, count) {
  if (!openAmassEnum) {
    return;
  }
  openAmassEnum.disabled = !present;
  openAmassEnum.textContent = present ? `Amass Enum (${count})` : "Amass Enum";
}

function updateLiveWebserversButton(present, count) {
  if (!openLiveWebservers) {
    return;
  }
  openLiveWebservers.disabled = !present;
  openLiveWebservers.textContent = present ? `Live Web Servers (${count})` : "Live Web Servers";
}

function normalizeFilterValue(v) {
  return (v || "").toString().toLowerCase().trim();
}

function liveStatusClass(statusCode) {
  const code = Number(statusCode) || 0;
  if (code >= 200 && code < 300) {
    return "lws-status--2xx";
  }
  if (code >= 300 && code < 400) {
    return "lws-status--3xx";
  }
  if (code >= 400 && code < 500) {
    return "lws-status--4xx";
  }
  if (code >= 500 && code < 600) {
    return "lws-status--5xx";
  }
  return "";
}

function liveStatusRowClass(statusCode) {
  const statusClass = liveStatusClass(statusCode);
  return statusClass ? `lws-row ${statusClass}` : "";
}

function getFilteredSortedAmassRows() {
  const nameNeedle = normalizeFilterValue(amassSearchName?.value);
  const domainNeedle = normalizeFilterValue(amassSearchDomain?.value);
  const ipNeedle = normalizeFilterValue(amassSearchIP?.value);

  const filtered = (amassRows || []).filter((row) => (
    (!nameNeedle || normalizeFilterValue(row.name).includes(nameNeedle)) &&
    (!domainNeedle || normalizeFilterValue(row.domain).includes(domainNeedle)) &&
    (!ipNeedle || normalizeFilterValue(row.ip).includes(ipNeedle))
  ));

  filtered.sort((a, b) => {
    const dir = amassSortDir === "asc" ? 1 : -1;
    const av = a[amassSortKey];
    const bv = b[amassSortKey];
    if (typeof av === "number" || typeof bv === "number") {
      return ((Number(av) || 0) - (Number(bv) || 0)) * dir;
    }
    return String(av || "").localeCompare(String(bv || ""), undefined, { sensitivity: "base" }) * dir;
  });
  return filtered;
}

function renderAmassTable() {
  if (!amassTableBody || !amassCount) {
    return;
  }
  const filtered = getFilteredSortedAmassRows();

  amassCount.textContent = `Showing ${filtered.length} of ${amassRows.length} rows`;
  amassTableBody.innerHTML = filtered.map((row) => `
    <tr>
      <td><code>${escapeHTML(row.name || "")}</code></td>
      <td>${escapeHTML(row.domain || "")}</td>
      <td>${escapeHTML(row.ip || "")}</td>
      <td>${escapeHTML(String(row.asn || ""))}</td>
    </tr>
  `).join("");
}

function renderLiveWebserversTable() {
  if (!lwsTableBody || !lwsCount) {
    return;
  }
  const urlNeedle = normalizeFilterValue(lwsSearchURL?.value);
  const statusNeedle = normalizeFilterValue(lwsFilterStatus?.value);
  const titleNeedle = normalizeFilterValue(lwsSearchTitle?.value);
  const webNeedle = normalizeFilterValue(lwsSearchWebServer?.value);
  const techNeedle = normalizeFilterValue(lwsSearchTech?.value);

  const filtered = liveWebserverRows.filter((row) => {
    const statusText = `${row.status_code || ""}`;
    const techText = (row.technologies || []).join(" ").toLowerCase();
    return (
      (!urlNeedle || normalizeFilterValue(row.url).includes(urlNeedle)) &&
      (!statusNeedle || statusText === statusNeedle) &&
      (!titleNeedle || normalizeFilterValue(row.title).includes(titleNeedle)) &&
      (!webNeedle || normalizeFilterValue(row.web_server).includes(webNeedle)) &&
      (!techNeedle || techText.includes(techNeedle))
    );
  });

  filtered.sort((a, b) => {
    const dir = lwsSortDir === "asc" ? 1 : -1;
    const av = a[lwsSortKey];
    const bv = b[lwsSortKey];
    if (typeof av === "number" || typeof bv === "number") {
      return ((Number(av) || 0) - (Number(bv) || 0)) * dir;
    }
    return String(av || "").localeCompare(String(bv || ""), undefined, { sensitivity: "base" }) * dir;
  });

  lwsCount.textContent = `Showing ${filtered.length} of ${liveWebserverRows.length} rows`;
  lwsTableBody.innerHTML = filtered.map((row) => `
      <tr class="${liveStatusRowClass(row.status_code)}">
        <td><a href="${escapeHTML(row.url || "")}" target="_blank" rel="noopener noreferrer"><code>${escapeHTML(row.url || "")}</code></a></td>
        <td>${escapeHTML(String(row.status_code || ""))}</td>
        <td>${escapeHTML(row.title || "")}</td>
        <td>${escapeHTML(row.web_server || "")}</td>
        <td>${escapeHTML((row.technologies || []).join(", "))}</td>
        <td>${escapeHTML(String(row.content_length || ""))}</td>
      </tr>
    `).join("");
}

async function refreshAmassEnum(options = {}) {
  try {
    const data = await fetchAmassEnum();
    updateAmassEnumButton(Boolean(data.present), Number(data.count || 0));
    if (!options.renderOnlyIfOpen || (amassEnumModal && !amassEnumModal.hidden)) {
      amassRows = Array.isArray(data.rows) ? data.rows : [];
      renderAmassTable();
    }
  } catch {
    updateAmassEnumButton(false, 0);
  }
}

async function refreshLiveWebservers(options = {}) {
  try {
    const data = await fetchLiveWebservers();
    updateLiveWebserversButton(Boolean(data.present), Number(data.count || 0));
    if (!options.renderOnlyIfOpen || (liveWebserversModal && !liveWebserversModal.hidden)) {
      liveWebserverRows = Array.isArray(data.rows) ? data.rows : [];
      if (lwsFilterStatus) {
        const statuses = [...new Set(liveWebserverRows.map((r) => `${r.status_code || ""}`).filter((s) => s))];
        statuses.sort((a, b) => Number(a) - Number(b));
        const current = lwsFilterStatus.value;
        lwsFilterStatus.innerHTML = `<option value="">All status codes</option>${statuses.map((s) => `<option value="${escapeHTML(s)}">${escapeHTML(s)}</option>`).join("")}`;
        if (statuses.includes(current)) {
          lwsFilterStatus.value = current;
        }
      }
      renderLiveWebserversTable();
    }
  } catch {
    updateLiveWebserversButton(false, 0);
  }
}

openAmassEnum?.addEventListener("click", async () => {
  if (amassEnumModal) {
    amassEnumModal.hidden = false;
  }
  await refreshAmassEnum();
});

closeAmassEnum?.addEventListener("click", () => {
  if (amassEnumModal) {
    amassEnumModal.hidden = true;
  }
});

exportAmassEnum?.addEventListener("click", () => {
  const rows = getFilteredSortedAmassRows();
  const header = "host,domain,ip,asn";
  const csvRows = rows.map((row) => {
    const cols = [row.name || "", row.domain || "", row.ip || "", String(row.asn || "")];
    return cols.map((col) => {
      const text = String(col);
      if (text.includes(",") || text.includes("\"") || text.includes("\n")) {
        return `"${text.replace(/\"/g, "\"\"")}"`;
      }
      return text;
    }).join(",");
  });
  const csv = [header, ...csvRows].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `amass_enum_${Date.now()}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});

closeFileViewer?.addEventListener("click", () => {
  if (fileViewerModal) {
    fileViewerModal.hidden = true;
  }
});

exportFileViewer?.addEventListener("click", async () => {
  const type = currentFileModalType;
  if (!type) {
    return;
  }
  try {
    const data = await fetchListMeta(type);
    const lines = Array.isArray(data.entries) ? data.entries : currentFileModalLines;
    const text = lines.length ? lines.join("\n") : "";
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const base = (currentFileModalLabel || type || "export")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "");
    anchor.href = url;
    anchor.download = `${base || "export"}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    fileViewerContent.textContent = `Export failed: ${error.message}`;
  }
});

fileViewerModal?.addEventListener("click", (event) => {
  if (event.target === fileViewerModal) {
    fileViewerModal.hidden = true;
  }
});

amassEnumModal?.addEventListener("click", (event) => {
  if (event.target === amassEnumModal) {
    amassEnumModal.hidden = true;
  }
});

openLiveWebservers?.addEventListener("click", async () => {
  if (liveWebserversModal) {
    liveWebserversModal.hidden = false;
  }
  await refreshLiveWebservers();
});

closeLiveWebservers?.addEventListener("click", () => {
  if (liveWebserversModal) {
    liveWebserversModal.hidden = true;
  }
});

liveWebserversModal?.addEventListener("click", (event) => {
  if (event.target === liveWebserversModal) {
    liveWebserversModal.hidden = true;
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && fileViewerModal && !fileViewerModal.hidden) {
    fileViewerModal.hidden = true;
  }
  if (event.key === "Escape" && amassEnumModal && !amassEnumModal.hidden) {
    amassEnumModal.hidden = true;
  }
  if (event.key === "Escape" && liveWebserversModal && !liveWebserversModal.hidden) {
    liveWebserversModal.hidden = true;
  }
});

[amassSearchName, amassSearchDomain, amassSearchIP].forEach((el) => {
  el?.addEventListener("input", renderAmassTable);
  el?.addEventListener("change", renderAmassTable);
});

[...document.querySelectorAll(".lws-table th[data-amass-sort-key]")].forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.amassSortKey;
    if (!key) {
      return;
    }
    if (amassSortKey === key) {
      amassSortDir = amassSortDir === "asc" ? "desc" : "asc";
    } else {
      amassSortKey = key;
      amassSortDir = "asc";
    }
    renderAmassTable();
  });
});

[lwsSearchURL, lwsFilterStatus, lwsSearchTitle, lwsSearchWebServer, lwsSearchTech].forEach((el) => {
  el?.addEventListener("input", renderLiveWebserversTable);
  el?.addEventListener("change", renderLiveWebserversTable);
});

document.querySelectorAll(".lws-table th[data-sort-key]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sortKey;
    if (!key) {
      return;
    }
    if (lwsSortKey === key) {
      lwsSortDir = lwsSortDir === "asc" ? "desc" : "asc";
    } else {
      lwsSortKey = key;
      lwsSortDir = "asc";
    }
    renderLiveWebserversTable();
  });
});

async function refreshScopeCards() {
  if (!scopeCards) {
    return;
  }

  const states = {};
  await Promise.all(
    LIST_FILES.map(async ({ type }) => {
      try {
        states[type] = await fetchListMeta(type);
      } catch {
        states[type] = { present: false, entries: [] };
      }
    }),
  );

  const changed = updateScopeCards(states);
  if (scopeCardsStatus && changed) {
    scopeCardsStatus.textContent = "File status updated";
  }
}

async function refreshStatus() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/status`);
    if (!res.ok) {
      throw new Error("failed to read status");
    }
    const data = await res.json();
    const statusText = data.running
      ? `running (${data.status})`
      : data.status;
    if (statusText !== lastStatusText) {
      flowStatus.textContent = statusText;
      lastStatusText = statusText;
    }
  } catch (error) {
    const statusText = `status error: ${error.message}`;
    if (statusText !== lastStatusText) {
      flowStatus.textContent = statusText;
      lastStatusText = statusText;
    }
  }
}

refreshStatus();
setInterval(refreshStatus, 5000);
refreshSubdomainProgress();
setInterval(refreshSubdomainProgress, 4000);

function stepPrefix(status) {
  switch (status) {
    case "done":
      return "[x]";
    case "running":
      return "[>]";
    case "error":
      return "[!]";
    case "skipped":
      return "[-]";
    default:
      return "[ ]";
  }
}

async function refreshSteps() {
  if (!flowStepsList) {
    return;
  }
  try {
    const res = await fetch(`${BACKEND_URL}/api/steps`);
    const bodyText = await res.text();
    if (!res.ok) {
      throw new Error(bodyText || `status ${res.status}`);
    }
    let data;
    try {
      data = bodyText ? JSON.parse(bodyText) : {};
    } catch {
      throw new Error(`non-JSON response from ${BACKEND_URL}/api/steps`);
    }
    const steps = data.steps ?? [];
    const signature = steps.map((step) => `${step.id}:${step.status || "pending"}`).join("|");
    if (signature === lastStepsSignature) {
      return;
    }
    lastStepsSignature = signature;

    const stepMap = new Map(steps.map((step) => [step.id, step]));
    flowStepsList.innerHTML = FLOW_SEGMENTS.map((segment) => {
      const itemsHtml = segment.items.map((item) => {
        if (!item.implemented) {
          return `<li class="flow-step flow-step--not-implemented"><span class="flow-step__status">[ ]</span><span class="flow-step__label flow-step__label--not-implemented">${escapeHTML(item.label)} (Not Implemented)</span></li>`;
        }
        if (!item.stepId) {
          return `<li class="flow-step flow-step--completed"><span class="flow-step__status">[x]</span><span class="flow-step__label">${escapeHTML(item.label)}</span></li>`;
        }
        const step = stepMap.get(item.stepId);
        if (!step) {
          return `<li class="flow-step flow-step--manual"><span class="flow-step__status">[~]</span><span class="flow-step__label">${escapeHTML(item.label)}</span></li>`;
        }
        const status = step?.status || "pending";
        const prefix = stepPrefix(status);
        const safeLabel = item.label || step?.label || item.stepId || "step";
        return `<li class="flow-step flow-step--${status}"><span class="flow-step__status">${prefix}</span><span class="flow-step__label">${escapeHTML(safeLabel)}</span></li>`;
      }).join("");

      return `<li class="flow-segment"><details open><summary class="flow-segment__title">${escapeHTML(segment.title)}</summary><ul class="flow-segment__items">${itemsHtml}</ul></details></li>`;
    }).join("");
  } catch (error) {
    const signature = `error:${error.message}`;
    if (signature !== lastStepsSignature) {
      lastStepsSignature = signature;
      flowStepsList.innerHTML = `<li class="flow-step flow-step--error">[!] Failed to load steps: ${escapeHTML(error.message)}</li>`;
    }
  }
}

refreshSteps();
setInterval(refreshSteps, 3000);

async function loadConfig() {
  if (!githubKeysList) {
    return;
  }
  githubKeysList.textContent = "Loading keys...";
  try {
    const res = await fetch(`${BACKEND_URL}/api/config`);
    if (!res.ok) {
      throw new Error(await res.text());
    }
    const data = await res.json();
    const provider = data.providers?.github ?? { auto_run: true, keys: [] };
    githubAutoRun.checked = provider.auto_run ?? true;
    renderGithubKeys(provider.keys ?? []);
  } catch (error) {
    githubKeysList.textContent = `Failed to load config: ${error.message}`;
  }
}

function renderGithubKeys(keys) {
  if (!githubKeysList) {
    return;
  }
  if (!keys.length) {
    githubKeysList.innerHTML = '<p class="muted">No keys yet.</p>';
    return;
  }

  githubKeysList.innerHTML = keys
    .map((key) => {
      const safeLabel = key.label ?? "";
      const safeValue = key.value ?? "";
      const checked = key.active ? "checked" : "";
      return `
        <div class="config-row" data-key-id="${key.id}">
          <input type="text" value="${escapeHTML(safeLabel)}" class="config-label" />
          <input type="password" value="${escapeHTML(safeValue)}" class="config-value" />
          <label class="inline">
            <input type="checkbox" class="config-active" ${checked} />
            Active
          </label>
          <div class="config-actions">
            <button class="config-save" type="button">Save</button>
            <button class="config-delete" type="button">Remove</button>
          </div>
        </div>
      `;
    })
    .join("");
}

githubKeyAdd?.addEventListener("click", async () => {
  const label = githubKeyLabel.value.trim();
  const value = githubKeyValue.value.trim();
  const active = githubKeyActive.checked;
  if (!value) {
    githubKeysList.textContent = "Token value is required.";
    return;
  }
  try {
    const res = await fetch(`${BACKEND_URL}/api/config/providers/github/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, value, active }),
    });
    if (!res.ok) {
      throw new Error(await res.text());
    }
    githubKeyLabel.value = "";
    githubKeyValue.value = "";
    githubKeyActive.checked = true;
    await loadConfig();
  } catch (error) {
    githubKeysList.textContent = `Failed to add key: ${error.message}`;
  }
});

githubAutoRun?.addEventListener("change", async () => {
  try {
    const res = await fetch(`${BACKEND_URL}/api/config/providers/github/settings`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_run: githubAutoRun.checked }),
    });
    if (!res.ok) {
      throw new Error(await res.text());
    }
  } catch (error) {
    githubKeysList.textContent = `Failed to update auto-run: ${error.message}`;
  }
});

async function loadNetworkSettings() {
  if (!torRouteToggle) {
    return;
  }
  try {
    const data = await fetchNetworkSettings();
    torRouteToggle.checked = Boolean(data.tor_enabled);
    renderNetworkIndicator(data);
  } catch {
    torRouteToggle.checked = false;
    renderNetworkIndicator({ tor_enabled: false, probe_error: "Network status unavailable" });
  }
}

function renderNetworkIndicator(data) {
  if (!torNetworkIndicator) {
    return;
  }
  torNetworkIndicator.classList.remove("tor-indicator--ok", "tor-indicator--error");
  const torOn = Boolean(data?.tor_enabled);
  if (!torOn) {
    torNetworkIndicator.textContent = "Tor off";
    return;
  }
  const ip = String(data?.probe_ip || "").trim();
  const error = String(data?.probe_error || "").trim();
  const probeAtRaw = String(data?.probe_at || "").trim();
  const probeAt = probeAtRaw ? new Date(probeAtRaw).toLocaleTimeString() : "";
  if (ip) {
    torNetworkIndicator.classList.add("tor-indicator--ok");
    torNetworkIndicator.textContent = probeAt ? `Tor IP: ${ip} (${probeAt})` : `Tor IP: ${ip}`;
    return;
  }
  if (error) {
    torNetworkIndicator.classList.add("tor-indicator--error");
    torNetworkIndicator.textContent = `Tor check failed: ${error}`;
    return;
  }
  torNetworkIndicator.textContent = "Checking Tor egress...";
}

torRouteToggle?.addEventListener("change", async () => {
  try {
    await updateNetworkSettings({ tor_enabled: Boolean(torRouteToggle.checked) });
    await loadNetworkSettings();
  } catch (error) {
    torRouteToggle.checked = !torRouteToggle.checked;
    if (flowStatus) {
      flowStatus.textContent = `Network toggle failed: ${error.message}`;
    }
  }
});

githubKeysList?.addEventListener("click", async (event) => {
  const target = event.target;
  const row = target.closest(".config-row");
  if (!row) {
    return;
  }
  const keyId = row.dataset.keyId;
  if (target.classList.contains("config-delete")) {
    try {
      const res = await fetch(`${BACKEND_URL}/api/config/providers/github/keys/${keyId}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      await loadConfig();
    } catch (error) {
      githubKeysList.textContent = `Failed to remove key: ${error.message}`;
    }
  }
  if (target.classList.contains("config-save")) {
    const label = row.querySelector(".config-label").value.trim();
    const value = row.querySelector(".config-value").value.trim();
    const active = row.querySelector(".config-active").checked;
    try {
      const res = await fetch(`${BACKEND_URL}/api/config/providers/github/keys/${keyId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, value, active }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      await loadConfig();
    } catch (error) {
      githubKeysList.textContent = `Failed to update key: ${error.message}`;
    }
  }
});

loadConfig();
loadNetworkSettings();
setInterval(loadNetworkSettings, 8000);

async function refreshLogs() {
  if (!flowLogOutput) {
    return;
  }
  try {
    const res = await fetch(`${BACKEND_URL}/api/logs`);
    if (!res.ok) {
      throw new Error(await res.text());
    }
    const data = await res.json();
    const nextText = data.logs ? data.logs.join("\n") : "Waiting for logs...";
    if (nextText === lastLogsSignature) {
      return;
    }
    const shouldStickToBottom =
      flowLogOutput.scrollHeight - flowLogOutput.scrollTop - flowLogOutput.clientHeight < 16;
    flowLogOutput.innerHTML = ansiTextToHTML(nextText);
    lastLogsSignature = nextText;
    if (shouldStickToBottom) {
      flowLogOutput.scrollTop = flowLogOutput.scrollHeight;
    }
  } catch (error) {
    const nextText = `Log fetch error: ${error.message}`;
    if (nextText !== lastLogsSignature) {
      flowLogOutput.innerHTML = ansiTextToHTML(nextText);
      lastLogsSignature = nextText;
    }
  }
}

refreshLogs();
setInterval(refreshLogs, 3000);

initializeScopeCards();
refreshScopeCards();
setInterval(() => {
  refreshScopeCards();
}, 4000);
initializeManualDomainChecklist();
setInterval(() => {
  refreshManualDomainOptions();
}, 10000);
setInterval(() => {
  refreshManualXSSStatus();
}, 5000);
refreshAmassEnum({ renderOnlyIfOpen: false });
setInterval(() => {
  refreshAmassEnum({ renderOnlyIfOpen: true });
}, 5000);
refreshLiveWebservers({ renderOnlyIfOpen: false });
setInterval(() => {
  refreshLiveWebservers({ renderOnlyIfOpen: true });
}, 5000);
refreshLeads({ force: true });
setInterval(() => {
  refreshLeads({ force: false });
}, 7000);

renderStrideLearning();
loadStrideAnswer();
initializeManualRecon();
