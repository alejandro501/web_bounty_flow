const BACKEND_URL = document.body.dataset.backendUrl || "http://localhost:8080";

const runButton = document.getElementById("run-flow");
const flowStatus = document.getElementById("flow-status");
const listViewSelect = document.getElementById("list-view-select");
const listViewOutput = document.getElementById("list-view-output");
const flowLogOutput = document.getElementById("flow-log-output");
const flowStepsList = document.getElementById("flow-steps-list");
const menuItems = document.querySelectorAll(".menu-item");
const views = document.querySelectorAll(".view");
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
const openAmassEnum = document.getElementById("open-amass-enum");
const amassEnumModal = document.getElementById("amass-enum-modal");
const closeAmassEnum = document.getElementById("close-amass-enum");
const amassSearchName = document.getElementById("amass-search-name");
const amassSearchDomain = document.getElementById("amass-search-domain");
const amassSearchIP = document.getElementById("amass-search-ip");
const amassSearchSource = document.getElementById("amass-search-source");
const amassFilterTag = document.getElementById("amass-filter-tag");
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
const scopeCardNodes = new Map();

let lastStatusText = "";
let lastStepsSignature = "";
let lastLogsSignature = "";
let lastScopeSignature = "";
const lastListTextByType = {};

const LIST_FILES = [
  { type: "wildcards", label: "Wildcards", uploadable: true },
  { type: "domains", label: "Domains", uploadable: true },
  { type: "apidomains", label: "API Domains", uploadable: true },
  { type: "organizations", label: "Organizations", uploadable: true },
  { type: "ips", label: "IPs", uploadable: true },
  { type: "out_of_scope", label: "Out of scope", uploadable: true },
  { type: "live_webservers_csv", label: "Live Web Servers CSV", uploadable: false },
  { type: "fuzzing_doc_hits", label: "Fuzzing Doc Hits", uploadable: false },
  { type: "fuzzing_dir_hits", label: "Fuzzing Dir Hits", uploadable: false },
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

function hasSelectionInside(element) {
  if (!element || !window.getSelection) {
    return false;
  }
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
    return false;
  }
  const range = selection.getRangeAt(0);
  return element.contains(range.commonAncestorContainer);
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

runButton?.addEventListener("click", async () => {
  flowStatus.textContent = "requesting run...";
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
  } catch (error) {
    flowStatus.textContent = `Run failed: ${error.message}`;
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
    listViewSelect?.value ? refreshListEntries(listViewSelect.value, { force: true }) : Promise.resolve(),
  ]);

  if (scopeCardsStatus) {
    scopeCardsStatus.textContent = `Uploaded ${file.name} to ${type}`;
  }
}

function initializeScopeCards() {
  if (!scopeCards) {
    return;
  }

  scopeCards.innerHTML = LIST_FILES.map(({ type, label, uploadable }) => {
    const inputId = `scope-upload-${type}`;

    return `
      <article class="scope-card" data-type="${escapeHTML(type)}">
        <h3 class="scope-card__name"><button type="button" class="scope-card__open" data-type="${escapeHTML(type)}" data-label="${escapeHTML(label)}">${escapeHTML(label)}</button></h3>
        <span class="scope-card__status scope-card__status--missing">Missing</span>
        ${uploadable ? `<input id="${inputId}" type="file" accept=".txt,.csv" />` : ""}
        ${uploadable ? `<button type="button" class="scope-card__upload" data-input-id="${inputId}">Upload</button>` : '<p class="muted">Auto-generated by flow.</p>'}
      </article>
    `;
  }).join("");

  scopeCards.querySelectorAll(".scope-card").forEach((card) => {
    const type = card.dataset.type;
    if (!type) {
      return;
    }
    scopeCardNodes.set(type, {
      card,
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
  fileViewerTitle.textContent = label;
  fileViewerContent.textContent = "Loading...";
  fileViewerModal.hidden = false;
  try {
    const data = await fetchListMeta(type);
    if (!data.present) {
      fileViewerContent.textContent = "File missing.";
      return;
    }
    fileViewerContent.textContent = data.entries && data.entries.length
      ? data.entries.join("\n")
      : "No entries yet.";
  } catch (error) {
    fileViewerContent.textContent = `Error: ${error.message}`;
  }
}

function updateScopeCards(states) {
  const signature = LIST_FILES
    .map(({ type }) => `${type}:${states[type]?.present ? "1" : "0"}`)
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
    const present = Boolean(states[type]?.present);
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

function renderAmassTable() {
  if (!amassTableBody || !amassCount) {
    return;
  }
  const nameNeedle = normalizeFilterValue(amassSearchName?.value);
  const domainNeedle = normalizeFilterValue(amassSearchDomain?.value);
  const ipNeedle = normalizeFilterValue(amassSearchIP?.value);
  const sourceNeedle = normalizeFilterValue(amassSearchSource?.value);
  const tagNeedle = normalizeFilterValue(amassFilterTag?.value);

  const filtered = amassRows.filter((row) => (
    (!nameNeedle || normalizeFilterValue(row.name).includes(nameNeedle)) &&
    (!domainNeedle || normalizeFilterValue(row.domain).includes(domainNeedle)) &&
    (!ipNeedle || normalizeFilterValue(row.ip).includes(ipNeedle)) &&
    (!sourceNeedle || normalizeFilterValue(row.source).includes(sourceNeedle)) &&
    (!tagNeedle || normalizeFilterValue(row.tag) === tagNeedle)
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

  amassCount.textContent = `Showing ${filtered.length} of ${amassRows.length} rows`;
  amassTableBody.innerHTML = filtered.map((row) => `
    <tr>
      <td><code>${escapeHTML(row.name || "")}</code></td>
      <td>${escapeHTML(row.domain || "")}</td>
      <td>${escapeHTML(row.ip || "")}</td>
      <td>${escapeHTML(String(row.asn || ""))}</td>
      <td>${escapeHTML(row.source || "")}</td>
      <td>${escapeHTML(row.tag || "")}</td>
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
      <tr>
        <td><code>${escapeHTML(row.url || "")}</code></td>
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
      if (amassFilterTag) {
        const tags = [...new Set(amassRows.map((r) => normalizeFilterValue(r.tag)).filter((t) => t))];
        tags.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
        const current = normalizeFilterValue(amassFilterTag.value);
        amassFilterTag.innerHTML = `<option value="">All tags</option>${tags.map((t) => `<option value="${escapeHTML(t)}">${escapeHTML(t)}</option>`).join("")}`;
        if (tags.includes(current)) {
          amassFilterTag.value = current;
        }
      }
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

closeFileViewer?.addEventListener("click", () => {
  if (fileViewerModal) {
    fileViewerModal.hidden = true;
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

[amassSearchName, amassSearchDomain, amassSearchIP, amassSearchSource, amassFilterTag].forEach((el) => {
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

    flowStepsList.innerHTML = steps
      .map((step) => {
        const status = step.status || "pending";
        const prefix = stepPrefix(status);
        const safeLabel = step.label || step.id || "step";
        return `<li class="flow-step flow-step--${status}"><span class="flow-step__status">${prefix}</span><span class="flow-step__label">${escapeHTML(safeLabel)}</span></li>`;
      })
      .join("");
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

async function refreshListEntries(type, options = {}) {
  if (!listViewOutput) {
    return;
  }
  try {
    const data = await fetchListMeta(type);
    if (!options.force && hasSelectionInside(listViewOutput)) {
      return;
    }
    if (!data.present) {
      const nextText = "File missing.";
      if (lastListTextByType[type] !== nextText) {
        listViewOutput.textContent = nextText;
        lastListTextByType[type] = nextText;
      }
      return;
    }
    const nextText = data.entries && data.entries.length ? data.entries.join("\n") : "No entries yet.";
    if (lastListTextByType[type] !== nextText) {
      listViewOutput.textContent = nextText;
      lastListTextByType[type] = nextText;
    }
  } catch (error) {
    const nextText = `Error: ${error.message}`;
    if (lastListTextByType[type] !== nextText) {
      listViewOutput.textContent = nextText;
      lastListTextByType[type] = nextText;
    }
  }
}

listViewSelect?.addEventListener("change", () => {
  refreshListEntries(listViewSelect.value);
});

if (listViewSelect?.value) {
  refreshListEntries(listViewSelect.value);
}

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
    flowLogOutput.textContent = nextText;
    lastLogsSignature = nextText;
    if (shouldStickToBottom) {
      flowLogOutput.scrollTop = flowLogOutput.scrollHeight;
    }
  } catch (error) {
    const nextText = `Log fetch error: ${error.message}`;
    if (nextText !== lastLogsSignature) {
      flowLogOutput.textContent = nextText;
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
refreshAmassEnum({ renderOnlyIfOpen: false });
setInterval(() => {
  refreshAmassEnum({ renderOnlyIfOpen: true });
}, 5000);
refreshLiveWebservers({ renderOnlyIfOpen: false });
setInterval(() => {
  refreshLiveWebservers({ renderOnlyIfOpen: true });
}, 5000);

renderStrideLearning();
loadStrideAnswer();
initializeManualRecon();
