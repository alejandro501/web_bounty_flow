export const STRIDE_LESSONS = {
  overview: [
    {
      question: "What stage are we at and what are we trying to accomplish?",
      answers: [
        "Build a reusable threat model baseline from recon findings.",
        "Map each mechanism/object to realistic STRIDE attack paths.",
        "Prioritize what can create customer, business, or trust impact.",
      ],
    },
    {
      question: "How should I think about STRIDE while testing?",
      answers: [
        "Treat each flow as a trust boundary crossing.",
        "Ask what breaks if identity, data integrity, logging, confidentiality, availability, or authorization fails.",
        "Capture exploitability and business impact, not just technical weakness.",
      ],
    },
  ],
  "high-level-questions": [
    {
      question: "What high-level questions matter first?",
      answers: [
        "What are critical assets and who can access them?",
        "Where are trust boundaries between user/client/service/provider?",
        "What actions must be auditable and non-repudiable?",
      ],
    },
  ],
  mechanisms: [
    {
      question: "Which mechanisms should I enumerate?",
      answers: [
        "AuthN/AuthZ, session lifecycle, token handling, and role transitions.",
        "Input handling, workflow state transitions, and async job triggers.",
        "Integrations such as webhooks, queues, third-party APIs, and cloud services.",
      ],
    },
  ],
  "notable-objects": [
    {
      question: "Which objects are highest-value?",
      answers: [
        "Identity and permission objects (users, orgs, roles, API keys).",
        "Business-critical records (orders, payouts, moderation, billing).",
        "Security evidence objects (logs, events, policy changes, alerts).",
      ],
    },
  ],
  "security-controls": [
    {
      question: "How do I evaluate controls quickly?",
      answers: [
        "Verify preventive control exists and is server-side enforced.",
        "Verify detective control records enough evidence to investigate.",
        "Verify corrective control can revoke, rotate, and recover fast.",
      ],
    },
  ],
  "threat-model": [
    {
      question: "How do I write a useful threat model entry?",
      answers: [
        "Describe preconditions, attack steps, and control bypass.",
        "Attach concrete impact: customer data, attacker scope, and company reputation.",
        "Record recommended mitigation and how to validate the fix.",
      ],
    },
  ],
  spoofing: [
    {
      question: "What spoofing checks should I run?",
      answers: [
        "Identity impersonation via weak session/token validation.",
        "Header trust abuse (`Host`, forwarded headers, origin assumptions).",
        "Cross-tenant identity confusion and account-linking mistakes.",
      ],
    },
  ],
  tampering: [
    {
      question: "Where does tampering usually appear?",
      answers: [
        "Client-controlled fields trusted by backend for state changes.",
        "Workflow transitions lacking server-side integrity checks.",
        "Object references mutable without ownership verification.",
      ],
    },
  ],
  repudiation: [
    {
      question: "What proves repudiation risk?",
      answers: [
        "Sensitive actions with no stable actor/request traceability.",
        "Editable/deletable logs without tamper-evident controls.",
        "Missing event context for high-risk transactions.",
      ],
    },
  ],
  "info-disclosure": [
    {
      question: "What information disclosure signals are high-value?",
      answers: [
        "Secrets in client bundles, logs, stack traces, or docs.",
        "Overly verbose API responses exposing internal fields.",
        "Cross-tenant data leakage via object ID or filtering flaws.",
      ],
    },
  ],
  dos: [
    {
      question: "How should I model DoS risk?",
      answers: [
        "Find expensive endpoints lacking strict quotas and backpressure.",
        "Test queue/job amplification and retry storm behavior.",
        "Measure blast radius on critical auth and payment flows.",
      ],
    },
  ],
  eop: [
    {
      question: "What elevation-of-privilege paths are common?",
      answers: [
        "Role/claim manipulation and stale authorization caches.",
        "Admin endpoints reachable from low-privileged contexts.",
        "Chained weak controls enabling horizontal to vertical escalation.",
      ],
    },
  ],
  workflow: [
    {
      question: "How do I operationalize this during recon/testing?",
      answers: [
        "Map findings to mechanisms/objects first, then STRIDE categories.",
        "Track evidence and hypotheses per subsection in 'Your Answer'.",
        "Promote only threats with plausible exploit path and impact.",
      ],
    },
  ],
};

export const MANUAL_RECON_QUESTIONS = [
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
      "Is the app intended to be embedded or integrated into other sites?",
    ],
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
      "Are custom client-side frameworks present?",
    ],
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
      "Are internal hostnames or regions leaked in responses?",
    ],
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
      "Are multiple domains involved in session handling?",
    ],
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
      "Are automated clients treated differently?",
    ],
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
      "Are authentication flows shared across domains?",
    ],
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
      "Are permissions enforced centrally or per-service?",
    ],
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
      "Is source code or documentation publicly available?",
    ],
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
      "Are infrastructure-as-code templates publicly accessible?",
    ],
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
      "Are API responses verbose with metadata?",
    ],
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
      "Are API docs, changelogs, or internal wikis indexed by search engines?",
    ],
  },
];

export const MANUAL_WORKSPACE_QUESTIONS = {
  "high-level-questions": MANUAL_RECON_QUESTIONS,
  mechanisms: [
    {
      category: "Authentication Mechanisms",
      questions: [
        "How are login, MFA, and recovery flows implemented?",
        "Where can token/session lifecycle be abused?",
        "Are SSO boundaries clearly enforced across subdomains?",
        "What identity assumptions are trusted from the client?",
      ],
    },
    {
      category: "Authorization Mechanisms",
      questions: [
        "Is RBAC/ABAC enforced server-side for every sensitive action?",
        "Are role transitions and privilege grants audited?",
        "Can tenancy boundaries be crossed through object IDs?",
        "Are admin operations separated from normal user flows?",
      ],
    },
    {
      category: "State & Input Mechanisms",
      questions: [
        "Which workflow state changes depend on client-controlled fields?",
        "Where is validation/canonicalization inconsistent?",
        "Are deserialization/parsing paths hardened against malformed input?",
        "Can async jobs be triggered out-of-order or replayed?",
      ],
    },
  ],
  "notable-objects": [
    {
      category: "Identity & Access Objects",
      questions: [
        "Which identity objects can change scope/privilege?",
        "Where are API keys, tokens, or service credentials stored?",
        "Are role and permission objects mutable by low-privileged users?",
        "What ownership model protects account and org objects?",
      ],
    },
    {
      category: "Business-Critical Objects",
      questions: [
        "Which business objects would create highest impact if modified?",
        "Can payout/order/refund objects be tampered with?",
        "Are moderation or trust-safety objects weakly protected?",
        "Which object IDs are predictable/enumerable?",
      ],
    },
    {
      category: "Security Evidence Objects",
      questions: [
        "What audit records exist for critical actions?",
        "Can logs/events be altered, deleted, or suppressed?",
        "Are security events linked to stable actor context?",
        "Do stored events support incident reconstruction?",
      ],
    },
  ],
  "security-controls": [
    {
      category: "Preventive Controls",
      questions: [
        "Which controls block misuse before execution?",
        "Are authz, schema validation, and rate limits consistently enforced?",
        "Which endpoints bypass WAF/proxy policy unintentionally?",
        "Are secret-management and key-rotation controls effective?",
      ],
    },
    {
      category: "Detective Controls",
      questions: [
        "Which high-risk actions generate detections?",
        "Is telemetry sufficient to detect abuse patterns quickly?",
        "Are anomaly detections resistant to noisy false positives?",
        "Do alerts provide enough context for triage?",
      ],
    },
    {
      category: "Corrective Controls",
      questions: [
        "How fast can sessions/keys/tokens be revoked?",
        "Are rollback and incident playbooks tested regularly?",
        "Can compromised objects be quarantined without broad outage?",
        "Is there verified recovery for worst-case abuse paths?",
      ],
    },
  ],
  "threat-model": [
    {
      category: "Threat Enumeration",
      questions: [
        "What are the top STRIDE threats for this flow?",
        "Which preconditions and trust assumptions make exploitation feasible?",
        "What attack chains convert low-risk bugs into critical impact?",
        "Where do existing controls fail under adversarial input?",
      ],
    },
    {
      category: "Impact Modeling",
      questions: [
        "What customer data exposure is plausible and at what scale?",
        "How far can attacker scope expand (user, org, platform)?",
        "What business operations can be disrupted or manipulated?",
        "What reputational/legal impact is likely if exploited?",
      ],
    },
    {
      category: "Mitigation Planning",
      questions: [
        "What is the highest-leverage fix for this threat?",
        "How should detection be updated to catch repeats?",
        "What validation proves mitigation is complete?",
        "Who owns remediation and what is the deadline?",
      ],
    },
  ],
  spoofing: [
    {
      category: "Identity Impersonation",
      questions: [
        "Can attacker impersonate users through session/token flaws?",
        "Are password reset and recovery flows resistant to spoofing?",
        "Can account linking be abused to bind attacker identity to victim context?",
        "Do service-to-service calls verify caller identity strongly?",
        "Can OAuth/OIDC callback handling be spoofed via redirect confusion?",
      ],
    },
    {
      category: "Trust Boundary Assumptions",
      questions: [
        "Does backend trust spoofable headers (`Host`, `X-Forwarded-*`)?",
        "Are origin/referrer checks enforceable and tamper-resistant?",
        "Can tenant context be spoofed via client-side parameters?",
        "Can federated identity claims be forged or replayed?",
        "Do mTLS/internal-service assumptions break at edge proxies?",
      ],
    },
  ],
  tampering: [
    {
      category: "Request/Data Integrity",
      questions: [
        "Which request parameters can alter protected state?",
        "Are client-calculated values (price, role, scope) trusted by backend?",
        "Can stored records be modified without ownership checks?",
        "Are signed tokens/payloads validated consistently?",
        "Can file/object metadata be overwritten to influence downstream processing?",
      ],
    },
    {
      category: "Workflow Integrity",
      questions: [
        "Can state transitions be forced out of sequence?",
        "Can attacker replay old requests to tamper with current state?",
        "Are idempotency and anti-race controls in place for critical actions?",
        "Can background job payloads be manipulated before execution?",
        "Can webhook payload trust be abused to mutate internal state?",
      ],
    },
  ],
  repudiation: [
    {
      category: "Auditability",
      questions: [
        "Which privileged actions lack durable audit trails?",
        "Is actor attribution stable across proxies and services?",
        "Can users deny actions due to missing context in logs?",
        "Are audit logs immutable and protected from tampering?",
        "Are admin actions distinguishable from automation/service actions?",
      ],
    },
    {
      category: "Forensics Readiness",
      questions: [
        "Do events include request ID, subject, object, and outcome?",
        "Are timestamps and correlation IDs reliable across systems?",
        "Can incident responders reconstruct attack sequence from telemetry?",
        "Are failed/high-risk actions logged at sufficient detail?",
        "Are log retention windows sufficient for realistic incident timelines?",
      ],
    },
  ],
  "info-disclosure": [
    {
      category: "Data Exposure",
      questions: [
        "Which endpoints leak sensitive fields beyond least-privilege need?",
        "Can cross-tenant/object access reveal unauthorized data?",
        "Are secrets exposed via errors, logs, or debug endpoints?",
        "Do client bundles/source maps leak private implementation details?",
        "Are internal-only endpoints exposed through API documentation or schema?",
      ],
    },
    {
      category: "Storage/Infra Exposure",
      questions: [
        "Are buckets/backups/indexes publicly accessible?",
        "Are internal hostnames, regions, or metadata leaked in responses?",
        "Can generated documents/files expose private paths or identifiers?",
        "Are data retention and redaction controls enforced consistently?",
        "Are pre-signed URLs scoped and expired safely?",
      ],
    },
  ],
  dos: [
    {
      category: "Resource Exhaustion",
      questions: [
        "Which endpoints are computationally expensive without strict limits?",
        "Can attacker trigger high-fanout jobs, retries, or queue floods?",
        "Do unauthenticated flows reach expensive backend work?",
        "What single dependency failure has largest blast radius?",
        "Can per-tenant abuse degrade global service availability?",
      ],
    },
    {
      category: "Resilience Controls",
      questions: [
        "Are quotas, backpressure, and concurrency caps in place?",
        "Do retries/circuit breakers prevent amplification cascades?",
        "Are caches/fallbacks used safely under failure?",
        "Is there graceful degradation for auth/payment/core workflows?",
        "How quickly can abusive traffic be detected and contained?",
      ],
    },
  ],
  eop: [
    {
      category: "Privilege Escalation Paths",
      questions: [
        "Can low-privileged users reach admin-only capabilities?",
        "Are role/claim changes trusted from client or stale caches?",
        "Can horizontal access bugs chain into vertical privilege gain?",
        "Are support/internal tools reachable from customer contexts?",
        "Can feature flags or hidden endpoints unlock privileged paths?",
      ],
    },
    {
      category: "Trust Expansion",
      questions: [
        "Can attacker pivot from one tenant/org into platform scope?",
        "Do service accounts have broader access than intended?",
        "Can secrets/tokens from one component unlock another trust zone?",
        "Are management APIs protected separately from product APIs?",
        "Can compromised automation/webhooks grant durable elevated access?",
      ],
    },
  ],
  workflow: [
    {
      category: "Operational Workflow",
      questions: [
        "Which findings should be promoted into validated threats?",
        "What evidence is missing before escalation/reporting?",
        "Which attack paths are realistic versus theoretical?",
        "Where should manual testing focus next for highest ROI?",
        "What remediation guidance is concrete enough to act on now?",
      ],
    },
  ],
};
