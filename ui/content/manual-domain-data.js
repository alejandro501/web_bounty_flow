export const MANUAL_DOMAIN_CHECKLIST_ITEMS = [
  { id: "username-policy", label: "Username enumeration and password policy checks" },
  { id: "recovery-rememberme", label: "Recovery and remember-me weakness testing" },
  { id: "session-entropy-cookie-policy", label: "Session token entropy and cookie policy analysis" },
  { id: "session-fixation-logout-invalidation", label: "Session fixation and logout invalidation checks" },
  { id: "authz-role-matrix-bola-idor", label: "Role-matrix authorization replay (BOLA/IDOR)" },
  { id: "authz-method-mismatch", label: "Method-based access control mismatch checks" },
  { id: "logic-race-conditions", label: "Race-condition checks on critical state transitions" },
];

export const HYBRID_MANUAL_CHECKLIST_ITEMS = [
  { id: "hybrid-injection-sqli-nosqli-xpath-ldap", label: "SQLi/NoSQL/XPath/LDAP: validate findings manually and confirm impact" },
  { id: "hybrid-injection-os-path-file", label: "OS command/path traversal/file inclusion: manual exploitability validation" },
  { id: "hybrid-injection-xxe-soap-ssrf-smtp", label: "XXE/SOAP/SSRF/SMTP: manual triage of automated findings" },
  { id: "hybrid-xss", label: "XSS (reflected/stored/DOM): manual verification and proof-of-impact" },
  { id: "hybrid-csrf", label: "CSRF: validate automated findings with authenticated/manual replay PoC" },
  { id: "hybrid-clickjacking", label: "Clickjacking: confirm exploitable UI redress on sensitive actions" },
  { id: "hybrid-cors", label: "CORS/SOP: validate data-read impact with authenticated browser context" },
  { id: "hybrid-open-redirect", label: "Open redirect: manually test OAuth/phishing/chaining impact" },
  { id: "hybrid-workflow-logic", label: "Workflow logic: validate semi-automated step/sequence findings manually" },
  { id: "hybrid-smuggling-stack", label: "Request smuggling/h2c/hop-by-hop/SSI-ESI: confirm exploitability manually" },
  { id: "hybrid-tier-isolation", label: "Tier-segmentation/shared-hosting: verify trust-boundary impact manually" },
];
