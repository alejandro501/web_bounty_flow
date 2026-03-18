import { downloadTextExport, exportStructuredRows, linesToMarkdown } from "./modules/export-utils.js";
import { initDiscoveryTablesFeature } from "./modules/discovery-tables.js";
import { initConfigNetworkFeature } from "./modules/config-network.js";
import { initCookieAuthFeature } from "./modules/cookie-auth.js?v=20260317-2";
import { initLeadsChaosFeature } from "./modules/leads-chaos.js";
import { initManualDomainFeature } from "./modules/manual-domain.js";
import { initNotesFeature } from "./modules/notes.js?v=20260317-2";
import { initScopeFilesFeature } from "./modules/scope-files.js";
import { initStrideFeature } from "./modules/stride.js";
import { initFlowRuntimeFeature } from "./modules/flow-runtime.js";
import { FLOW_SEGMENTS, FLOW_SUBDOMAIN_TOOLS } from "./content/flow-data.js";
import { HYBRID_MANUAL_CHECKLIST_ITEMS, MANUAL_DOMAIN_CHECKLIST_ITEMS } from "./content/manual-domain-data.js";
import { FILE_EXPLANATIONS, GENERATED_FILE_GROUPS, LIST_FILES } from "./content/scope-files.js";

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
const proxyRouteToggle = document.getElementById("proxy-route-toggle");
const proxyNetworkIndicator = document.getElementById("proxy-network-indicator");
const leadsStatus = document.getElementById("leads-status");
const leadsSummary = document.getElementById("leads-summary");
const leadsWildcards = document.getElementById("leads-wildcards");
const chaosStatus = document.getElementById("chaos-status");
const chaosSummary = document.getElementById("chaos-summary");
const chaosGroups = document.getElementById("chaos-groups");
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
const notesEditor = document.getElementById("notes-editor");
const notesSave = document.getElementById("notes-save");
const notesStatus = document.getElementById("notes-status");
const notesPreview = document.getElementById("notes-preview");
const cookieRows = document.getElementById("cookie-pairs");
const cookieAddRow = document.getElementById("cookie-add-row");
const cookieSave = document.getElementById("cookie-save");
const cookieStatus = document.getElementById("cookie-status");
const authEditor = document.getElementById("auth-editor");
const authSave = document.getElementById("auth-save");
const authStatus = document.getElementById("auth-status");
const authPreview = document.getElementById("auth-preview");
const manualTipsEditor = document.getElementById("manual-tips-editor");
const manualTipsSave = document.getElementById("manual-tips-save");
const manualTipsStatus = document.getElementById("manual-tips-status");
const manualTipsPreview = document.getElementById("manual-tips-preview");
const githubAutoRun = document.getElementById("github-auto-run");
const githubKeyLabel = document.getElementById("github-key-label");
const githubKeyValue = document.getElementById("github-key-value");
const githubKeyActive = document.getElementById("github-key-active");
const githubKeyAdd = document.getElementById("github-key-add");
const githubKeysList = document.getElementById("github-keys-list");
const flowConfigTools = document.getElementById("flow-config-tools");
const flowConfigStatus = document.getElementById("flow-config-status");
const flowConfigSave = document.getElementById("flow-config-save");
const proxyConfigEnabled = document.getElementById("proxy-config-enabled");
const proxyConfigHost = document.getElementById("proxy-config-host");
const proxyConfigPort = document.getElementById("proxy-config-port");
const proxyConfigSave = document.getElementById("proxy-config-save");
const scopeCards = document.getElementById("scope-cards");
const scopeCardsStatus = document.getElementById("scope-cards-status");
const fileViewerModal = document.getElementById("file-viewer-modal");
const fileViewerTitle = document.getElementById("file-viewer-title");
const fileViewerDescription = document.getElementById("file-viewer-description");
const fileViewerContent = document.getElementById("file-viewer-content");
const fileViewerFilters = document.getElementById("file-viewer-filters");
const hopByHopStatusFilter = document.getElementById("hop-by-hop-status-filter");
const closeFileViewer = document.getElementById("close-file-viewer");
const openFileViewerExport = document.getElementById("open-file-viewer-export");
const fileViewerExportMenu = document.getElementById("file-viewer-export-menu");
const editFileViewer = document.getElementById("edit-file-viewer");
const saveFileViewer = document.getElementById("save-file-viewer");
const fileViewerEditor = document.getElementById("file-viewer-editor");
const openAmassEnum = document.getElementById("open-amass-enum");
const amassEnumModal = document.getElementById("amass-enum-modal");
const closeAmassEnum = document.getElementById("close-amass-enum");
const exportAmassEnum = document.getElementById("export-amass-enum");
const amassEnumExportMenu = document.getElementById("amass-enum-export-menu");
const amassSearchName = document.getElementById("amass-search-name");
const amassSearchDomain = document.getElementById("amass-search-domain");
const amassSearchIP = document.getElementById("amass-search-ip");
const amassTableBody = document.getElementById("amass-table-body");
const amassCount = document.getElementById("amass-count");
const openLiveWebservers = document.getElementById("open-live-webservers");
const liveWebserversModal = document.getElementById("live-webservers-modal");
const closeLiveWebservers = document.getElementById("close-live-webservers");
const exportLiveWebservers = document.getElementById("export-live-webservers");
const liveWebserversExportMenu = document.getElementById("live-webservers-export-menu");
const lwsSearchURL = document.getElementById("lws-search-url");
const lwsFilterStatus = document.getElementById("lws-filter-status");
const lwsSearchTitle = document.getElementById("lws-search-title");
const lwsSearchWebServer = document.getElementById("lws-search-webserver");
const lwsSearchTech = document.getElementById("lws-search-tech");
const lwsTableBody = document.getElementById("lws-table-body");
const lwsCount = document.getElementById("lws-count");
const manualDomainSelect = document.getElementById("manual-domain-select");
const manualDomainStatusFilter = document.getElementById("manual-domain-status-filter");
const manualDomainSearch = document.getElementById("manual-domain-search");
const manualDomainUrl = document.getElementById("manual-domain-url");
const manualAuthHeader = document.getElementById("manual-auth-header");
const manualRunXSS = document.getElementById("manual-run-xss");
const manualXSSStatus = document.getElementById("manual-xss-status");
const manualXSSRunner = manualRunXSS?.closest(".manual-xss-runner") || null;
const manualChecklistList = document.getElementById("manual-checklist-list");
const manualChecklistProgress = document.getElementById("manual-checklist-progress");
const hybridChecklistList = document.getElementById("hybrid-checklist-list");
const hybridChecklistProgress = document.getElementById("hybrid-checklist-progress");
const notesFeature = initNotesFeature({
  backendUrl: BACKEND_URL,
  escapeHTML,
  notesEditor,
  notesSave,
  notesStatus,
  notesPreview,
  manualTipsEditor,
  manualTipsSave,
  manualTipsStatus,
  manualTipsPreview,
});
const cookieAuthFeature = initCookieAuthFeature({
  backendUrl: BACKEND_URL,
  escapeHTML,
  cookieRows,
  cookieAddRow,
  cookieSave,
  cookieStatus,
  authEditor,
  authSave,
  authStatus,
  authPreview,
});
const discoveryTablesFeature = initDiscoveryTablesFeature({
  escapeHTML,
  normalizeFilterValue,
  normalizeTableCellValue,
  exportStructuredRows,
  fetchAmassEnum,
  fetchLiveWebservers,
  openAmassEnum,
  amassEnumModal,
  closeAmassEnum,
  exportAmassEnum,
  amassEnumExportMenu,
  amassSearchName,
  amassSearchDomain,
  amassSearchIP,
  amassTableBody,
  amassCount,
  openLiveWebservers,
  liveWebserversModal,
  closeLiveWebservers,
  exportLiveWebservers,
  liveWebserversExportMenu,
  lwsSearchURL,
  lwsFilterStatus,
  lwsSearchTitle,
  lwsSearchWebServer,
  lwsSearchTech,
  lwsTableBody,
  lwsCount,
});


const scopeFilesFeature = initScopeFilesFeature({
  backendUrl: BACKEND_URL,
  listFiles: LIST_FILES,
  generatedFileGroups: GENERATED_FILE_GROUPS,
  fileExplanations: FILE_EXPLANATIONS,
  escapeHTML,
  normalizeTableCellValue,
  downloadTextExport,
  linesToMarkdown,
  exportStructuredRows,
  scopeCards,
  scopeCardsStatus,
  fileViewerModal,
  fileViewerTitle,
  fileViewerDescription,
  fileViewerContent,
  fileViewerFilters,
  hopByHopStatusFilter,
  closeFileViewer,
  openFileViewerExport,
  fileViewerExportMenu,
  editFileViewer,
  saveFileViewer,
  fileViewerEditor,
});

const configNetworkFeature = initConfigNetworkFeature({
  backendUrl: BACKEND_URL,
  escapeHTML,
  flowSubdomainTools: FLOW_SUBDOMAIN_TOOLS,
  flowStatus,
  torRouteToggle,
  torNetworkIndicator,
  proxyRouteToggle,
  proxyNetworkIndicator,
  githubAutoRun,
  githubKeyLabel,
  githubKeyValue,
  githubKeyActive,
  githubKeyAdd,
  githubKeysList,
  flowConfigTools,
  flowConfigStatus,
  flowConfigSave,
  proxyConfigEnabled,
  proxyConfigHost,
  proxyConfigPort,
  proxyConfigSave,
});

const manualDomainFeature = initManualDomainFeature({
  backendUrl: BACKEND_URL,
  escapeHTML,
  fetchLiveWebservers,
  fetchDomainsHTTP: () => scopeFilesFeature.fetchListMeta("domains_http"),
  manualDomainSelect,
  manualDomainStatusFilter,
  manualDomainSearch,
  manualDomainUrl,
  manualAuthHeader,
  manualRunXSS,
  manualXSSStatus,
  manualXSSRunner,
  manualChecklistList,
  manualChecklistProgress,
  hybridChecklistList,
  hybridChecklistProgress,
  manualChecklistItems: MANUAL_DOMAIN_CHECKLIST_ITEMS,
  hybridChecklistItems: HYBRID_MANUAL_CHECKLIST_ITEMS,
});

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
      void leadsChaosFeature.refreshLeads({ force: true });
    }
    if (view === "chaos") {
      void leadsChaosFeature.refreshChaos({ force: true });
    }
    if (view === "config") {
      void configNetworkFeature.loadConfig();
      void configNetworkFeature.loadFlowConfig();
    }
    notesFeature.activateView(view);
    cookieAuthFeature.activateView(view);
  });
});

function normalizeTableCellValue(value) {
  if (value === null || value === undefined) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeTableCellValue(item)).join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function isLikelyURL(value) {
  const s = String(value || "").trim();
  return /^https?:\/\/\S+$/i.test(s);
}

const leadsChaosFeature = initLeadsChaosFeature({
  backendUrl: BACKEND_URL,
  escapeHTML,
  normalizeTableCellValue,
  isLikelyURL,
  leadsStatus,
  leadsSummary,
  leadsWildcards,
  chaosStatus,
  chaosSummary,
  chaosGroups,
});
const flowRuntimeFeature = initFlowRuntimeFeature({
  backendUrl: BACKEND_URL,
  ansiTextToHTML,
  escapeHTML,
  flowSegments: FLOW_SEGMENTS,
  runButton,
  pauseButton,
  stopButton,
  clearResultsButton,
  flowStatus,
  flowLogOutput,
  flowStepsList,
  subdomainProgressBar,
  subdomainProgressText,
  torRouteToggle,
  torNetworkIndicator,
  onRunQueued: () => configNetworkFeature.loadNetworkSettings(),
  onClearResults: async ({ refreshStatus, refreshSteps, refreshSubdomainProgress }) => {
    await Promise.all([
      scopeFilesFeature.refreshScopeCards(),
      refreshSubdomainProgress(),
      discoveryTablesFeature.refreshAmassEnum({ renderOnlyIfOpen: false }),
      discoveryTablesFeature.refreshLiveWebservers({ renderOnlyIfOpen: false }),
      refreshSteps(),
      refreshStatus(),
    ]);
  },
});

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

function normalizeFilterValue(v) {
  return (v || "").toString().toLowerCase().trim();
}

configNetworkFeature.loadConfig();
configNetworkFeature.loadFlowConfig();
configNetworkFeature.loadNetworkSettings();
setInterval(() => {
  configNetworkFeature.loadNetworkSettings();
}, 8000);
flowRuntimeFeature.startPolling();

scopeFilesFeature.initializeScopeCards();
scopeFilesFeature.refreshScopeCards();
setInterval(() => {
  scopeFilesFeature.refreshScopeCards();
}, 4000);
manualDomainFeature.initializeManualDomainChecklist();
setInterval(() => {
  manualDomainFeature.refreshManualDomainOptions();
}, 10000);
setInterval(() => {
  manualDomainFeature.refreshManualXSSStatus();
}, 5000);
discoveryTablesFeature.refreshAmassEnum({ renderOnlyIfOpen: false });
setInterval(() => {
  discoveryTablesFeature.refreshAmassEnum({ renderOnlyIfOpen: true });
}, 5000);
discoveryTablesFeature.refreshLiveWebservers({ renderOnlyIfOpen: false });
setInterval(() => {
  discoveryTablesFeature.refreshLiveWebservers({ renderOnlyIfOpen: true });
}, 5000);
leadsChaosFeature.refreshLeads({ force: true });
setInterval(() => {
  leadsChaosFeature.refreshLeads({ force: false });
}, 7000);
leadsChaosFeature.refreshChaos({ force: true });
setInterval(() => {
  leadsChaosFeature.refreshChaos({ force: false });
}, 120000);

initStrideFeature({
  strideTabs,
  strideSections,
  learnQuestion,
  learnAnswers,
  learnPrev,
  learnNext,
  learnIndex,
  strideAnswerText,
  strideAnswerStatus,
  strideExportAnswers,
  manualWorkspaceRoots,
  escapeHTML,
});
notesFeature.loadCanvas("notes");
notesFeature.loadCanvas("manual_tips");
manualDomainFeature.refreshManualDomainOptions();
manualDomainFeature.refreshManualXSSStatus();
