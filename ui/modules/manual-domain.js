export function initManualDomainFeature({
  backendUrl,
  escapeHTML,
  fetchLiveWebservers,
  fetchDomainsHTTP,
  manualDomainSelect,
  manualDomainStatusFilter,
  manualDomainUrl,
  manualAuthHeader,
  manualRunXSS,
  manualXSSStatus,
  manualXSSRunner,
  manualChecklistList,
  manualChecklistProgress,
  hybridChecklistList,
  hybridChecklistProgress,
  manualChecklistItems,
  hybridChecklistItems,
}) {
  let manualDomainOptions = [];
  let manualDomainsReady = false;

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
    return "bflow_hybrid_checklist_v1";
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
    const raw = String(entry || "").trim();
    if (!raw) {
      return "";
    }
    if (/^https?:\/\//i.test(raw)) {
      try {
        return new URL(raw).hostname.toLowerCase();
      } catch {
        return raw.toLowerCase();
      }
    }
    return raw.toLowerCase();
  }

  function domainFromURL(urlText) {
    try {
      return new URL(String(urlText || "")).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function selectedManualDomain() {
    return String(manualDomainSelect?.value || "").trim().toLowerCase();
  }

  function selectedManualStatusFilter() {
    return String(manualDomainStatusFilter?.value || "all").trim().toLowerCase();
  }

  function updateManualStatusFilterOptions(rows) {
    if (!manualDomainStatusFilter) {
      return;
    }
    const current = selectedManualStatusFilter();
    const hasHttp = rows.some((row) => row.status === "http");
    const hasDead = rows.some((row) => row.status === "dead");
    const options = ['<option value="all">All domains</option>'];
    if (hasHttp) {
      options.push('<option value="http">HTTP only</option>');
    }
    if (hasDead) {
      options.push('<option value="dead">Dead only</option>');
    }
    manualDomainStatusFilter.innerHTML = options.join("");
    manualDomainStatusFilter.value = options.includes(`<option value="${current}">`) ? current : "all";
  }

  function renderManualChecklist() {
    if (!manualChecklistList || !manualChecklistProgress) {
      return;
    }
    const domain = selectedManualDomain();
    const state = loadManualDomainChecklistState();
    const doneMap = state[domain] || {};
    const completed = manualChecklistItems.filter((item) => doneMap[item.id]).length;
    manualChecklistProgress.textContent = domain
      ? `${completed} / ${manualChecklistItems.length} completed for ${domain}`
      : "Select a domain to track checklist progress.";
    manualChecklistList.innerHTML = manualChecklistItems.map((item) => {
      const checked = Boolean(doneMap[item.id]);
      return `
        <label class="checklist-item${checked ? " is-done" : ""}">
          <input type="checkbox" data-manual-check="${escapeHTML(item.id)}" ${checked ? "checked" : ""} ${domain ? "" : "disabled"} />
          <span>${escapeHTML(item.label)}</span>
        </label>
      `;
    }).join("");
  }

  function updateManualXSSStatusText(statusData) {
    if (!manualXSSStatus) {
      return;
    }
    if (!statusData || !statusData.running) {
      manualXSSStatus.textContent = "Idle";
      return;
    }
    const startedAt = statusData.started_at ? new Date(statusData.started_at).toLocaleTimeString() : "just now";
    manualXSSStatus.textContent = `Running since ${startedAt}`;
  }

  function applyManualXSSRunnerAvailability(running = false) {
    if (manualRunXSS) {
      manualRunXSS.disabled = running || !selectedManualDomain();
    }
    if (manualDomainUrl) {
      manualDomainUrl.disabled = running;
    }
    if (manualAuthHeader) {
      manualAuthHeader.disabled = running;
    }
    if (manualXSSRunner) {
      manualXSSRunner.classList.toggle("is-running", running);
    }
  }

  async function refreshManualXSSStatus() {
    try {
      const response = await fetch(`${backendUrl}/api/manual/xss-status`);
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const data = await response.json();
      updateManualXSSStatusText(data);
      applyManualXSSRunnerAvailability(Boolean(data?.running));
    } catch (error) {
      if (manualXSSStatus) {
        manualXSSStatus.textContent = `Status error: ${error.message}`;
      }
      applyManualXSSRunnerAvailability(false);
    }
  }

  function renderHybridChecklist() {
    if (!hybridChecklistList || !hybridChecklistProgress) {
      return;
    }
    const state = loadHybridChecklistState();
    const completed = hybridChecklistItems.filter((item) => state[item.id]).length;
    hybridChecklistProgress.textContent = `${completed} / ${hybridChecklistItems.length} manual validation tasks completed`;
    hybridChecklistList.innerHTML = hybridChecklistItems.map((item) => {
      const checked = Boolean(state[item.id]);
      return `
        <label class="checklist-item${checked ? " is-done" : ""}">
          <input type="checkbox" data-hybrid-check="${escapeHTML(item.id)}" ${checked ? "checked" : ""} />
          <span>${escapeHTML(item.label)}</span>
        </label>
      `;
    }).join("");
  }

  function populateManualDomainSelect(options) {
    if (!manualDomainSelect) {
      return;
    }
    const previous = selectedManualDomain();
    const list = options.map((row) => ({ value: row.domain, status: row.status, statusCode: row.statusCode }));
    const filteredList = selectedManualStatusFilter() === "all"
      ? list
      : list.filter((row) => row.status === selectedManualStatusFilter());
    manualDomainSelect.innerHTML = [
      '<option value="">Choose a domain</option>',
      ...filteredList.map((row) => {
        const statusText = row.status === "http" ? `${row.statusCode || "live"}`
          : "dead";
        return `<option value="${escapeHTML(row.value)}">${escapeHTML(row.value)} (${escapeHTML(statusText)})</option>`;
      }),
    ].join("");
    if (filteredList.some((row) => row.value === previous)) {
      manualDomainSelect.value = previous;
    }
  }

  async function refreshManualDomainOptions() {
    const [liveData, domainsHTTPData] = await Promise.all([
      fetchLiveWebservers().catch(() => ({ present: false, rows: [] })),
      fetchDomainsHTTP().catch(() => ({ present: false, entries: [] })),
    ]);

    const liveRows = Array.isArray(liveData.rows) ? liveData.rows : [];
    const liveMap = new Map();
    liveRows.forEach((row) => {
      const domain = normalizeDomainEntry(row.url || row.input || "");
      if (!domain) {
        return;
      }
      liveMap.set(domain, {
        domain,
        status: "http",
        statusCode: row.status_code ? String(row.status_code) : "",
        url: row.url || "",
      });
    });

    const domainsHTTPEntries = Array.isArray(domainsHTTPData.entries) ? domainsHTTPData.entries : [];
    domainsHTTPEntries.forEach((entry) => {
      const domain = normalizeDomainEntry(entry);
      if (!domain || liveMap.has(domain)) {
        return;
      }
      liveMap.set(domain, { domain, status: "http", statusCode: "", url: `https://${domain}` });
    });

    const all = [...liveMap.values()];
    all.sort((a, b) => a.domain.localeCompare(b.domain, undefined, { sensitivity: "base" }));
    manualDomainOptions = all;
    manualDomainsReady = true;
    updateManualStatusFilterOptions(all);
    populateManualDomainSelect(all);
    renderManualChecklist();
    applyManualXSSRunnerAvailability(false);
  }

  function initializeManualDomainChecklist() {
    renderManualChecklist();
    renderHybridChecklist();

    manualDomainSelect?.addEventListener("change", () => {
      const selected = selectedManualDomain();
      const chosen = manualDomainOptions.find((item) => item.domain === selected);
      if (manualDomainUrl) {
        manualDomainUrl.value = chosen?.url || (selected ? `https://${selected}` : "");
      }
      renderManualChecklist();
      applyManualXSSRunnerAvailability(false);
    });

    manualDomainStatusFilter?.addEventListener("change", () => {
      populateManualDomainSelect(manualDomainOptions);
      renderManualChecklist();
      applyManualXSSRunnerAvailability(false);
    });

    manualChecklistList?.addEventListener("change", (event) => {
      const checkbox = event.target.closest("input[data-manual-check]");
      const domain = selectedManualDomain();
      if (!checkbox || !domain) {
        return;
      }
      const state = loadManualDomainChecklistState();
      const next = { ...(state[domain] || {}) };
      next[checkbox.dataset.manualCheck] = checkbox.checked;
      state[domain] = next;
      saveManualDomainChecklistState(state);
      renderManualChecklist();
    });

    hybridChecklistList?.addEventListener("change", (event) => {
      const checkbox = event.target.closest("input[data-hybrid-check]");
      if (!checkbox) {
        return;
      }
      const state = loadHybridChecklistState();
      state[checkbox.dataset.hybridCheck] = checkbox.checked;
      saveHybridChecklistState(state);
      renderHybridChecklist();
    });

    manualRunXSS?.addEventListener("click", async () => {
      const selected = selectedManualDomain();
      if (!selected) {
        if (manualXSSStatus) {
          manualXSSStatus.textContent = "Choose a domain first.";
        }
        return;
      }
      const target = String(manualDomainUrl?.value || "").trim() || `https://${selected}`;
      const authHeader = String(manualAuthHeader?.value || "").trim();
      applyManualXSSRunnerAvailability(true);
      if (manualXSSStatus) {
        manualXSSStatus.textContent = "Starting manual XSS scan...";
      }
      try {
        const response = await fetch(`${backendUrl}/api/manual/xss-run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: selected, target, auth_header: authHeader }),
        });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        await refreshManualXSSStatus();
      } catch (error) {
        if (manualXSSStatus) {
          manualXSSStatus.textContent = `Launch failed: ${error.message}`;
        }
        applyManualXSSRunnerAvailability(false);
      }
    });
  }

  return {
    initializeManualDomainChecklist,
    refreshManualDomainOptions,
    refreshManualXSSStatus,
  };
}
