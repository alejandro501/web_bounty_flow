export function initScopeFilesFeature({
  backendUrl,
  listFiles,
  generatedFileGroups,
  fileExplanations,
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
  openFileViewerAquatone,
  fileViewerAquatoneMenu,
  fileViewerAquatoneStatus,
  openFileViewerExport,
  fileViewerExportMenu,
  editFileViewer,
  saveFileViewer,
  fileViewerEditor,
  aquatoneGalleryModal,
  aquatoneGalleryTitle,
  aquatoneGallerySubtitle,
  aquatoneGalleryContent,
  closeAquatoneGallery,
  aquatoneImageModal,
  aquatoneImageTitle,
  aquatoneImageSubtitle,
  aquatoneImagePreview,
  closeAquatoneImage,
  aquatoneDashboardStatus,
  aquatoneDashboardSections,
}) {
  const FILE_VIEWER_PREVIEW_LIMIT = 5000;
  const AQUATONE_DASHBOARD_TYPES = ["domains_http", "domains", "apidomains_http", "apidomains", "robots_urls", "wayback_urls", "katana_urls", "all_urls"];
  const AQUATONE_SUPPORTED_TYPES = new Set(AQUATONE_DASHBOARD_TYPES);
  const scopeCardNodes = new Map();
  let lastScopeSignature = "";
  let currentFileModalType = "";
  let currentFileModalLabel = "";
  let currentFileModalLines = [];
  let currentFileModalRows = [];
  let currentFileModalColumns = [];
  let fileViewerEditing = false;
  let fileViewerExportStructured = false;
  let currentFileModalRawText = "";
  let aquatoneAutoOpenOnComplete = false;
  let lastAquatoneStatusType = "";

  async function fetchListMeta(type, options = {}) {
    const params = new URLSearchParams({ type: String(type || "") });
    if (options.metaOnly) {
      params.set("meta", "1");
    }
    if (Number.isInteger(options.limit) && options.limit > 0) {
      params.set("limit", String(options.limit));
    }
    const response = await fetch(`${backendUrl}/api/list?${params.toString()}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }

    const data = await response.json();
    if (Array.isArray(data.entries)) {
      const present = typeof data.present === "boolean" ? data.present : data.entries.length > 0;
      return {
        present,
        count: Number.isFinite(data.count) ? Number(data.count) : data.entries.length,
        entries: data.entries,
        truncated: Boolean(data.truncated),
        previewMax: Number.isFinite(data.preview_max) ? Number(data.preview_max) : 0,
      };
    }

    return { present: false, count: 0, entries: [], truncated: false, previewMax: 0 };
  }

  async function saveScopeFileContent(type, content) {
    const response = await fetch(`${backendUrl}/api/list?type=${encodeURIComponent(type)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  function supportsAquatone(type) {
    return AQUATONE_SUPPORTED_TYPES.has(String(type || "").trim().toLowerCase());
  }

  async function fetchAquatoneStatus(type) {
    const response = await fetch(`${backendUrl}/api/aquatone/status?type=${encodeURIComponent(type)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function runAquatone(type) {
    const response = await fetch(`${backendUrl}/api/aquatone/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function stopAquatone(type) {
    const response = await fetch(`${backendUrl}/api/aquatone/stop`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function fetchAquatoneGallery(type) {
    const response = await fetch(`${backendUrl}/api/aquatone/gallery?type=${encodeURIComponent(type)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function fetchAquatoneLog(type) {
    const response = await fetch(`${backendUrl}/api/aquatone/log?type=${encodeURIComponent(type)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.text();
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

    const response = await fetch(`${backendUrl}/api/upload`, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error(await response.text());
    }

    await refreshScopeCards();

    if (scopeCardsStatus) {
      scopeCardsStatus.textContent = `Uploaded ${file.name} to ${type}`;
    }
  }

  function describeListFile(type, label) {
    const key = String(type || "").trim();
    if (fileExplanations[key]) {
      return fileExplanations[key];
    }
    const fallback = String(label || key || "artifact").trim();
    return `${fallback}: generated artifact from the flow; open to inspect entries and export for reporting.`;
  }

  function isLikelyURL(value) {
    const text = String(value || "").trim();
    return /^https?:\/\/\S+$/i.test(text);
  }

  function renderTableCellValue(value) {
    const text = normalizeTableCellValue(value);
    if (isLikelyURL(text)) {
      const safe = escapeHTML(text);
      return `<a href="${safe}" target="_blank" rel="noopener noreferrer"><code>${safe}</code></a>`;
    }
    return escapeHTML(text);
  }

  function renderRawTextWithLinks(lines) {
    if (!fileViewerContent) {
      return;
    }
    const text = Array.isArray(lines) ? lines.join("\n") : String(lines || "");
    const escaped = escapeHTML(text);
    const linked = escaped.replace(/(https?:\/\/[^\s<]+)/g, (match) => (
      `<a href="${match}" target="_blank" rel="noopener noreferrer"><code>${match}</code></a>`
    ));
    fileViewerContent.innerHTML = linked;
  }

  function parseJSONLRows(lines) {
    const rows = [];
    const columns = [];
    const columnSet = new Set();
    let sawAnyLine = false;
    for (const rawLine of lines || []) {
      const line = String(rawLine || "").trim();
      if (!line) {
        continue;
      }
      sawAnyLine = true;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        return { ok: false, rows: [], columns: [] };
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, rows: [], columns: [] };
      }
      rows.push(parsed);
      Object.keys(parsed).forEach((key) => {
        if (!columnSet.has(key)) {
          columnSet.add(key);
          columns.push(key);
        }
      });
    }
    if (!sawAnyLine || rows.length === 0 || columns.length === 0) {
      return { ok: false, rows: [], columns: [] };
    }
    return { ok: true, rows, columns };
  }

  function applyFileViewerExportFormatOptions(isStructured) {
    fileViewerExportStructured = Boolean(isStructured);
    if (!fileViewerExportMenu) {
      return;
    }
    fileViewerExportMenu
      .querySelectorAll("button[data-export-format='csv'], button[data-export-format='json']")
      .forEach((button) => {
        button.disabled = !isStructured;
      });
  }

  function setAquatoneStatusMessage(message = "", visible = false) {
    if (!fileViewerAquatoneStatus) {
      return;
    }
    fileViewerAquatoneStatus.textContent = message || "Aquatone idle.";
    fileViewerAquatoneStatus.hidden = !visible;
  }

  function updateFileViewerAquatoneVisibility() {
    const supported = supportsAquatone(currentFileModalType);
    if (openFileViewerAquatone) {
      openFileViewerAquatone.hidden = !supported;
      openFileViewerAquatone.disabled = fileViewerEditing || !supported;
    }
    if (!supported) {
      if (fileViewerAquatoneMenu) {
        fileViewerAquatoneMenu.hidden = true;
      }
      setAquatoneStatusMessage("", false);
    }
    return supported;
  }

  function setAquatoneDashboardStatus(message = "") {
    if (!aquatoneDashboardStatus) {
      return;
    }
    aquatoneDashboardStatus.textContent = message || "Aquatone idle.";
  }

  function aquatoneLabelForType(type) {
    const item = listFiles.find((entry) => entry.type === type);
    return item?.label || type;
  }

  function aquatoneSectionForType(type) {
    return aquatoneDashboardSections?.querySelector(`.aquatone-dashboard-section[data-aquatone-type="${CSS.escape(type)}"]`) || null;
  }

  function setAquatoneSectionLog(section, message = "", options = {}) {
    const logElement = section?.querySelector("[data-aquatone-log]");
    if (!logElement) {
      return;
    }
    const text = String(message || "").trimEnd();
    logElement.textContent = text || "Aquatone logs will appear here when screenshots are running.";
    if (options.scrollToEnd) {
      logElement.scrollTop = logElement.scrollHeight;
    }
  }

  function updateAquatoneSectionActions(section, status = null) {
    const running = Boolean(status?.running);
    const available = Boolean(status?.available);
    const runButton = section?.querySelector("button[data-aquatone-dashboard-action='run']");
    const stopButton = section?.querySelector("button[data-aquatone-dashboard-action='stop']");
    if (runButton) {
      runButton.disabled = running;
      if (running) {
        runButton.textContent = "Screenshots In Progress";
      } else if (available) {
        runButton.textContent = "Take Fresh Screenshots";
      } else {
        runButton.textContent = "Take Screenshots";
      }
    }
    if (stopButton) {
      stopButton.hidden = !running;
      stopButton.disabled = !running;
    }
  }

  function formatAquatoneOutputNote(status = null) {
    const outputDir = String(status?.output_dir || "").trim();
    if (!outputDir) {
      return "";
    }
    return ` Output: ${outputDir}`;
  }

  function aquatoneStatusText(status = null, label = "Aquatone") {
    if (!status) {
      return "Aquatone ready. Choose Open Existing Gallery or Take New Screenshots.";
    }
    if (status.running) {
      return `Aquatone running for ${label}...${formatAquatoneOutputNote(status)}`;
    }
    if (status.last_error) {
      const failedLog = String(status.failed_log || "").trim();
      const logNote = failedLog ? ` Log: ${failedLog}` : "";
      return `Aquatone error: ${status.last_error}.${logNote}`;
    }
    if (status.available) {
      const countText = Number(status.screenshot_count || 0).toLocaleString();
      const groupText = Number(status.group_count || 0).toLocaleString();
      return `Aquatone gallery ready: ${countText} screenshots across ${groupText} groups.${formatAquatoneOutputNote(status)}`;
    }
    return `No Aquatone screenshots available for this file yet.${formatAquatoneOutputNote(status)}`;
  }

  function applyAquatoneMenuState(status = null, errorMessage = "") {
    const supported = updateFileViewerAquatoneVisibility();
    if (!fileViewerAquatoneMenu) {
      return;
    }
    const viewButton = fileViewerAquatoneMenu.querySelector("button[data-aquatone-action='view']");
    const runButton = fileViewerAquatoneMenu.querySelector("button[data-aquatone-action='run']");
    if (viewButton) {
      viewButton.disabled = !status?.available || Boolean(status?.running);
    }
    if (runButton) {
      runButton.disabled = Boolean(status?.running) || !supportsAquatone(currentFileModalType);
    }
    if (errorMessage) {
      setAquatoneStatusMessage(`Aquatone error: ${errorMessage}`, true);
      return;
    }
    if (!supported) {
      setAquatoneStatusMessage("", false);
      return;
    }
    setAquatoneStatusMessage(aquatoneStatusText(status, currentFileModalLabel || currentFileModalType), true);
  }

  function renderAquatoneGallery(type, data, target = aquatoneGalleryContent) {
    if (!target) {
      return;
    }
    const groups = Array.isArray(data?.groups) ? data.groups : [];
    if (!groups.length) {
      target.innerHTML = '<p class="muted">No screenshots available yet.</p>';
      return;
    }
    target.innerHTML = groups.map((group, index) => `
      <details class="aquatone-group" ${index === 0 ? "open" : ""}>
        <summary>
          <span>${escapeHTML(group.root_domain || "(unknown)")}</span>
          <span class="lead-domain-meta">${escapeHTML(String(group.count || 0))} screenshots</span>
        </summary>
        <div class="aquatone-grid">
          ${(group.pages || []).map((page) => {
            const screenshotUrl = `${backendUrl}/api/aquatone/asset?type=${encodeURIComponent(type)}&path=${encodeURIComponent(page.screenshot_path || "")}`;
            return `
              <article class="aquatone-card">
                <div class="aquatone-card__url">
                  <a href="${escapeHTML(page.url || "#")}" target="_blank" rel="noopener noreferrer">${escapeHTML(page.url || page.hostname || "")}</a>
                </div>
                <div class="aquatone-card__meta">
                  <span>${escapeHTML(page.status || "")}</span>
                  ${page.title ? `<span>${escapeHTML(page.title)}</span>` : ""}
                </div>
                <a class="aquatone-card__shot" href="${escapeHTML(screenshotUrl)}" data-aquatone-image-url="${escapeHTML(screenshotUrl)}" data-aquatone-image-title="${escapeHTML(page.url || page.hostname || "Aquatone page")}" target="_blank" rel="noopener noreferrer" aria-label="Open larger screenshot for ${escapeHTML(page.url || page.hostname || "Aquatone page")}">
                  <img src="${escapeHTML(screenshotUrl)}" alt="${escapeHTML(page.url || page.hostname || "Aquatone screenshot")}" loading="lazy" />
                </a>
              </article>
            `;
          }).join("")}
        </div>
      </details>
    `).join("");
  }

  async function openAquatoneGallery(type, label) {
    if (!aquatoneGalleryModal || !aquatoneGalleryContent) {
      return;
    }
    aquatoneGalleryModal.hidden = false;
    if (aquatoneGalleryTitle) {
      aquatoneGalleryTitle.textContent = `${label || type || "Scope File"} Aquatone`;
    }
    if (aquatoneGallerySubtitle) {
      aquatoneGallerySubtitle.textContent = "Loading screenshots...";
    }
    aquatoneGalleryContent.innerHTML = '<p class="muted">Loading screenshots...</p>';
    try {
      const data = await fetchAquatoneGallery(type);
      if (aquatoneGallerySubtitle) {
        const generated = data?.generated_at ? new Date(data.generated_at).toLocaleString() : "unknown time";
        const limitNote = data?.preview_limited ? ` Showing first ${Number(data.preview_max_items || 0).toLocaleString()} screenshots.` : "";
        aquatoneGallerySubtitle.textContent = `Grouped by main domain. Generated ${generated}.${limitNote}`;
      }
      renderAquatoneGallery(type, data);
    } catch (error) {
      aquatoneGalleryContent.innerHTML = `<p class="muted">Aquatone gallery error: ${escapeHTML(error.message)}</p>`;
      if (aquatoneGallerySubtitle) {
        aquatoneGallerySubtitle.textContent = "Aquatone screenshots are not available yet.";
      }
    }
  }

  function openAquatoneImagePreview(src, title) {
    if (!aquatoneImageModal || !aquatoneImagePreview) {
      window.open(src, "_blank", "noopener,noreferrer");
      return;
    }
    aquatoneImagePreview.src = src;
    aquatoneImagePreview.alt = title ? `Aquatone screenshot preview for ${title}` : "Aquatone screenshot preview";
    if (aquatoneImageTitle) {
      aquatoneImageTitle.textContent = "Screenshot";
    }
    if (aquatoneImageSubtitle) {
      aquatoneImageSubtitle.textContent = title || "";
    }
    aquatoneImageModal.hidden = false;
  }

  function closeAquatoneImagePreview() {
    if (!aquatoneImageModal) {
      return;
    }
    aquatoneImageModal.hidden = true;
    if (aquatoneImagePreview) {
      aquatoneImagePreview.removeAttribute("src");
    }
  }

  async function refreshAquatoneStatus(type = currentFileModalType) {
    const normalizedType = String(type || "").trim().toLowerCase();
    lastAquatoneStatusType = normalizedType;
    if (!supportsAquatone(normalizedType)) {
      applyAquatoneMenuState(null);
      return null;
    }
    try {
      const status = await fetchAquatoneStatus(normalizedType);
      if (lastAquatoneStatusType !== normalizedType) {
        return status;
      }
      applyAquatoneMenuState(status);
      if (aquatoneAutoOpenOnComplete && !status.running && status.available && normalizedType === currentFileModalType) {
        aquatoneAutoOpenOnComplete = false;
        void openAquatoneGallery(normalizedType, currentFileModalLabel);
      }
      return status;
    } catch (error) {
      applyAquatoneMenuState(null, error.message);
      return null;
    }
  }

  function ensureAquatoneDashboardSections() {
    if (!aquatoneDashboardSections || aquatoneDashboardSections.dataset.rendered === "1") {
      return;
    }
    aquatoneDashboardSections.innerHTML = AQUATONE_DASHBOARD_TYPES.map((type, index) => {
      const label = aquatoneLabelForType(type);
      return `
        <details class="aquatone-dashboard-section" data-aquatone-type="${escapeHTML(type)}" ${index === 0 ? "open" : ""}>
          <summary>
            <span>${escapeHTML(label)}</span>
            <span class="lead-domain-meta" data-aquatone-status>Checking...</span>
          </summary>
          <div class="aquatone-dashboard-section__body">
            <div class="aquatone-dashboard__actions">
              <button type="button" data-aquatone-dashboard-action="run">Take Screenshots</button>
              <button type="button" class="button-secondary" data-aquatone-dashboard-action="stop" hidden>Stop Process</button>
              <button type="button" class="button-secondary" data-aquatone-dashboard-action="refresh">Refresh</button>
            </div>
            <div class="aquatone-gallery aquatone-gallery--page" data-aquatone-gallery>
              <p class="muted">${escapeHTML(label)} screenshots will appear here after Aquatone runs.</p>
            </div>
            <pre class="log-view aquatone-log-view" data-aquatone-log>Aquatone logs will appear here when screenshots are running.</pre>
          </div>
        </details>
      `;
    }).join("");
    aquatoneDashboardSections.dataset.rendered = "1";
  }

  async function refreshAquatoneDashboard() {
    if (!aquatoneDashboardSections) {
      return null;
    }
    ensureAquatoneDashboardSections();
    const statuses = await Promise.all(AQUATONE_DASHBOARD_TYPES.map((type) => refreshAquatoneDashboardSection(type)));
    const runningCount = statuses.filter((status) => status?.running).length;
    const availableCount = statuses.filter((status) => status?.available).length;
    if (runningCount > 0) {
      setAquatoneDashboardStatus(`${runningCount} Aquatone screenshot run${runningCount === 1 ? "" : "s"} in progress.`);
    } else {
      setAquatoneDashboardStatus(`${availableCount} / ${AQUATONE_DASHBOARD_TYPES.length} Aquatone galleries available.`);
    }
    return statuses;
  }

  async function refreshAquatoneDashboardSection(type) {
    const section = aquatoneSectionForType(type);
    if (!section) {
      return null;
    }
    const label = aquatoneLabelForType(type);
    const statusElement = section.querySelector("[data-aquatone-status]");
    const galleryElement = section.querySelector("[data-aquatone-gallery]");
    try {
      const status = await fetchAquatoneStatus(type);
      if (statusElement) {
        statusElement.textContent = aquatoneStatusText(status, label);
      }
      updateAquatoneSectionActions(section, status);
      await refreshAquatoneSectionLog(type, status);
      if (status.available && galleryElement) {
        const data = await fetchAquatoneGallery(type);
        renderAquatoneGallery(type, data, galleryElement);
      } else if (galleryElement && !status.running) {
        galleryElement.innerHTML = `<p class="muted">${escapeHTML(label)} screenshots will appear here after Aquatone runs.</p>`;
      }
      return status;
    } catch (error) {
      if (statusElement) {
        statusElement.textContent = `Aquatone error: ${error.message}`;
      }
      updateAquatoneSectionActions(section, null);
      setAquatoneSectionLog(section, `Aquatone log unavailable: ${error.message}`);
      return null;
    }
  }

  async function refreshAquatoneSectionLog(type, status = null) {
    const section = aquatoneSectionForType(type);
    if (!section) {
      return;
    }
    try {
      const logText = await fetchAquatoneLog(type);
      if (logText.trim()) {
        setAquatoneSectionLog(section, logText, { scrollToEnd: Boolean(status?.running) });
        return;
      }
      if (status?.running) {
        setAquatoneSectionLog(section, "Aquatone is running. Waiting for log output...");
        return;
      }
      if (status?.last_error) {
        setAquatoneSectionLog(section, `Aquatone failed: ${status.last_error}`);
        return;
      }
      setAquatoneSectionLog(section, "");
    } catch (error) {
      setAquatoneSectionLog(section, `Aquatone log unavailable: ${error.message}`);
    }
  }

  async function runDashboardAquatone(type) {
    const section = aquatoneSectionForType(type);
    const label = aquatoneLabelForType(type);
    updateAquatoneSectionActions(section, { running: true });
    const statusElement = section?.querySelector("[data-aquatone-status]");
    if (statusElement) {
      statusElement.textContent = `Starting Aquatone for ${label}...`;
    }
    setAquatoneSectionLog(section, "Starting Aquatone...");
    try {
      const startStatus = await runAquatone(type);
      if (statusElement) {
        statusElement.textContent = `Aquatone queued for ${label}.${formatAquatoneOutputNote(startStatus)}`;
      }
      await refreshAquatoneDashboardSection(type);
    } catch (error) {
      if (statusElement) {
        statusElement.textContent = `Aquatone error: ${error.message}`;
      }
      updateAquatoneSectionActions(section, null);
    }
  }

  async function stopDashboardAquatone(type) {
    const section = aquatoneSectionForType(type);
    const label = aquatoneLabelForType(type);
    const stopButton = section?.querySelector("button[data-aquatone-dashboard-action='stop']");
    const statusElement = section?.querySelector("[data-aquatone-status]");
    if (stopButton) {
      stopButton.disabled = true;
    }
    if (statusElement) {
      statusElement.textContent = `Stopping Aquatone for ${label}...`;
    }
    try {
      await stopAquatone(type);
      await refreshAquatoneDashboardSection(type);
    } catch (error) {
      if (statusElement) {
        statusElement.textContent = `Aquatone stop error: ${error.message}`;
      }
      if (stopButton) {
        stopButton.disabled = false;
      }
    }
  }

  function isHopByHopDifferingStatusType(type) {
    return String(type || "").trim() === "smuggling_stack_findings";
  }

  function updateHopByHopFilterOptions(rows) {
    if (!fileViewerFilters || !hopByHopStatusFilter) {
      return;
    }
    const enabled = isHopByHopDifferingStatusType(currentFileModalType) && Array.isArray(rows) && rows.length > 0;
    fileViewerFilters.hidden = !enabled || fileViewerEditing;
    if (!enabled) {
      return;
    }
    const current = hopByHopStatusFilter.value;
    const statusCodes = [...new Set(rows.map((row) => String(row.mutated_status_code || row.status_code || "").trim()).filter(Boolean))]
      .sort((a, b) => Number(a) - Number(b));
    hopByHopStatusFilter.innerHTML = [`<option value="">All hop-by-hop status codes</option>`, ...statusCodes.map((code) => `<option value="${escapeHTML(code)}">${escapeHTML(code)}</option>`)].join("");
    if (statusCodes.includes(current)) {
      hopByHopStatusFilter.value = current;
    }
  }

  function normalizeFilterValue(value) {
    return (value || "").toString().toLowerCase().trim();
  }

  function getFilteredHopByHopRows(rows) {
    const statusNeedle = normalizeFilterValue(hopByHopStatusFilter?.value);
    return (rows || []).filter((row) => (
      !statusNeedle || normalizeFilterValue(row.mutated_status_code || row.status_code) === statusNeedle
    ));
  }

  function statusCodeClass(statusCode) {
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

  function renderStructuredTable(rows, columns, options = {}) {
    const rowClass = typeof options.rowClass === "function" ? options.rowClass : () => "";
    const body = rows.map((row) => {
      const cells = columns.map((column) => `<td>${renderTableCellValue(row[column])}</td>`).join("");
      const rowClasses = rowClass(row);
      return `<tr${rowClasses ? ` class="${rowClasses}"` : ""}>${cells}</tr>`;
    }).join("");
    const header = columns.map((column) => `<th>${escapeHTML(column)}</th>`).join("");
    return `
      <div class="modal-table-wrap file-viewer-table-wrap">
        <table class="lws-table">
          <thead><tr>${header}</tr></thead>
          <tbody>${body || `<tr><td colspan="${columns.length}" class="muted">No matching rows.</td></tr>`}</tbody>
        </table>
      </div>
    `;
  }

  function setFileViewerEditing(editing) {
    fileViewerEditing = Boolean(editing);
    if (fileViewerEditor) {
      fileViewerEditor.hidden = !fileViewerEditing;
      if (fileViewerEditing) {
        fileViewerEditor.value = currentFileModalRawText || "";
      }
    }
    if (fileViewerContent) {
      fileViewerContent.hidden = fileViewerEditing;
    }
    if (saveFileViewer) {
      saveFileViewer.disabled = !fileViewerEditing;
    }
    if (editFileViewer) {
      editFileViewer.textContent = fileViewerEditing ? "Cancel Edit" : "Edit";
    }
    if (openFileViewerExport) {
      openFileViewerExport.disabled = fileViewerEditing;
    }
    updateFileViewerAquatoneVisibility();
    if (fileViewerEditing && fileViewerExportMenu) {
      fileViewerExportMenu.hidden = true;
    }
    if (fileViewerEditing && fileViewerAquatoneMenu) {
      fileViewerAquatoneMenu.hidden = true;
    }
    if (fileViewerFilters) {
      fileViewerFilters.hidden = fileViewerEditing || !isHopByHopDifferingStatusType(currentFileModalType) || currentFileModalRows.length === 0;
    }
  }

  function renderFileViewerData(lines) {
    const parsed = parseJSONLRows(lines);
    currentFileModalRows = parsed.rows;
    currentFileModalColumns = parsed.columns;
    applyFileViewerExportFormatOptions(parsed.ok);
    updateHopByHopFilterOptions(parsed.rows);

    if (!fileViewerContent) {
      return;
    }
    if (!Array.isArray(lines) || lines.length === 0) {
      fileViewerContent.classList.remove("log-view--table");
      fileViewerContent.textContent = "No entries yet.";
      return;
    }

    if (!parsed.ok) {
      if (fileViewerFilters) {
        fileViewerFilters.hidden = true;
      }
      fileViewerContent.classList.remove("log-view--table");
      renderRawTextWithLinks(lines);
      return;
    }

    fileViewerContent.classList.add("log-view--table");
    if (isHopByHopDifferingStatusType(currentFileModalType)) {
      const filteredRows = getFilteredHopByHopRows(parsed.rows);
      fileViewerContent.innerHTML = renderStructuredTable(filteredRows, parsed.columns, {
        rowClass: (row) => {
          const statusClass = statusCodeClass(row?.mutated_status_code);
          return statusClass ? `lws-row ${statusClass}` : "";
        },
      });
      return;
    }
    fileViewerContent.innerHTML = renderStructuredTable(parsed.rows, parsed.columns);
  }

  async function openScopeFileModal(type, label) {
    if (!fileViewerModal || !fileViewerContent || !fileViewerTitle) {
      return;
    }
    currentFileModalType = type || "";
    currentFileModalLabel = label || type || "file";
    currentFileModalLines = [];
    currentFileModalRows = [];
    currentFileModalColumns = [];
    currentFileModalRawText = "";
    aquatoneAutoOpenOnComplete = false;
    applyFileViewerExportFormatOptions(false);
    if (hopByHopStatusFilter) {
      hopByHopStatusFilter.value = "";
    }
    if (fileViewerFilters) {
      fileViewerFilters.hidden = true;
    }
    if (fileViewerAquatoneMenu) {
      fileViewerAquatoneMenu.hidden = true;
    }
    updateFileViewerAquatoneVisibility();
    setFileViewerEditing(false);
    fileViewerTitle.textContent = label;
    if (fileViewerDescription) {
      fileViewerDescription.textContent = describeListFile(type, label);
    }
    applyAquatoneMenuState(null);
    fileViewerContent.classList.remove("log-view--table");
    fileViewerContent.textContent = "Loading...";
    fileViewerModal.hidden = false;
    if (supportsAquatone(type)) {
      void refreshAquatoneStatus(type);
    }
    try {
      const data = await fetchListMeta(type, { limit: FILE_VIEWER_PREVIEW_LIMIT });
      currentFileModalLines = Array.isArray(data.entries) ? data.entries : [];
      currentFileModalRawText = currentFileModalLines.join("\n");
      if (fileViewerDescription) {
        const baseDescription = describeListFile(type, label);
        const previewNote = data.truncated
          ? ` Previewing first ${data.entries.length.toLocaleString()} of ${Number(data.count || data.entries.length).toLocaleString()} lines.`
          : data.count > 0
            ? ` ${Number(data.count).toLocaleString()} lines.`
            : "";
        fileViewerDescription.textContent = `${baseDescription}${previewNote}`;
      }
      renderFileViewerData(currentFileModalLines);
    } catch (error) {
      applyFileViewerExportFormatOptions(false);
      fileViewerContent.classList.remove("log-view--table");
      fileViewerContent.textContent = `Error: ${error.message}`;
    }
  }

  async function exportCurrentFileViewerContent(requestedFormat = "") {
    const type = currentFileModalType;
    if (!type) {
      return;
    }
    try {
      const data = await fetchListMeta(type);
      const lines = Array.isArray(data.entries) ? data.entries : currentFileModalLines;
      const parsed = parseJSONLRows(lines);
      const exportFormat = requestedFormat || (parsed.ok ? "csv" : "txt");
      const base = (currentFileModalLabel || type || "export")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "");
      if (parsed.ok) {
        const rows = isHopByHopDifferingStatusType(type) ? getFilteredHopByHopRows(parsed.rows) : parsed.rows;
        exportStructuredRows(rows, parsed.columns, base || "export", exportFormat, currentFileModalLabel || type || "Export", normalizeTableCellValue);
        return;
      }
      if (exportFormat === "csv" || exportFormat === "json") {
        throw new Error(`${exportFormat.toUpperCase()} export requires structured JSON lines.`);
      }
      if (exportFormat === "md") {
        downloadTextExport(linesToMarkdown(lines, currentFileModalLabel || type || "Export"), "text/markdown;charset=utf-8", `${base || "export"}.md`);
        return;
      }
      downloadTextExport(lines.length ? `${lines.join("\n")}\n` : "", "text/plain;charset=utf-8", `${base || "export"}.txt`);
    } catch (error) {
      if (fileViewerContent) {
        fileViewerContent.textContent = `Export failed: ${error.message}`;
      }
    }
  }

  function updateScopeCards(states) {
    const signature = listFiles
      .map(({ type }) => `${type}:${states[type]?.present ? "1" : "0"}:${Number.isFinite(states[type]?.count) ? states[type].count : (states[type]?.entries?.length || 0)}`)
      .join("|");
    if (signature === lastScopeSignature) {
      return false;
    }
    lastScopeSignature = signature;

    listFiles.forEach(({ type }) => {
      const node = scopeCardNodes.get(type);
      if (!node || !node.status) {
        return;
      }
      const count = Number.isFinite(states[type]?.count) ? states[type].count : (Array.isArray(states[type]?.entries) ? states[type].entries.length : 0);
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
          ${uploadable ? `<input id="${inputId}" name="${inputId}" type="file" accept=".txt,.csv" />` : ""}
          ${uploadable ? `<button type="button" class="scope-card__upload" data-input-id="${inputId}">Upload</button>` : '<p class="muted">Auto-generated by flow.</p>'}
        </article>
      `;
    };

    const uploadableCards = listFiles.filter((item) => item.uploadable).map(renderCard).join("");
    const generatedItems = listFiles.filter((item) => !item.uploadable);
    const generatedByType = new Map(generatedItems.map((item) => [item.type, item]));
    const groupedGeneratedSections = generatedFileGroups.map((group) => {
      const cards = group.types
        .map((type) => generatedByType.get(type))
        .filter(Boolean)
        .map((item) => renderCard(item))
        .join("");
      if (!cards) {
        return "";
      }
      return `
        <details class="scope-generated-group" open>
          <summary class="scope-generated-group__summary">${escapeHTML(group.title)}</summary>
          <div class="scope-group__grid">${cards}</div>
        </details>
      `;
    }).join("");

    const groupedTypes = new Set(generatedFileGroups.flatMap((group) => group.types));
    const otherGeneratedCards = generatedItems
      .filter((item) => !groupedTypes.has(item.type))
      .map((item) => renderCard(item))
      .join("");
    const otherGeneratedSection = otherGeneratedCards
      ? `
        <details class="scope-generated-group" open>
          <summary class="scope-generated-group__summary">Other</summary>
          <div class="scope-group__grid">${otherGeneratedCards}</div>
        </details>
      `
      : "";

    scopeCards.innerHTML = `
      <section class="scope-group">
        <h3 class="scope-group__title">Manual / Uploadable</h3>
        <div class="scope-group__grid">
          ${uploadableCards}
        </div>
      </section>
      <details class="scope-group scope-group--generated">
        <summary class="scope-group__summary">Auto-generated</summary>
        <div class="scope-generated-groups">
          ${groupedGeneratedSections}
          ${otherGeneratedSection}
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

  async function refreshScopeCards() {
    if (!scopeCards) {
      return;
    }

    const states = {};
    const chunks = [];
    for (let index = 0; index < listFiles.length; index += 8) {
      chunks.push(listFiles.slice(index, index + 8));
    }

    await Promise.all(chunks.map(async (chunk) => {
      await Promise.all(chunk.map(async ({ type }) => {
        states[type] = await fetchListMeta(type, { metaOnly: true });
      }));
    }));

    const changed = updateScopeCards(states);
    if (changed && scopeCardsStatus) {
      const available = listFiles.filter(({ type }) => states[type]?.present).length;
      scopeCardsStatus.textContent = `${available} / ${listFiles.length} artifacts available`;
    }
  }

  closeFileViewer?.addEventListener("click", () => {
    if (fileViewerModal) {
      fileViewerModal.hidden = true;
    }
    setFileViewerEditing(false);
    if (fileViewerExportMenu) {
      fileViewerExportMenu.hidden = true;
    }
    if (fileViewerAquatoneMenu) {
      fileViewerAquatoneMenu.hidden = true;
    }
  });

  editFileViewer?.addEventListener("click", () => {
    if (fileViewerEditing) {
      setFileViewerEditing(false);
      return;
    }
    setFileViewerEditing(true);
  });

  saveFileViewer?.addEventListener("click", async () => {
    const type = currentFileModalType;
    if (!type || !fileViewerEditor) {
      return;
    }
    const content = fileViewerEditor.value || "";
    if (saveFileViewer) {
      saveFileViewer.disabled = true;
      saveFileViewer.textContent = "Saving...";
    }
    try {
      await saveScopeFileContent(type, content);
      currentFileModalRawText = content;
      currentFileModalLines = content === "" ? [] : content.split(/\r?\n/);
      renderFileViewerData(currentFileModalLines);
      setFileViewerEditing(false);
      await refreshScopeCards();
      if (scopeCardsStatus) {
        scopeCardsStatus.textContent = `Saved ${currentFileModalLabel || type}`;
      }
    } catch (error) {
      if (fileViewerContent) {
        fileViewerContent.classList.remove("log-view--table");
        fileViewerContent.textContent = `Save failed: ${error.message}`;
      }
    } finally {
      if (saveFileViewer) {
        saveFileViewer.textContent = "Save";
        saveFileViewer.disabled = !fileViewerEditing;
      }
    }
  });

  openFileViewerExport?.addEventListener("click", () => {
    if (!fileViewerExportMenu || fileViewerEditing) {
      return;
    }
    if (fileViewerAquatoneMenu) {
      fileViewerAquatoneMenu.hidden = true;
    }
    fileViewerExportMenu.hidden = !fileViewerExportMenu.hidden;
  });

  openFileViewerAquatone?.addEventListener("click", async () => {
    if (!fileViewerAquatoneMenu || fileViewerEditing || !supportsAquatone(currentFileModalType)) {
      return;
    }
    if (fileViewerExportMenu) {
      fileViewerExportMenu.hidden = true;
    }
    if (fileViewerAquatoneMenu.hidden) {
      const status = await refreshAquatoneStatus(currentFileModalType);
      if (!status) {
        setAquatoneStatusMessage("Aquatone ready. Choose Open Existing Gallery or Take New Screenshots.", true);
      }
    }
    fileViewerAquatoneMenu.hidden = !fileViewerAquatoneMenu.hidden;
  });

  fileViewerExportMenu?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-export-format]");
    if (!button || button.disabled) {
      return;
    }
    const format = (button.dataset.exportFormat || "").trim().toLowerCase();
    if ((format === "csv" || format === "json") && !fileViewerExportStructured) {
      return;
    }
    fileViewerExportMenu.hidden = true;
    await exportCurrentFileViewerContent(format || "txt");
  });

  fileViewerAquatoneMenu?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-aquatone-action]");
    if (!button || button.disabled) {
      return;
    }
    const action = (button.dataset.aquatoneAction || "").trim().toLowerCase();
    fileViewerAquatoneMenu.hidden = true;
    if (action === "view") {
      await openAquatoneGallery(currentFileModalType, currentFileModalLabel);
      return;
    }
    if (action === "run") {
      try {
        aquatoneAutoOpenOnComplete = true;
        setAquatoneStatusMessage(`Starting Aquatone for ${currentFileModalLabel || currentFileModalType}...`, true);
        const startStatus = await runAquatone(currentFileModalType);
        setAquatoneStatusMessage(`Aquatone queued for ${currentFileModalLabel || currentFileModalType}.${formatAquatoneOutputNote(startStatus)}`, true);
        await refreshAquatoneStatus(currentFileModalType);
      } catch (error) {
        aquatoneAutoOpenOnComplete = false;
        applyAquatoneMenuState(null, error.message);
      }
    }
  });

  fileViewerModal?.addEventListener("click", (event) => {
    if (event.target === fileViewerModal) {
      fileViewerModal.hidden = true;
      setFileViewerEditing(false);
      if (fileViewerExportMenu) {
        fileViewerExportMenu.hidden = true;
      }
      if (fileViewerAquatoneMenu) {
        fileViewerAquatoneMenu.hidden = true;
      }
    }
  });

  closeAquatoneGallery?.addEventListener("click", () => {
    if (aquatoneGalleryModal) {
      aquatoneGalleryModal.hidden = true;
    }
  });

  closeAquatoneImage?.addEventListener("click", () => {
    closeAquatoneImagePreview();
  });

  aquatoneDashboardSections?.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-aquatone-dashboard-action]");
    if (!button || button.disabled) {
      return;
    }
    const section = button.closest(".aquatone-dashboard-section");
    const type = section?.dataset.aquatoneType || "";
    if (!supportsAquatone(type)) {
      return;
    }
    const action = button.dataset.aquatoneDashboardAction;
    if (action === "run") {
      void runDashboardAquatone(type);
      return;
    }
    if (action === "stop") {
      void stopDashboardAquatone(type);
      return;
    }
    if (action === "refresh") {
      void refreshAquatoneDashboardSection(type);
    }
  });

  aquatoneGalleryModal?.addEventListener("click", (event) => {
    if (event.target === aquatoneGalleryModal) {
      aquatoneGalleryModal.hidden = true;
    }
  });

  aquatoneImageModal?.addEventListener("click", (event) => {
    if (event.target === aquatoneImageModal) {
      closeAquatoneImagePreview();
    }
  });

  document.addEventListener("click", (event) => {
    const imageLink = event.target.closest("a[data-aquatone-image-url]");
    if (!imageLink) {
      return;
    }
    event.preventDefault();
    openAquatoneImagePreview(imageLink.dataset.aquatoneImageUrl || imageLink.href, imageLink.dataset.aquatoneImageTitle || "");
  });

  document.addEventListener("click", (event) => {
    const clickedExportButton = openFileViewerExport?.contains(event.target);
    const clickedExportMenu = fileViewerExportMenu?.contains(event.target);
    if (fileViewerExportMenu && !fileViewerExportMenu.hidden && !clickedExportButton && !clickedExportMenu) {
      fileViewerExportMenu.hidden = true;
    }
    const clickedAquatoneButton = openFileViewerAquatone?.contains(event.target);
    const clickedAquatoneMenu = fileViewerAquatoneMenu?.contains(event.target);
    if (fileViewerAquatoneMenu && !fileViewerAquatoneMenu.hidden && !clickedAquatoneButton && !clickedAquatoneMenu) {
      fileViewerAquatoneMenu.hidden = true;
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") {
      return;
    }
    if (aquatoneImageModal && !aquatoneImageModal.hidden) {
      closeAquatoneImagePreview();
      return;
    }
    if (aquatoneGalleryModal && !aquatoneGalleryModal.hidden) {
      aquatoneGalleryModal.hidden = true;
      return;
    }
    if (fileViewerModal && !fileViewerModal.hidden) {
      fileViewerModal.hidden = true;
      setFileViewerEditing(false);
      if (fileViewerExportMenu) {
        fileViewerExportMenu.hidden = true;
      }
      if (fileViewerAquatoneMenu) {
        fileViewerAquatoneMenu.hidden = true;
      }
    }
  });

  [hopByHopStatusFilter].forEach((element) => {
    element?.addEventListener("input", () => renderFileViewerData(currentFileModalLines));
    element?.addEventListener("change", () => renderFileViewerData(currentFileModalLines));
  });

  window.setInterval(() => {
    if (fileViewerModal && !fileViewerModal.hidden && supportsAquatone(currentFileModalType)) {
      void refreshAquatoneStatus(currentFileModalType);
    }
    if (document.querySelector(".view-aquatone.is-active")) {
      void refreshAquatoneDashboard();
    }
  }, 5000);

  return {
    fetchListMeta,
    initializeScopeCards,
    refreshScopeCards,
    refreshAquatoneDashboard,
  };
}
