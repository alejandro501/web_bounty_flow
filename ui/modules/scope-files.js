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
  paramFuzzBaselineFilter,
  paramFuzzMutatedFilter,
  closeFileViewer,
  openFileViewerExport,
  fileViewerExportMenu,
  editFileViewer,
  saveFileViewer,
  fileViewerEditor,
}) {
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

  async function fetchListMeta(type) {
    const response = await fetch(`${backendUrl}/api/list?type=${encodeURIComponent(type)}`);
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

  function isParamFuzzHitsType(type) {
    return [
      "param_fuzz_query_hits",
      "param_fuzz_body_hits",
      "param_fuzz_header_hits",
      "param_fuzz_cookie_hits",
    ].includes(String(type || "").trim());
  }

  function updateParamFuzzFilterOptions(rows) {
    if (!fileViewerFilters || !paramFuzzBaselineFilter || !paramFuzzMutatedFilter) {
      return;
    }
    const enabled = isParamFuzzHitsType(currentFileModalType) && Array.isArray(rows) && rows.length > 0;
    fileViewerFilters.hidden = !enabled || fileViewerEditing;
    if (!enabled) {
      return;
    }
    const baselineCurrent = paramFuzzBaselineFilter.value;
    const mutatedCurrent = paramFuzzMutatedFilter.value;
    const baselineCodes = [...new Set(rows.map((row) => String(row.baseline_status_code || "").trim()).filter(Boolean))].sort((a, b) => Number(a) - Number(b));
    const mutatedCodes = [...new Set(rows.map((row) => String(row.mutated_status_code || "").trim()).filter(Boolean))].sort((a, b) => Number(a) - Number(b));
    paramFuzzBaselineFilter.innerHTML = [`<option value="">All baseline status codes</option>`, ...baselineCodes.map((code) => `<option value="${escapeHTML(code)}">${escapeHTML(code)}</option>`)].join("");
    paramFuzzMutatedFilter.innerHTML = [`<option value="">All mutated status codes</option>`, ...mutatedCodes.map((code) => `<option value="${escapeHTML(code)}">${escapeHTML(code)}</option>`)].join("");
    if (baselineCodes.includes(baselineCurrent)) {
      paramFuzzBaselineFilter.value = baselineCurrent;
    }
    if (mutatedCodes.includes(mutatedCurrent)) {
      paramFuzzMutatedFilter.value = mutatedCurrent;
    }
  }

  function normalizeFilterValue(value) {
    return (value || "").toString().toLowerCase().trim();
  }

  function getFilteredParamFuzzRows(rows) {
    const baselineNeedle = normalizeFilterValue(paramFuzzBaselineFilter?.value);
    const mutatedNeedle = normalizeFilterValue(paramFuzzMutatedFilter?.value);
    return (rows || []).filter((row) => (
      (!baselineNeedle || normalizeFilterValue(row.baseline_status_code) === baselineNeedle) &&
      (!mutatedNeedle || normalizeFilterValue(row.mutated_status_code) === mutatedNeedle)
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
    if (fileViewerEditing && fileViewerExportMenu) {
      fileViewerExportMenu.hidden = true;
    }
    if (fileViewerFilters) {
      fileViewerFilters.hidden = fileViewerEditing || !isParamFuzzHitsType(currentFileModalType) || currentFileModalRows.length === 0;
    }
  }

  function renderFileViewerData(lines) {
    const parsed = parseJSONLRows(lines);
    currentFileModalRows = parsed.rows;
    currentFileModalColumns = parsed.columns;
    applyFileViewerExportFormatOptions(parsed.ok);
    updateParamFuzzFilterOptions(parsed.rows);

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
    if (isParamFuzzHitsType(currentFileModalType)) {
      const filteredRows = getFilteredParamFuzzRows(parsed.rows);
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
    applyFileViewerExportFormatOptions(false);
    if (paramFuzzBaselineFilter) {
      paramFuzzBaselineFilter.value = "";
    }
    if (paramFuzzMutatedFilter) {
      paramFuzzMutatedFilter.value = "";
    }
    if (fileViewerFilters) {
      fileViewerFilters.hidden = true;
    }
    setFileViewerEditing(false);
    fileViewerTitle.textContent = label;
    if (fileViewerDescription) {
      fileViewerDescription.textContent = describeListFile(type, label);
    }
    fileViewerContent.classList.remove("log-view--table");
    fileViewerContent.textContent = "Loading...";
    fileViewerModal.hidden = false;
    try {
      const data = await fetchListMeta(type);
      currentFileModalLines = Array.isArray(data.entries) ? data.entries : [];
      currentFileModalRawText = currentFileModalLines.join("\n");
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
        const rows = isParamFuzzHitsType(type) ? getFilteredParamFuzzRows(parsed.rows) : parsed.rows;
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
      .map(({ type }) => `${type}:${states[type]?.present ? "1" : "0"}:${states[type]?.entries?.length || 0}`)
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
        states[type] = await fetchListMeta(type);
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
    fileViewerExportMenu.hidden = !fileViewerExportMenu.hidden;
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

  fileViewerModal?.addEventListener("click", (event) => {
    if (event.target === fileViewerModal) {
      fileViewerModal.hidden = true;
      setFileViewerEditing(false);
      if (fileViewerExportMenu) {
        fileViewerExportMenu.hidden = true;
      }
    }
  });

  document.addEventListener("click", (event) => {
    if (!openFileViewerExport || !fileViewerExportMenu || fileViewerExportMenu.hidden) {
      return;
    }
    const clickedButton = openFileViewerExport.contains(event.target);
    const clickedMenu = fileViewerExportMenu.contains(event.target);
    if (!clickedButton && !clickedMenu) {
      fileViewerExportMenu.hidden = true;
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && fileViewerModal && !fileViewerModal.hidden) {
      fileViewerModal.hidden = true;
      setFileViewerEditing(false);
      if (fileViewerExportMenu) {
        fileViewerExportMenu.hidden = true;
      }
    }
  });

  [paramFuzzBaselineFilter, paramFuzzMutatedFilter].forEach((element) => {
    element?.addEventListener("input", () => renderFileViewerData(currentFileModalLines));
    element?.addEventListener("change", () => renderFileViewerData(currentFileModalLines));
  });

  return {
    fetchListMeta,
    initializeScopeCards,
    refreshScopeCards,
  };
}
