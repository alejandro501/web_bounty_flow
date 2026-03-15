export function initDiscoveryTablesFeature({
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
}) {
  const amassState = {
    rows: [],
    sortKey: "name",
    sortDir: "asc",
  };
  const liveState = {
    rows: [],
    sortKey: "url",
    sortDir: "asc",
  };

  function updateButton(button, label, present, count) {
    if (!button) {
      return;
    }
    const total = Number(count) || 0;
    button.disabled = !present || total === 0;
    button.textContent = `${label} (${total})`;
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

  function compareRows(a, b, sortKey, sortDir) {
    const dir = sortDir === "asc" ? 1 : -1;
    const av = a?.[sortKey];
    const bv = b?.[sortKey];
    if (typeof av === "number" || typeof bv === "number") {
      return ((Number(av) || 0) - (Number(bv) || 0)) * dir;
    }
    return String(av || "").localeCompare(String(bv || ""), undefined, { sensitivity: "base" }) * dir;
  }

  function getFilteredSortedAmassRows() {
    const nameNeedle = normalizeFilterValue(amassSearchName?.value);
    const domainNeedle = normalizeFilterValue(amassSearchDomain?.value);
    const ipNeedle = normalizeFilterValue(amassSearchIP?.value);

    const filtered = amassState.rows.filter((row) => (
      (!nameNeedle || normalizeFilterValue(row.name).includes(nameNeedle)) &&
      (!domainNeedle || normalizeFilterValue(row.domain).includes(domainNeedle)) &&
      (!ipNeedle || normalizeFilterValue(row.ip).includes(ipNeedle))
    ));

    filtered.sort((a, b) => compareRows(a, b, amassState.sortKey, amassState.sortDir));
    return filtered;
  }

  function getFilteredSortedLiveRows() {
    const urlNeedle = normalizeFilterValue(lwsSearchURL?.value);
    const statusNeedle = normalizeFilterValue(lwsFilterStatus?.value);
    const titleNeedle = normalizeFilterValue(lwsSearchTitle?.value);
    const webNeedle = normalizeFilterValue(lwsSearchWebServer?.value);
    const techNeedle = normalizeFilterValue(lwsSearchTech?.value);

    const filtered = liveState.rows.filter((row) => {
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

    filtered.sort((a, b) => compareRows(a, b, liveState.sortKey, liveState.sortDir));
    return filtered;
  }

  function renderAmassTable() {
    if (!amassTableBody || !amassCount) {
      return;
    }
    const filtered = getFilteredSortedAmassRows();
    amassCount.textContent = `Showing ${filtered.length} of ${amassState.rows.length} rows`;
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
    const filtered = getFilteredSortedLiveRows();
    lwsCount.textContent = `Showing ${filtered.length} of ${liveState.rows.length} rows`;
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

  function refreshLiveStatusOptions() {
    if (!lwsFilterStatus) {
      return;
    }
    const statuses = [...new Set(liveState.rows.map((row) => `${row.status_code || ""}`).filter(Boolean))];
    statuses.sort((a, b) => Number(a) - Number(b));
    const current = lwsFilterStatus.value;
    lwsFilterStatus.innerHTML = `<option value="">All status codes</option>${statuses.map((status) => `<option value="${escapeHTML(status)}">${escapeHTML(status)}</option>`).join("")}`;
    if (statuses.includes(current)) {
      lwsFilterStatus.value = current;
    }
  }

  function closeAmassModal() {
    if (amassEnumModal) {
      amassEnumModal.hidden = true;
    }
    if (amassEnumExportMenu) {
      amassEnumExportMenu.hidden = true;
    }
  }

  function closeLiveModal() {
    if (liveWebserversModal) {
      liveWebserversModal.hidden = true;
    }
    if (liveWebserversExportMenu) {
      liveWebserversExportMenu.hidden = true;
    }
  }

  async function refreshAmassEnumRows(options = {}) {
    try {
      const data = await fetchAmassEnum();
      updateButton(openAmassEnum, "Amass Enum", Boolean(data.present), Number(data.count || 0));
      if (!options.renderOnlyIfOpen || (amassEnumModal && !amassEnumModal.hidden)) {
        amassState.rows = Array.isArray(data.rows) ? data.rows : [];
        renderAmassTable();
      }
    } catch {
      updateButton(openAmassEnum, "Amass Enum", false, 0);
    }
  }

  async function refreshLiveWebserverRows(options = {}) {
    try {
      const data = await fetchLiveWebservers();
      updateButton(openLiveWebservers, "Live Web Servers", Boolean(data.present), Number(data.count || 0));
      if (!options.renderOnlyIfOpen || (liveWebserversModal && !liveWebserversModal.hidden)) {
        liveState.rows = Array.isArray(data.rows) ? data.rows : [];
        refreshLiveStatusOptions();
        renderLiveWebserversTable();
      }
    } catch {
      updateButton(openLiveWebservers, "Live Web Servers", false, 0);
    }
  }

  openAmassEnum?.addEventListener("click", async () => {
    if (amassEnumModal) {
      amassEnumModal.hidden = false;
    }
    await refreshAmassEnumRows();
  });

  closeAmassEnum?.addEventListener("click", closeAmassModal);

  exportAmassEnum?.addEventListener("click", () => {
    if (amassEnumExportMenu) {
      amassEnumExportMenu.hidden = !amassEnumExportMenu.hidden;
    }
  });

  amassEnumExportMenu?.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-export-format]");
    if (!button || button.disabled) {
      return;
    }
    const format = String(button.dataset.exportFormat || "").trim().toLowerCase();
    amassEnumExportMenu.hidden = true;
    exportStructuredRows(
      getFilteredSortedAmassRows(),
      ["name", "domain", "ip", "asn"],
      `amass_enum_${Date.now()}`,
      format,
      "Amass Enum Export",
      normalizeTableCellValue,
    );
  });

  exportLiveWebservers?.addEventListener("click", () => {
    if (liveWebserversExportMenu) {
      liveWebserversExportMenu.hidden = !liveWebserversExportMenu.hidden;
    }
  });

  liveWebserversExportMenu?.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-export-format]");
    if (!button || button.disabled) {
      return;
    }
    const format = String(button.dataset.exportFormat || "").trim().toLowerCase();
    liveWebserversExportMenu.hidden = true;
    exportStructuredRows(
      getFilteredSortedLiveRows(),
      ["url", "status_code", "title", "web_server", "technologies", "content_length"],
      `live_webservers_${Date.now()}`,
      format,
      "Live Web Servers Export",
      normalizeTableCellValue,
    );
  });

  amassEnumModal?.addEventListener("click", (event) => {
    if (event.target === amassEnumModal) {
      closeAmassModal();
    }
  });

  openLiveWebservers?.addEventListener("click", async () => {
    if (liveWebserversModal) {
      liveWebserversModal.hidden = false;
    }
    await refreshLiveWebserverRows();
  });

  closeLiveWebservers?.addEventListener("click", closeLiveModal);

  liveWebserversModal?.addEventListener("click", (event) => {
    if (event.target === liveWebserversModal) {
      closeLiveModal();
    }
  });

  [amassSearchName, amassSearchDomain, amassSearchIP].forEach((element) => {
    element?.addEventListener("input", renderAmassTable);
    element?.addEventListener("change", renderAmassTable);
  });

  [...document.querySelectorAll(".lws-table th[data-amass-sort-key]")].forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.amassSortKey;
      if (!key) {
        return;
      }
      if (amassState.sortKey === key) {
        amassState.sortDir = amassState.sortDir === "asc" ? "desc" : "asc";
      } else {
        amassState.sortKey = key;
        amassState.sortDir = "asc";
      }
      renderAmassTable();
    });
  });

  [lwsSearchURL, lwsFilterStatus, lwsSearchTitle, lwsSearchWebServer, lwsSearchTech].forEach((element) => {
    element?.addEventListener("input", renderLiveWebserversTable);
    element?.addEventListener("change", renderLiveWebserversTable);
  });

  document.querySelectorAll(".lws-table th[data-sort-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (!key) {
        return;
      }
      if (liveState.sortKey === key) {
        liveState.sortDir = liveState.sortDir === "asc" ? "desc" : "asc";
      } else {
        liveState.sortKey = key;
        liveState.sortDir = "asc";
      }
      renderLiveWebserversTable();
    });
  });

  document.addEventListener("click", (event) => {
    const exportMenus = [
      { button: exportAmassEnum, menu: amassEnumExportMenu },
      { button: exportLiveWebservers, menu: liveWebserversExportMenu },
    ];
    for (const pair of exportMenus) {
      if (!pair.button || !pair.menu || pair.menu.hidden) {
        continue;
      }
      const clickedButton = pair.button.contains(event.target);
      const clickedMenu = pair.menu.contains(event.target);
      if (!clickedButton && !clickedMenu) {
        pair.menu.hidden = true;
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && amassEnumModal && !amassEnumModal.hidden) {
      closeAmassModal();
    }
    if (event.key === "Escape" && liveWebserversModal && !liveWebserversModal.hidden) {
      closeLiveModal();
    }
  });

  return {
    refreshAmassEnum: refreshAmassEnumRows,
    refreshLiveWebservers: refreshLiveWebserverRows,
    closeOpenMenus(event) {
      const exportMenus = [
        { button: exportAmassEnum, menu: amassEnumExportMenu },
        { button: exportLiveWebservers, menu: liveWebserversExportMenu },
      ];
      for (const pair of exportMenus) {
        if (!pair.button || !pair.menu || pair.menu.hidden) {
          continue;
        }
        const clickedButton = pair.button.contains(event.target);
        const clickedMenu = pair.menu.contains(event.target);
        if (!clickedButton && !clickedMenu) {
          pair.menu.hidden = true;
        }
      }
    },
  };
}
