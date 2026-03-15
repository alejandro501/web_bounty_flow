export function initLeadsChaosFeature({
  backendUrl,
  escapeHTML,
  normalizeTableCellValue,
  isLikelyURL,
  leadsStatus,
  leadsSummary,
  leadsWildcards,
  chaosStatus,
  chaosSummary,
  chaosGroups,
}) {
  let lastLeadsSignature = "";
  let lastChaosSignature = "";

  async function fetchLeads() {
    const response = await fetch(`${backendUrl}/api/leads`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function fetchChaos() {
    const response = await fetch(`${backendUrl}/api/chaos`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  function severityPillClass(severity) {
    const normalized = (severity || "").toString().toLowerCase().trim();
    if (normalized === "high" || normalized === "critical") {
      return "lead-severity--high";
    }
    if (normalized === "medium") {
      return "lead-severity--medium";
    }
    return "lead-severity--low";
  }

  function rootDomainFromHost(host) {
    const raw = String(host || "").trim().toLowerCase();
    const parts = raw.split(".").filter(Boolean);
    if (parts.length < 2) {
      return raw;
    }
    return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  }

  function sortedLeadEvidenceEntries(evidence) {
    if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
      return [];
    }
    const preferred = [
      "method",
      "endpoint",
      "url",
      "param",
      "payload",
      "vector",
      "mutated_url",
      "status_code",
      "baseline_status_code",
      "mutated_status_code",
      "length",
      "baseline_length",
      "mutated_length",
      "duration_ms",
      "baseline_duration_ms",
      "mutated_duration_ms",
      "baseline_location",
      "mutated_location",
      "origin",
      "referer",
      "chain_signals",
      "matcher-name",
      "template-id",
      "template",
      "matched-at",
      "host",
      "ip",
      "port",
      "timestamp",
    ];
    const entries = Object.entries(evidence);
    const rank = new Map(preferred.map((key, index) => [key, index]));
    return entries.sort((a, b) => {
      const ra = rank.has(a[0]) ? rank.get(a[0]) : Number.MAX_SAFE_INTEGER;
      const rb = rank.has(b[0]) ? rank.get(b[0]) : Number.MAX_SAFE_INTEGER;
      if (ra !== rb) {
        return ra - rb;
      }
      return a[0].localeCompare(b[0], undefined, { sensitivity: "base" });
    });
  }

  function renderLeadEvidenceValue(value) {
    const normalized = normalizeTableCellValue(value);
    if (isLikelyURL(normalized)) {
      const safe = escapeHTML(normalized);
      return `<a href="${safe}" target="_blank" rel="noopener noreferrer"><code>${safe}</code></a>`;
    }
    return `<code>${escapeHTML(normalized)}</code>`;
  }

  function renderLeadListBlocks(wildcards, sectionClass = "") {
    if (!Array.isArray(wildcards) || !wildcards.length) {
      return '<p class="muted">No leads in this section.</p>';
    }
    return wildcards.map((wc) => {
      const wildcardName = String(wc.wildcard || "(unmapped)").trim().toLowerCase();
      const domains = Array.isArray(wc.domains) ? wc.domains : [];
      const groupedByRoot = new Map();
      for (const domain of domains) {
        const root = rootDomainFromHost(domain?.domain || "") || "(unmapped)";
        if (!groupedByRoot.has(root)) {
          groupedByRoot.set(root, []);
        }
        groupedByRoot.get(root).push(domain);
      }
      const rootBlocks = [...groupedByRoot.entries()]
        .sort((a, b) => a[0].localeCompare(b[0], undefined, { sensitivity: "base" }))
        .map(([rootDomain, rootDomains]) => {
          const domainHtml = rootDomains.map((domain) => {
            const leads = Array.isArray(domain.leads) ? domain.leads : [];
            const leadsHtml = leads.map((lead) => `
              <details class="lead-item" data-lead-id="${escapeHTML(lead.id || "")}">
                <summary>
                  <div class="lead-item__top">
                    <span class="lead-roi">ROI ${escapeHTML(String(lead.roi || 0))}</span>
                    <span class="lead-severity ${severityPillClass(lead.severity)}">${escapeHTML((lead.severity || "low").toUpperCase())}</span>
                    <span class="lead-category">${escapeHTML(lead.category || "unknown")}${lead.family ? `/${escapeHTML(lead.family)}` : ""}</span>
                    <span class="lead-item__actions">
                      <label class="lead-done-toggle">
                        <input type="checkbox" data-lead-action="done" data-lead-id="${escapeHTML(lead.id || "")}" ${lead.done ? "checked" : ""} />
                        DONE
                      </label>
                      <button type="button" class="lead-options-button" data-lead-action="toggle-menu" data-lead-id="${escapeHTML(lead.id || "")}">Options</button>
                      <button type="button" class="lead-replay-button" data-lead-action="replay" data-lead-id="${escapeHTML(lead.id || "")}">Replay</button>
                    </span>
                  </div>
                  <div class="lead-item__target">${
                  isLikelyURL(lead.target || "")
                    ? `<a href="${escapeHTML(lead.target || "")}" target="_blank" rel="noopener noreferrer"><code>${escapeHTML(lead.target || "")}</code></a>`
                    : `<code>${escapeHTML(lead.target || "")}</code>`
                }</div>
                </summary>
                <div class="lead-item__menu" data-lead-menu="${escapeHTML(lead.id || "")}" hidden>
                  <button type="button" data-lead-action="bucket" data-bucket="hits" data-lead-id="${escapeHTML(lead.id || "")}">Hits</button>
                  <button type="button" data-lead-action="bucket" data-bucket="investigation" data-lead-id="${escapeHTML(lead.id || "")}">Further Investigation</button>
                  <button type="button" data-lead-action="bucket" data-bucket="archive" data-lead-id="${escapeHTML(lead.id || "")}">Archive</button>
                  <button type="button" data-lead-action="bucket" data-bucket="active" data-lead-id="${escapeHTML(lead.id || "")}">Reset to Leads</button>
                  <button type="button" data-lead-action="delete" data-lead-id="${escapeHTML(lead.id || "")}">Delete</button>
                </div>
                ${(() => {
                  const entries = sortedLeadEvidenceEntries(lead.evidence);
                  if (!entries.length) {
                    return '<p class="muted">No evidence attached.</p>';
                  }
                  return `<div class="lead-item__evidence">${entries.map(([key, value]) => `
                    <div class="lead-item__evidence-row">
                      <span class="lead-item__evidence-key">${escapeHTML(key)}</span>
                      <span class="lead-item__evidence-value">${renderLeadEvidenceValue(value)}</span>
                    </div>
                  `).join("")}</div>`;
                })()}
              </details>
            `).join("");
            return `
              <details class="lead-domain ${sectionClass}">
                <summary>
                  <span><code>${escapeHTML(domain.domain || "")}</code></span>
                  <span class="lead-domain-meta">${escapeHTML(String(leads.length))} leads</span>
                </summary>
                ${leadsHtml || '<p class="muted">No leads in this domain.</p>'}
              </details>
            `;
          }).join("");
          return `
            <details class="lead-root-block">
              <summary>
                <span>${escapeHTML(rootDomain)}</span>
                <span class="lead-domain-meta">${escapeHTML(String(rootDomains.length))} domains</span>
              </summary>
              ${domainHtml}
            </details>
          `;
        }).join("");

      return `
        <section class="lead-card ${sectionClass}">
          <header class="lead-card__header">
            <h3>${escapeHTML(wildcardName)}</h3>
            <span>${escapeHTML(String(domains.length))} domains</span>
          </header>
          ${rootBlocks}
        </section>
      `;
    }).join("");
  }

  function renderLeads(data) {
    if (!leadsStatus || !leadsSummary || !leadsWildcards) {
      return;
    }
    const wildcards = Array.isArray(data?.wildcards) ? data.wildcards : [];
    const hitsWildcards = Array.isArray(data?.hits_wildcards) ? data.hits_wildcards : [];
    const investigationWildcards = Array.isArray(data?.investigation_wildcards) ? data.investigation_wildcards : [];
    const archiveWildcards = Array.isArray(data?.archive_wildcards) ? data.archive_wildcards : [];
    const updated = data?.updated_at ? `Updated ${new Date(data.updated_at).toLocaleTimeString()}` : "No lead data yet";
    leadsStatus.textContent = updated;
    leadsSummary.innerHTML = `
      <div class="lead-summary-card"><strong>${escapeHTML(String(data?.lead_count || 0))}</strong><span>Total Leads</span></div>
      <div class="lead-summary-card"><strong>${escapeHTML(String(data?.hit_count || 0))}</strong><span>Hits</span></div>
      <div class="lead-summary-card"><strong>${escapeHTML(String(data?.investigation_count || 0))}</strong><span>Further Investigation</span></div>
      <div class="lead-summary-card"><strong>${escapeHTML(String(data?.archive_count || 0))}</strong><span>Archived</span></div>
    `;
    leadsWildcards.innerHTML = `
      <section class="lead-section">
        <h3>Active Leads</h3>
        ${renderLeadListBlocks(wildcards)}
      </section>
      <section class="lead-section">
        <h3>Hits</h3>
        ${renderLeadListBlocks(hitsWildcards, "lead-card--hits")}
      </section>
      <section class="lead-section">
        <h3>Further Investigation</h3>
        ${renderLeadListBlocks(investigationWildcards, "lead-card--investigation")}
      </section>
      <section class="lead-section">
        <h3>Archive</h3>
        ${renderLeadListBlocks(archiveWildcards, "lead-card--archive")}
      </section>
    `;
  }

  function renderChaos(data) {
    if (!chaosStatus || !chaosSummary || !chaosGroups) {
      return;
    }
    const updated = data?.updated_at ? `Updated ${new Date(data.updated_at).toLocaleTimeString()}` : "No Chaos data yet";
    const groups = Array.isArray(data?.groups) ? data.groups : [];
    chaosStatus.textContent = updated;
    chaosSummary.innerHTML = `
      <div class="lead-summary-card"><strong>${escapeHTML(String(data?.total_domains || 0))}</strong><span>Total Domains</span></div>
      <div class="lead-summary-card"><strong>${escapeHTML(String(groups.length))}</strong><span>Main Domains</span></div>
    `;
    if (!groups.length) {
      chaosGroups.innerHTML = '<p class="muted">No main domains found. Add wildcards/domains first.</p>';
      return;
    }
    chaosGroups.innerHTML = groups.map((group) => {
      const list = (group.domains || []).map((domain) => `
        <tr>
          <td><code>${escapeHTML(domain.domain || "")}</code></td>
          <td>${escapeHTML(String(domain.subdomains || 0))}</td>
          <td>${escapeHTML((domain.ips || []).join(", "))}</td>
          <td>${escapeHTML((domain.sources || []).join(", "))}</td>
        </tr>
      `).join("");
      return `
        <details class="lead-wildcard-card">
          <summary>
            <span><strong>${escapeHTML(group.main_domain || "(unknown)")}</strong></span>
            <span class="lead-domain-meta">Associated: ${escapeHTML(String(group.count || 0))} | DNS subs: ${escapeHTML(String(group.dns_total_subdomains || 0))}</span>
          </summary>
          ${group.error ? `<p class="muted">Error: ${escapeHTML(group.error)}</p>` : ""}
          ${group.dns_error ? `<p class="muted">DNS Error: ${escapeHTML(group.dns_error)}</p>` : ""}
          ${group.sources?.length ? `<p class="muted">Sources: ${escapeHTML(group.sources.join(", "))}</p>` : ""}
          ${group.source_counts && Object.keys(group.source_counts).length ? `<p class="muted">Source counts: ${escapeHTML(Object.entries(group.source_counts).map(([k, v]) => `${k}=${v}`).join(", "))}</p>` : ""}
          ${group.dns_sample_subdomains?.length ? `<p class="muted">Sample subdomains: <code>${escapeHTML(group.dns_sample_subdomains.slice(0, 15).join(", "))}</code></p>` : ""}
          <div class="modal-table-wrap">
            <table class="lws-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Subdomains</th>
                  <th>IPs</th>
                  <th>Sources</th>
                </tr>
              </thead>
              <tbody>${list || "<tr><td colspan='4' class='muted'>No records returned.</td></tr>"}</tbody>
            </table>
          </div>
        </details>
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
        updated_at: data?.updated_at || "",
        lead_count: data?.lead_count || 0,
        hit_count: data?.hit_count || 0,
        investigation_count: data?.investigation_count || 0,
        archive_count: data?.archive_count || 0,
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

  async function refreshChaos(options = {}) {
    if (!chaosStatus || !chaosSummary || !chaosGroups) {
      return;
    }
    try {
      const data = await fetchChaos();
      const signature = JSON.stringify({
        total_domains: data?.total_domains || 0,
        updated_at: data?.updated_at || "",
        groups: (data?.groups || []).map((group) => `${group.main_domain}:${group.count}:${group.error || ""}`),
      });
      if (!options.force && signature === lastChaosSignature) {
        return;
      }
      lastChaosSignature = signature;
      renderChaos(data);
    } catch (error) {
      chaosStatus.textContent = `Chaos fetch error: ${error.message}`;
    }
  }

  async function updateLeadState(payload) {
    const response = await fetch(`${backendUrl}/api/leads/state`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function replayLead(id) {
    const response = await fetch(`${backendUrl}/api/leads/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  leadsWildcards?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-lead-action]");
    if (!button) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const action = button.dataset.leadAction;
    const leadId = button.dataset.leadId;
    if (!leadId) {
      return;
    }
    if (action === "toggle-menu") {
      const menu = leadsWildcards.querySelector(`[data-lead-menu="${CSS.escape(leadId)}"]`);
      if (menu) {
        menu.hidden = !menu.hidden;
      }
      return;
    }
    try {
      if (action === "bucket") {
        await updateLeadState({ id: leadId, bucket: button.dataset.bucket || "" });
        await refreshLeads({ force: true });
        return;
      }
      if (action === "delete") {
        await updateLeadState({ id: leadId, action: "delete" });
        await refreshLeads({ force: true });
        return;
      }
      if (action === "replay") {
        button.disabled = true;
        const result = await replayLead(leadId);
        const statusCode = Number(result?.status_code || 0);
        const url = String(result?.url || "");
        const proxied = result?.proxy_enabled ? ` via ${result.proxy_url}` : "";
        leadsStatus.textContent = `Replay ${statusCode} ${url}${proxied}`;
        return;
      }
    } catch (error) {
      leadsStatus.textContent = `Lead action failed: ${error.message}`;
    } finally {
      if (action === "replay") {
        button.disabled = false;
      }
    }
  });

  leadsWildcards?.addEventListener("change", async (event) => {
    const checkbox = event.target.closest("input[data-lead-action='done']");
    if (!checkbox) {
      return;
    }
    const leadId = checkbox.dataset.leadId;
    if (!leadId) {
      return;
    }
    try {
      await updateLeadState({ id: leadId, done: checkbox.checked });
    } catch (error) {
      checkbox.checked = !checkbox.checked;
      leadsStatus.textContent = `Lead update failed: ${error.message}`;
    }
  });

  return {
    refreshLeads,
    refreshChaos,
  };
}
