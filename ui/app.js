const BACKEND_URL = document.body.dataset.backendUrl || "http://localhost:8080";

const runButton = document.getElementById("run-flow");
const flowStatus = document.getElementById("flow-status");
const listViewSelect = document.getElementById("list-view-select");
const listViewOutput = document.getElementById("list-view-output");
const flowLogOutput = document.getElementById("flow-log-output");
const flowStepsList = document.getElementById("flow-steps-list");
const menuItems = document.querySelectorAll(".menu-item");
const pageTitle = document.querySelector(".page-title");
const githubAutoRun = document.getElementById("github-auto-run");
const githubKeyLabel = document.getElementById("github-key-label");
const githubKeyValue = document.getElementById("github-key-value");
const githubKeyActive = document.getElementById("github-key-active");
const githubKeyAdd = document.getElementById("github-key-add");
const githubKeysList = document.getElementById("github-keys-list");
const scopeCards = document.getElementById("scope-cards");
const scopeCardsStatus = document.getElementById("scope-cards-status");

const LIST_FILES = [
  { type: "wildcards", label: "Wildcards" },
  { type: "domains", label: "Domains" },
  { type: "apidomains", label: "API Domains" },
  { type: "organizations", label: "Organizations" },
  { type: "ips", label: "IPs" },
  { type: "out_of_scope", label: "Out of scope" },
];

function escapeHTML(value) {
  return (value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;");
}

menuItems.forEach((item) => {
  item.addEventListener("click", () => {
    menuItems.forEach((btn) => btn.classList.remove("is-active"));
    item.classList.add("is-active");
    const view = item.dataset.view;
    document.body.dataset.activeView = view;
    if (pageTitle) {
      pageTitle.textContent = view === "config" ? "Configuration" : "Bounty Flow Control";
    }
  });
});

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
    listViewSelect?.value ? refreshListEntries(listViewSelect.value) : Promise.resolve(),
  ]);

  if (scopeCardsStatus) {
    scopeCardsStatus.textContent = `Uploaded ${file.name} to ${type}`;
  }
}

function renderScopeCards(states) {
  if (!scopeCards) {
    return;
  }

  scopeCards.innerHTML = LIST_FILES.map(({ type, label }) => {
    const state = states[type] || { present: false };
    const statusText = state.present ? "Present" : "Missing";
    const statusClass = state.present ? "scope-card__status--present" : "scope-card__status--missing";
    const inputId = `scope-upload-${type}`;

    return `
      <article class="scope-card" data-type="${escapeHTML(type)}">
        <h3 class="scope-card__name">${escapeHTML(label)}</h3>
        <span class="scope-card__status ${statusClass}">${statusText}</span>
        <input id="${inputId}" type="file" accept=".txt" />
        <button type="button" class="scope-card__upload" data-input-id="${inputId}">Upload</button>
      </article>
    `;
  }).join("");

  scopeCards.querySelectorAll(".scope-card__upload").forEach((button) => {
    button.addEventListener("click", () => {
      const inputId = button.dataset.inputId;
      const input = document.getElementById(inputId);
      input?.click();
    });
  });

  scopeCards.querySelectorAll(".scope-card input[type='file']").forEach((input) => {
    input.addEventListener("change", async () => {
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
  });
}

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

  renderScopeCards(states);

  if (scopeCardsStatus) {
    scopeCardsStatus.textContent = "File status refreshed";
  }
}

async function refreshStatus() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/status`);
    if (!res.ok) {
      throw new Error("failed to read status");
    }
    const data = await res.json();
    flowStatus.textContent = data.running
      ? `running (${data.status})`
      : data.status;
  } catch (error) {
    flowStatus.textContent = `status error: ${error.message}`;
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
    flowStepsList.innerHTML = steps
      .map((step) => {
        const status = step.status || "pending";
        const prefix = stepPrefix(status);
        const safeLabel = step.label || step.id || "step";
        return `<li class="flow-step flow-step--${status}"><span class="flow-step__status">${prefix}</span><span class="flow-step__label">${escapeHTML(safeLabel)}</span></li>`;
      })
      .join("");
  } catch (error) {
    flowStepsList.innerHTML = `<li class="flow-step flow-step--error">[!] Failed to load steps: ${escapeHTML(error.message)}</li>`;
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

async function refreshListEntries(type) {
  if (!listViewOutput) {
    return;
  }
  listViewOutput.textContent = "Loading...";
  try {
    const data = await fetchListMeta(type);
    if (!data.present) {
      listViewOutput.textContent = "File missing.";
      return;
    }
    listViewOutput.textContent =
      data.entries && data.entries.length ? data.entries.join("\n") : "No entries yet.";
  } catch (error) {
    listViewOutput.textContent = `Error: ${error.message}`;
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
    flowLogOutput.textContent = data.logs ? data.logs.join("\n") : "Waiting for logs...";
    flowLogOutput.scrollTop = flowLogOutput.scrollHeight;
  } catch (error) {
    flowLogOutput.textContent = `Log fetch error: ${error.message}`;
  }
}

refreshLogs();
setInterval(refreshLogs, 3000);

refreshScopeCards();
setInterval(() => {
  refreshScopeCards();
  if (listViewSelect?.value) {
    refreshListEntries(listViewSelect.value);
  }
}, 4000);
