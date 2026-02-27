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
const scopeCardNodes = new Map();

let lastStatusText = "";
let lastStepsSignature = "";
let lastLogsSignature = "";
let lastScopeSignature = "";
const lastListTextByType = {};

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

  scopeCards.innerHTML = LIST_FILES.map(({ type, label }) => {
    const inputId = `scope-upload-${type}`;

    return `
      <article class="scope-card" data-type="${escapeHTML(type)}">
        <h3 class="scope-card__name">${escapeHTML(label)}</h3>
        <span class="scope-card__status scope-card__status--missing">Missing</span>
        <input id="${inputId}" type="file" accept=".txt" />
        <button type="button" class="scope-card__upload" data-input-id="${inputId}">Upload</button>
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
