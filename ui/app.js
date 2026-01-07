const BACKEND_URL = document.body.dataset.backendUrl || "http://localhost:8080";

const uploadForm = document.getElementById("upload-form");
const uploadStatus = document.getElementById("upload-status");
const urlForm = document.getElementById("url-form");
const urlStatus = document.getElementById("url-status");
const runButton = document.getElementById("run-flow");
const flowStatus = document.getElementById("flow-status");
const listViewSelect = document.getElementById("list-view-select");
const listViewOutput = document.getElementById("list-view-output");
const flowLogOutput = document.getElementById("flow-log-output");
const flowStepsList = document.getElementById("flow-steps-list");

function isValidURL(value) {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

uploadForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(uploadForm);
  uploadStatus.textContent = "Uploading…";

  try {
    const response = await fetch(`${BACKEND_URL}/api/upload`, {
      method: "POST",
      body: formData,
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    uploadStatus.textContent = "Upload finished";
  } catch (error) {
    uploadStatus.textContent = `Upload failed: ${error.message}`;
  }
});

urlForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const listType = urlForm.list_type.value;
  const entry = urlForm.url.value.trim();

  if (!entry) {
    urlStatus.textContent = "Entry cannot be empty";
    return;
  }

  if (listType !== "wildcards" && !isValidURL(entry)) {
    urlStatus.textContent = "Please enter a valid URL for this list";
    return;
  }

  const payload = {
    list_type: listType,
    url: entry,
  };
  urlStatus.textContent = "Saving…";

  try {
    const response = await fetch(`${BACKEND_URL}/api/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const data = await response.json();
    urlStatus.textContent = data.message ?? "Entry appended";
    await refreshListEntries(listType);
  } catch (error) {
    urlStatus.textContent = `Append failed: ${error.message}`;
  }
});

runButton?.addEventListener("click", async () => {
  flowStatus.textContent = "requesting run…";
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
    } catch (parseError) {
      throw new Error(`non-JSON response from ${BACKEND_URL}/api/steps`);
    }
    const steps = data.steps ?? [];
    flowStepsList.innerHTML = steps
      .map((step) => {
        const status = step.status || "pending";
        const prefix = stepPrefix(status);
        const safeLabel = step.label || step.id || "step";
        return `<li class="flow-step flow-step--${status}"><span class="flow-step__status">${prefix}</span><span class="flow-step__label">${safeLabel}</span></li>`;
      })
      .join("");
  } catch (error) {
    flowStepsList.innerHTML = `<li class="flow-step flow-step--error">[!] Failed to load steps: ${error.message}</li>`;
  }
}

refreshSteps();
setInterval(refreshSteps, 3000);

async function refreshListEntries(type) {
  if (!listViewOutput) {
    return;
  }
  listViewOutput.textContent = "Loading…";
  try {
    const response = await fetch(`${BACKEND_URL}/api/list?type=${encodeURIComponent(type)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const data = await response.json();
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
    flowLogOutput.textContent = data.logs ? data.logs.join("\n") : "Waiting for logs…";
    flowLogOutput.scrollTop = flowLogOutput.scrollHeight;
  } catch (error) {
    flowLogOutput.textContent = `Log fetch error: ${error.message}`;
  }
}

refreshLogs();
setInterval(refreshLogs, 3000);
