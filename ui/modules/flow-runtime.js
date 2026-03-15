export function initFlowRuntimeFeature({
  backendUrl,
  ansiTextToHTML,
  escapeHTML,
  flowSegments,
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
  onRunQueued,
  onClearResults,
}) {
  let lastStatusText = "";
  let lastStepsSignature = "";
  let lastLogsSignature = "";

  async function postFlowAction(path) {
    const response = await fetch(`${backendUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    try {
      return await response.json();
    } catch {
      return {};
    }
  }

  async function fetchSubdomainProgress() {
    const response = await fetch(`${backendUrl}/api/progress/subdomain`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  function renderSubdomainProgress(data) {
    if (!subdomainProgressBar || !subdomainProgressText) {
      return;
    }
    const total = Number(data?.total_wildcards || 0);
    const done = Number(data?.overall_done || 0);
    const percent = Number(data?.overall_percent || 0);
    subdomainProgressBar.value = Math.max(0, Math.min(100, percent));
    subdomainProgressText.textContent = `${done} / ${total} (${percent}%)`;
  }

  async function refreshSubdomainProgress() {
    try {
      const data = await fetchSubdomainProgress();
      renderSubdomainProgress(data);
    } catch {
      if (subdomainProgressBar) {
        subdomainProgressBar.value = 0;
      }
      if (subdomainProgressText) {
        subdomainProgressText.textContent = "0 / 0";
      }
    }
  }

  async function refreshStatus() {
    try {
      const res = await fetch(`${backendUrl}/api/status`);
      if (!res.ok) {
        throw new Error("failed to read status");
      }
      const data = await res.json();
      const statusText = data.running ? `running (${data.status})` : data.status;
      if (statusText !== lastStatusText && flowStatus) {
        flowStatus.textContent = statusText;
        lastStatusText = statusText;
      }
    } catch (error) {
      const statusText = `status error: ${error.message}`;
      if (statusText !== lastStatusText && flowStatus) {
        flowStatus.textContent = statusText;
        lastStatusText = statusText;
      }
    }
  }

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
      const res = await fetch(`${backendUrl}/api/steps`);
      const bodyText = await res.text();
      if (!res.ok) {
        throw new Error(bodyText || `status ${res.status}`);
      }
      let data;
      try {
        data = bodyText ? JSON.parse(bodyText) : {};
      } catch {
        throw new Error(`non-JSON response from ${backendUrl}/api/steps`);
      }
      const steps = data.steps ?? [];
      const signature = steps.map((step) => `${step.id}:${step.status || "pending"}`).join("|");
      if (signature === lastStepsSignature) {
        return;
      }
      lastStepsSignature = signature;

      const stepMap = new Map(steps.map((step) => [step.id, step]));
      flowStepsList.innerHTML = flowSegments.map((segment) => {
        const itemsHtml = segment.items.map((item) => {
          if (!item.implemented) {
            return `<li class="flow-step flow-step--not-implemented"><span class="flow-step__status">[ ]</span><span class="flow-step__label flow-step__label--not-implemented">${escapeHTML(item.label)} (Not Implemented)</span></li>`;
          }
          if (!item.stepId) {
            return `<li class="flow-step flow-step--completed"><span class="flow-step__status">[x]</span><span class="flow-step__label">${escapeHTML(item.label)}</span></li>`;
          }
          const step = stepMap.get(item.stepId);
          if (!step) {
            return `<li class="flow-step flow-step--manual"><span class="flow-step__status">[~]</span><span class="flow-step__label">${escapeHTML(item.label)}</span></li>`;
          }
          const status = step?.status || "pending";
          const prefix = stepPrefix(status);
          const safeLabel = item.label || step?.label || item.stepId || "step";
          return `<li class="flow-step flow-step--${status}"><span class="flow-step__status">${prefix}</span><span class="flow-step__label">${escapeHTML(safeLabel)}</span></li>`;
        }).join("");

        return `<li class="flow-segment"><details open><summary class="flow-segment__title">${escapeHTML(segment.title)}</summary><ul class="flow-segment__items">${itemsHtml}</ul></details></li>`;
      }).join("");
    } catch (error) {
      const signature = `error:${error.message}`;
      if (signature !== lastStepsSignature) {
        lastStepsSignature = signature;
        flowStepsList.innerHTML = `<li class="flow-step flow-step--error">[!] Failed to load steps: ${escapeHTML(error.message)}</li>`;
      }
    }
  }

  async function refreshLogs() {
    if (!flowLogOutput) {
      return;
    }
    try {
      const res = await fetch(`${backendUrl}/api/logs`);
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
      flowLogOutput.innerHTML = ansiTextToHTML(nextText);
      lastLogsSignature = nextText;
      if (shouldStickToBottom) {
        flowLogOutput.scrollTop = flowLogOutput.scrollHeight;
      }
    } catch (error) {
      const nextText = `Log fetch error: ${error.message}`;
      if (nextText !== lastLogsSignature) {
        flowLogOutput.innerHTML = ansiTextToHTML(nextText);
        lastLogsSignature = nextText;
      }
    }
  }

  runButton?.addEventListener("click", async () => {
    if (flowStatus) {
      flowStatus.textContent = "requesting run...";
    }
    if (torRouteToggle?.checked && torNetworkIndicator) {
      torNetworkIndicator.classList.remove("tor-indicator--ok", "tor-indicator--error");
      torNetworkIndicator.textContent = "Checking Tor egress...";
    }
    try {
      const response = await fetch(`${backendUrl}/api/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      if (flowStatus) {
        flowStatus.textContent = "Flow queued";
      }
      if (typeof onRunQueued === "function") {
        await onRunQueued();
      }
    } catch (error) {
      if (flowStatus) {
        flowStatus.textContent = `Run failed: ${error.message}`;
      }
    }
  });

  pauseButton?.addEventListener("click", async () => {
    if (flowStatus) {
      flowStatus.textContent = "requesting pause...";
    }
    try {
      await postFlowAction("/api/run/pause");
      if (flowStatus) {
        flowStatus.textContent = "Pause requested";
      }
    } catch (error) {
      if (flowStatus) {
        flowStatus.textContent = `Pause failed: ${error.message}`;
      }
    }
  });

  stopButton?.addEventListener("click", async () => {
    if (flowStatus) {
      flowStatus.textContent = "requesting stop...";
    }
    try {
      await postFlowAction("/api/run/stop");
      if (flowStatus) {
        flowStatus.textContent = "Stop requested";
      }
    } catch (error) {
      if (flowStatus) {
        flowStatus.textContent = `Stop failed: ${error.message}`;
      }
    }
  });

  clearResultsButton?.addEventListener("click", async () => {
    if (flowStatus) {
      flowStatus.textContent = "clearing results...";
    }
    try {
      await postFlowAction("/api/run/clear");
      if (flowStatus) {
        flowStatus.textContent = "Results cleared";
      }
      if (typeof onClearResults === "function") {
        await onClearResults({ refreshStatus, refreshSteps, refreshSubdomainProgress });
      }
    } catch (error) {
      if (flowStatus) {
        flowStatus.textContent = `Clear failed: ${error.message}`;
      }
    }
  });

  return {
    refreshStatus,
    refreshSteps,
    refreshLogs,
    refreshSubdomainProgress,
    startPolling() {
      void refreshStatus();
      setInterval(refreshStatus, 5000);
      void refreshSubdomainProgress();
      setInterval(refreshSubdomainProgress, 4000);
      void refreshSteps();
      setInterval(refreshSteps, 3000);
      void refreshLogs();
      setInterval(refreshLogs, 3000);
    },
  };
}
