export function initConfigNetworkFeature({
  backendUrl,
  escapeHTML,
  flowSubdomainTools,
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
}) {
  let flowConfigDraft = {};

  async function fetchNetworkSettings() {
    const response = await fetch(`${backendUrl}/api/network`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function updateNetworkSettings(payload) {
    const response = await fetch(`${backendUrl}/api/network`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
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

  async function loadConfig() {
    if (!githubKeysList) {
      return;
    }
    githubKeysList.textContent = "Loading keys...";
    try {
      const res = await fetch(`${backendUrl}/api/config`);
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const data = await res.json();
      const provider = data.providers?.github ?? { auto_run: true, keys: [] };
      if (githubAutoRun) {
        githubAutoRun.checked = provider.auto_run ?? true;
      }
      renderGithubKeys(provider.keys ?? []);
    } catch (error) {
      githubKeysList.textContent = `Failed to load config: ${error.message}`;
    }
  }

  async function loadFlowConfig() {
    if (!flowConfigTools || !flowConfigStatus) {
      return;
    }
    flowConfigStatus.textContent = "Loading...";
    try {
      const res = await fetch(`${backendUrl}/api/config`);
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const data = await res.json();
      const providers = data?.providers || {};
      flowConfigDraft = {};
      for (const tool of flowSubdomainTools) {
        const enabled = providers?.[tool.provider]?.auto_run;
        flowConfigDraft[tool.provider] = enabled === undefined ? true : Boolean(enabled);
      }
      flowConfigTools.innerHTML = flowSubdomainTools.map((tool) => {
        const checked = flowConfigDraft[tool.provider] ? "checked" : "";
        return `
          <div class="config-row" data-flow-provider="${tool.provider}">
            <div>
              <strong>${escapeHTML(tool.label)}</strong>
              <p class="muted">${escapeHTML(tool.notes)}</p>
            </div>
            <label class="inline">
              <input type="checkbox" data-flow-provider-toggle="${tool.provider}" ${checked} />
              Enabled
            </label>
          </div>
        `;
      }).join("");
      if (flowConfigSave) {
        flowConfigSave.disabled = true;
      }
      flowConfigStatus.textContent = "Loaded";
    } catch (error) {
      flowConfigStatus.textContent = `Failed to load flow configuration: ${error.message}`;
    }
  }

  function renderNetworkIndicator(data) {
    if (!torNetworkIndicator) {
      return;
    }
    torNetworkIndicator.classList.remove("tor-indicator--ok", "tor-indicator--error");
    const torOn = Boolean(data?.tor_enabled);
    if (!torOn) {
      torNetworkIndicator.textContent = "Tor off";
    } else {
      const ip = String(data?.probe_ip || "").trim();
      const error = String(data?.probe_error || "").trim();
      const probeAtRaw = String(data?.probe_at || "").trim();
      const probeAt = probeAtRaw ? new Date(probeAtRaw).toLocaleTimeString() : "";
      if (ip) {
        torNetworkIndicator.classList.add("tor-indicator--ok");
        torNetworkIndicator.textContent = probeAt ? `Tor IP: ${ip} (${probeAt})` : `Tor IP: ${ip}`;
      } else if (error) {
        torNetworkIndicator.classList.add("tor-indicator--error");
        torNetworkIndicator.textContent = `Tor check failed: ${error}`;
      } else {
        torNetworkIndicator.textContent = "Checking Tor egress...";
      }
    }
    if (proxyNetworkIndicator) {
      proxyNetworkIndicator.classList.remove("tor-indicator--ok", "tor-indicator--error");
      const proxyOn = Boolean(data?.proxy_enabled);
      if (!proxyOn) {
        proxyNetworkIndicator.textContent = "Proxy off";
      } else {
        const host = String(data?.proxy_host || "localhost").trim() || "localhost";
        const port = Number(data?.proxy_port || 8080) || 8080;
        proxyNetworkIndicator.classList.add("tor-indicator--ok");
        proxyNetworkIndicator.textContent = `Proxy on: ${host}:${port}`;
      }
    }
  }

  async function loadNetworkSettings() {
    if (!torRouteToggle) {
      return;
    }
    try {
      const data = await fetchNetworkSettings();
      torRouteToggle.checked = Boolean(data.tor_enabled);
      if (proxyRouteToggle) {
        proxyRouteToggle.checked = Boolean(data.proxy_enabled);
      }
      if (proxyConfigEnabled) {
        proxyConfigEnabled.checked = Boolean(data.proxy_enabled);
      }
      if (proxyConfigHost) {
        proxyConfigHost.value = String(data.proxy_host || "localhost");
      }
      if (proxyConfigPort) {
        proxyConfigPort.value = String(data.proxy_port || 8080);
      }
      renderNetworkIndicator(data);
    } catch {
      torRouteToggle.checked = false;
      if (proxyRouteToggle) {
        proxyRouteToggle.checked = false;
      }
      renderNetworkIndicator({ tor_enabled: false, proxy_enabled: false, probe_error: "Network status unavailable" });
    }
  }

  githubKeyAdd?.addEventListener("click", async () => {
    const label = githubKeyLabel?.value.trim() || "";
    const value = githubKeyValue?.value.trim() || "";
    const active = Boolean(githubKeyActive?.checked);
    if (!value) {
      if (githubKeysList) {
        githubKeysList.textContent = "Token value is required.";
      }
      return;
    }
    try {
      const res = await fetch(`${backendUrl}/api/config/providers/github/keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, value, active }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      if (githubKeyLabel) {
        githubKeyLabel.value = "";
      }
      if (githubKeyValue) {
        githubKeyValue.value = "";
      }
      if (githubKeyActive) {
        githubKeyActive.checked = true;
      }
      await loadConfig();
    } catch (error) {
      if (githubKeysList) {
        githubKeysList.textContent = `Failed to add key: ${error.message}`;
      }
    }
  });

  githubAutoRun?.addEventListener("change", async () => {
    try {
      const res = await fetch(`${backendUrl}/api/config/providers/github/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auto_run: githubAutoRun.checked }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
    } catch (error) {
      if (githubKeysList) {
        githubKeysList.textContent = `Failed to update auto-run: ${error.message}`;
      }
    }
  });

  flowConfigTools?.addEventListener("change", (event) => {
    const input = event.target.closest("input[data-flow-provider-toggle]");
    if (!input) {
      return;
    }
    const provider = input.dataset.flowProviderToggle;
    if (!provider) {
      return;
    }
    flowConfigDraft[provider] = Boolean(input.checked);
    if (flowConfigSave) {
      flowConfigSave.disabled = false;
    }
    if (flowConfigStatus) {
      flowConfigStatus.textContent = "Unsaved changes...";
    }
  });

  flowConfigSave?.addEventListener("click", async () => {
    if (!flowConfigStatus || !flowConfigSave) {
      return;
    }
    flowConfigStatus.textContent = "Saving...";
    flowConfigSave.disabled = true;
    try {
      const res = await fetch(`${backendUrl}/api/config/flow-tools`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tools: flowConfigDraft }),
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      flowConfigStatus.textContent = "Saved";
    } catch (error) {
      flowConfigStatus.textContent = `Failed to save flow configuration: ${error.message}`;
      flowConfigSave.disabled = false;
    }
  });

  torRouteToggle?.addEventListener("change", async () => {
    try {
      await updateNetworkSettings({
        tor_enabled: Boolean(torRouteToggle.checked),
        proxy_enabled: Boolean(proxyRouteToggle?.checked),
        proxy_host: String(proxyConfigHost?.value || "localhost").trim() || "localhost",
        proxy_port: Number(proxyConfigPort?.value || 8080) || 8080,
      });
      await loadNetworkSettings();
    } catch (error) {
      torRouteToggle.checked = !torRouteToggle.checked;
      if (flowStatus) {
        flowStatus.textContent = `Network toggle failed: ${error.message}`;
      }
    }
  });

  proxyRouteToggle?.addEventListener("change", async () => {
    try {
      await updateNetworkSettings({
        tor_enabled: Boolean(torRouteToggle?.checked),
        proxy_enabled: Boolean(proxyRouteToggle.checked),
        proxy_host: String(proxyConfigHost?.value || "localhost").trim() || "localhost",
        proxy_port: Number(proxyConfigPort?.value || 8080) || 8080,
      });
      await loadNetworkSettings();
    } catch (error) {
      proxyRouteToggle.checked = !proxyRouteToggle.checked;
      if (flowStatus) {
        flowStatus.textContent = `Proxy toggle failed: ${error.message}`;
      }
    }
  });

  proxyConfigSave?.addEventListener("click", async () => {
    const host = String(proxyConfigHost?.value || "localhost").trim() || "localhost";
    const port = Number(proxyConfigPort?.value || 8080) || 8080;
    const enabled = Boolean(proxyConfigEnabled?.checked || proxyRouteToggle?.checked);
    try {
      await updateNetworkSettings({
        tor_enabled: Boolean(torRouteToggle?.checked),
        proxy_enabled: enabled,
        proxy_host: host,
        proxy_port: port,
      });
      await loadNetworkSettings();
      if (flowStatus) {
        flowStatus.textContent = `Proxy updated: ${host}:${port}`;
      }
    } catch (error) {
      if (flowStatus) {
        flowStatus.textContent = `Proxy save failed: ${error.message}`;
      }
    }
  });

  proxyConfigEnabled?.addEventListener("change", () => {
    if (proxyRouteToggle) {
      proxyRouteToggle.checked = Boolean(proxyConfigEnabled.checked);
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
        const res = await fetch(`${backendUrl}/api/config/providers/github/keys/${keyId}`, {
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
        const res = await fetch(`${backendUrl}/api/config/providers/github/keys/${keyId}`, {
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

  return {
    loadConfig,
    loadFlowConfig,
    loadNetworkSettings,
  };
}
