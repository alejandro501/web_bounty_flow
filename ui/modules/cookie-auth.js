import { bindMarkdownPreview, renderMarkdownPreview } from "./notes.js?v=20260317-2";

export function initCookieAuthFeature({
  backendUrl,
  escapeHTML,
  cookieRows,
  cookieAddRow,
  cookieSave,
  cookieStatus,
  authEditor,
  authSave,
  authStatus,
  authPreview,
}) {
  let cookiePairs = [];
  let authAutosaveTimer = null;

  async function fetchNoteDoc(name) {
    const response = await fetch(`${backendUrl}/api/notes?name=${encodeURIComponent(name)}`);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  async function saveNoteDoc(name, content) {
    const response = await fetch(`${backendUrl}/api/notes?name=${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  }

  function extractCookieBlob(raw) {
    const text = String(raw || "").replace(/\r\n/g, "\n").trim();
    if (!text) {
      return "";
    }
    const fenced = text.match(/^```[^\n]*\n([\s\S]*?)\n```$/);
    return (fenced ? fenced[1] : text).trim();
  }

  function parseCookieDoc(raw) {
    const blob = extractCookieBlob(raw).replace(/\n/g, " ");
    if (!blob) {
      return [];
    }
    return blob
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((entry) => {
        const separator = entry.indexOf("=");
        if (separator === -1) {
          return { key: entry, value: "" };
        }
        return {
          key: entry.slice(0, separator).trim(),
          value: entry.slice(separator + 1).trim(),
        };
      });
  }

  function buildCookieDoc() {
    const serialized = cookiePairs
      .map((pair) => ({
        key: String(pair?.key || "").trim(),
        value: String(pair?.value || "").trim(),
      }))
      .filter((pair) => pair.key)
      .map((pair) => `${pair.key}=${pair.value}`)
      .join("; ");
    if (!serialized) {
      return "```sh\n```\n";
    }
    return `\`\`\`sh\n${serialized}\n\`\`\`\n`;
  }

  function setCookieStatus(text) {
    if (cookieStatus) {
      cookieStatus.textContent = text;
    }
  }

  function setAuthStatus(text) {
    if (authStatus) {
      authStatus.textContent = text;
    }
  }

  function renderCookieRows() {
    if (!cookieRows) {
      return;
    }
    cookieRows.innerHTML = cookiePairs.map((pair, index) => `
      <div class="cookie-pair-row" data-cookie-index="${index}">
        <input
          type="text"
          name="cookie_key"
          class="cookie-pair-row__key"
          data-cookie-field="key"
          value="${escapeHTML(pair.key || "")}"
          placeholder="cookie_name"
        />
        <textarea name="cookie_value" class="cookie-pair-row__value" data-cookie-field="value" rows="2" placeholder="cookie value">${escapeHTML(pair.value || "")}</textarea>
        <button type="button" class="cookie-pair-row__remove" data-cookie-action="remove">Remove</button>
      </div>
    `).join("");
    if (cookieRows.innerHTML === "") {
      cookieRows.innerHTML = '<p class="muted">No cookies yet. Add your first cookie row.</p>';
    }
  }

  async function loadCookieDoc() {
    setCookieStatus("Loading...");
    try {
      const data = await fetchNoteDoc("cookie");
      cookiePairs = parseCookieDoc(data.content);
      renderCookieRows();
      setCookieStatus("Loaded");
    } catch (error) {
      setCookieStatus(`Load failed: ${error.message}`);
    }
  }

  async function saveCookieDoc() {
    setCookieStatus("Saving...");
    try {
      await saveNoteDoc("cookie", buildCookieDoc());
      setCookieStatus("Saved");
    } catch (error) {
      setCookieStatus(`Save failed: ${error.message}`);
    }
  }

  function refreshAuthPreview() {
    if (!authPreview) {
      return;
    }
    authPreview.innerHTML = renderMarkdownPreview(authEditor?.value || "", escapeHTML);
    bindMarkdownPreview(authPreview);
  }

  async function loadAuthDoc() {
    if (!authEditor) {
      return;
    }
    setAuthStatus("Loading...");
    try {
      const data = await fetchNoteDoc("auth");
      authEditor.value = String(data.content || "");
      refreshAuthPreview();
      setAuthStatus("Loaded");
    } catch (error) {
      setAuthStatus(`Load failed: ${error.message}`);
    }
  }

  async function saveAuthDoc() {
    if (!authEditor) {
      return;
    }
    setAuthStatus("Saving...");
    try {
      await saveNoteDoc("auth", authEditor.value || "");
      setAuthStatus("Saved");
    } catch (error) {
      setAuthStatus(`Save failed: ${error.message}`);
    }
  }

  function scheduleAuthAutosave() {
    if (authAutosaveTimer) {
      clearTimeout(authAutosaveTimer);
    }
    authAutosaveTimer = setTimeout(() => {
      void saveAuthDoc();
    }, 900);
  }

  cookieRows?.addEventListener("input", (event) => {
    const field = event.target.closest("[data-cookie-field]");
    const row = event.target.closest("[data-cookie-index]");
    if (!field || !row) {
      return;
    }
    const index = Number(row.dataset.cookieIndex);
    if (Number.isNaN(index) || !cookiePairs[index]) {
      return;
    }
    cookiePairs[index][field.dataset.cookieField] = event.target.value || "";
    setCookieStatus("Unsaved changes...");
  });

  cookieRows?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-cookie-action='remove']");
    const row = event.target.closest("[data-cookie-index]");
    if (!button || !row) {
      return;
    }
    const index = Number(row.dataset.cookieIndex);
    if (Number.isNaN(index)) {
      return;
    }
    cookiePairs.splice(index, 1);
    renderCookieRows();
    setCookieStatus("Unsaved changes...");
  });

  cookieAddRow?.addEventListener("click", () => {
    cookiePairs.push({ key: "", value: "" });
    renderCookieRows();
    setCookieStatus("Unsaved changes...");
  });

  cookieSave?.addEventListener("click", async () => {
    await saveCookieDoc();
  });

  authSave?.addEventListener("click", async () => {
    await saveAuthDoc();
  });

  authEditor?.addEventListener("input", () => {
    setAuthStatus("Unsaved changes...");
    refreshAuthPreview();
    scheduleAuthAutosave();
  });

  return {
    activateView(view) {
      if (view !== "cookie-auth") {
        return;
      }
      void loadCookieDoc();
      void loadAuthDoc();
    },
  };
}
