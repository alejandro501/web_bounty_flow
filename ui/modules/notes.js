export function renderMarkdownPreview(rawText, escapeHTML) {
  const text = String(rawText || "").replace(/\r\n/g, "\n");
  if (!text.trim()) {
    return '<p class="muted">Markdown preview appears here.</p>';
  }
  const lines = text.split("\n");
  let html = "";
  let inCode = false;
  let inUL = false;
  let inOL = false;

  const closeLists = () => {
    if (inUL) {
      html += "</ul>";
      inUL = false;
    }
    if (inOL) {
      html += "</ol>";
      inOL = false;
    }
  };

  const inline = (value) => {
    let out = escapeHTML(value);
    out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
    out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    out = out.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    return out;
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      closeLists();
      if (!inCode) {
        html += '<div class="markdown-code-block"><button type="button" class="markdown-copy-button" data-copy-code>Copy</button><pre><code>';
        inCode = true;
      } else {
        html += "</code></pre></div>";
        inCode = false;
      }
      continue;
    }
    if (inCode) {
      html += `${escapeHTML(line)}\n`;
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed) {
      closeLists();
      continue;
    }
    const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      closeLists();
      const level = Math.min(6, heading[1].length);
      html += `<h${level}>${inline(heading[2])}</h${level}>`;
      continue;
    }
    const ol = trimmed.match(/^(\d+)\.\s+(.+)$/);
    if (ol) {
      if (inUL) {
        html += "</ul>";
        inUL = false;
      }
      if (!inOL) {
        html += "<ol>";
        inOL = true;
      }
      html += `<li>${inline(ol[2])}</li>`;
      continue;
    }
    const ul = trimmed.match(/^[-*]\s+(.+)$/);
    if (ul) {
      if (inOL) {
        html += "</ol>";
        inOL = false;
      }
      if (!inUL) {
        html += "<ul>";
        inUL = true;
      }
      html += `<li>${inline(ul[1])}</li>`;
      continue;
    }
    closeLists();
    html += `<p>${inline(trimmed)}</p>`;
  }
  closeLists();
  if (inCode) {
    html += "</code></pre></div>";
  }
  return html;
}

export function bindMarkdownPreview(preview) {
  if (!preview || preview.dataset.copyBound === "true") {
    return;
  }
  preview.dataset.copyBound = "true";
  preview.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy-code]");
    if (!button) {
      return;
    }
    const code = button.parentElement?.querySelector("pre code")?.textContent || "";
    if (!code) {
      return;
    }
    try {
      await navigator.clipboard.writeText(code);
      const previous = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => {
        button.textContent = previous || "Copy";
      }, 1200);
    } catch {
      button.textContent = "Failed";
      window.setTimeout(() => {
        button.textContent = "Copy";
      }, 1200);
    }
  });
}

export function initNotesFeature({
  backendUrl,
  escapeHTML,
  notesEditor,
  notesSave,
  notesStatus,
  notesPreview,
  manualTipsEditor,
  manualTipsSave,
  manualTipsStatus,
  manualTipsPreview,
}) {
  const canvases = {
    notes: {
      editor: notesEditor,
      saveButton: notesSave,
      statusNode: notesStatus,
      preview: notesPreview,
      autosaveTimer: null,
    },
    manual_tips: {
      editor: manualTipsEditor,
      saveButton: manualTipsSave,
      statusNode: manualTipsStatus,
      preview: manualTipsPreview,
      autosaveTimer: null,
    },
  };

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

  function refreshPreview(name, content) {
    const canvas = canvases[name];
    if (!canvas?.preview) {
      return;
    }
    canvas.preview.innerHTML = renderMarkdownPreview(content, escapeHTML);
    bindMarkdownPreview(canvas.preview);
  }

  async function loadCanvas(name) {
    const canvas = canvases[name];
    if (!canvas?.editor || !canvas.statusNode) {
      return;
    }
    canvas.statusNode.textContent = "Loading...";
    try {
      const data = await fetchNoteDoc(name);
      const content = String(data.content || "");
      canvas.editor.value = content;
      refreshPreview(name, content);
      canvas.statusNode.textContent = "Loaded";
    } catch (error) {
      canvas.statusNode.textContent = `Load failed: ${error.message}`;
    }
  }

  async function saveCanvas(name) {
    const canvas = canvases[name];
    if (!canvas?.editor || !canvas.statusNode) {
      return;
    }
    const content = canvas.editor.value || "";
    canvas.statusNode.textContent = "Saving...";
    try {
      await saveNoteDoc(name, content);
      canvas.statusNode.textContent = "Saved";
    } catch (error) {
      canvas.statusNode.textContent = `Save failed: ${error.message}`;
    }
  }

  function scheduleAutosave(name) {
    const canvas = canvases[name];
    if (!canvas) {
      return;
    }
    if (canvas.autosaveTimer) {
      clearTimeout(canvas.autosaveTimer);
    }
    canvas.autosaveTimer = setTimeout(() => {
      void saveCanvas(name);
    }, 900);
  }

  function bindCanvas(name) {
    const canvas = canvases[name];
    if (!canvas?.editor) {
      return;
    }
    canvas.saveButton?.addEventListener("click", async () => {
      await saveCanvas(name);
    });
    canvas.editor.addEventListener("input", () => {
      if (canvas.statusNode) {
        canvas.statusNode.textContent = "Unsaved changes...";
      }
      refreshPreview(name, canvas.editor.value || "");
      scheduleAutosave(name);
    });
  }

  bindCanvas("notes");
  bindCanvas("manual_tips");

  return {
    activateView(view) {
      if (view === "notes") {
        void loadCanvas("notes");
      }
      if (view === "manual-tips") {
        void loadCanvas("manual_tips");
      }
    },
    loadCanvas,
  };
}
