const BACKEND_URL = document.body.dataset.backendUrl || "http://localhost:8080";

const uploadForm = document.getElementById("upload-form");
const uploadStatus = document.getElementById("upload-status");
const urlForm = document.getElementById("url-form");
const urlStatus = document.getElementById("url-status");
const runButton = document.getElementById("run-flow");
const flowStatus = document.getElementById("flow-status");

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
  const payload = {
    list_type: urlForm.list_type.value,
    url: urlForm.url.value,
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
    urlStatus.textContent = "Entry appended";
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
