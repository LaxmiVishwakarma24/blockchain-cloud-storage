const root = document.getElementById("versions-root");
const fileId = root.dataset.fileId;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const rows = document.getElementById("version-rows");
const message = document.getElementById("message");
const form = document.getElementById("version-form");

function notify(text, kind) {
  message.textContent = text;
  message.className = text ? "alert alert-" + kind : "";
}

async function api(url, options) {
  const settings = options || {};
  settings.headers = Object.assign({ "X-CSRFToken": csrf }, settings.headers || {});
  const response = await fetch(url, settings);
  let data = {};
  try { data = await response.json(); } catch (error) { data = {}; }
  return { ok: response.ok, data: data };
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

async function restore(version) {
  if (!window.confirm("Restore version " + version.version + " as a new version?")) return;
  const result = await api("/api/files/" + fileId + "/versions/" + version.version + "/restore", { method: "POST" });
  if (result.ok) { notify("Restored as version " + result.data.version + ".", "success"); load(); }
  else { notify(result.data.message || "Restore failed.", "danger"); }
}

function row(version, isCurrent) {
  const tr = document.createElement("tr");
  tr.appendChild(cell("v" + version.version + (isCurrent ? " (current)" : "")));
  tr.appendChild(cell(formatSize(version.size_bytes)));
  tr.appendChild(cell(version.sha256.slice(0, 16) + "..."));
  tr.appendChild(cell(version.created_by || ""));
  tr.appendChild(cell(version.created_at ? new Date(version.created_at).toLocaleString() : ""));
  tr.appendChild(cell((version.encrypted ? "yes" : "no") + (version.verification ? " / " + version.verification.toLowerCase() : "")));
  const actions = document.createElement("td");
  const link = document.createElement("a");
  link.className = "btn btn-sm btn-outline-primary me-1";
  link.href = "/api/files/" + fileId + "/versions/" + version.version + "/download";
  link.textContent = "Download";
  actions.appendChild(link);
  const verifyLink = document.createElement("a");
  verifyLink.className = "btn btn-sm btn-outline-success me-1";
  verifyLink.href = "/files/" + fileId + "/verify?version=" + version.version;
  verifyLink.textContent = "Verify";
  actions.appendChild(verifyLink);
  if (!isCurrent) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-sm btn-outline-secondary";
    button.textContent = "Restore as new version";
    button.addEventListener("click", () => restore(version));
    actions.appendChild(button);
  }
  tr.appendChild(actions);
  return tr;
}

async function load() {
  const result = await api("/api/files/" + fileId + "/versions");
  if (!result.ok) {
    notify(result.data.message || "Could not load the versions.", "danger");
    return;
  }
  rows.textContent = "";
  result.data.versions.forEach((version, index) => rows.appendChild(row(version, index === 0)));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/api/files/" + fileId + "/versions", { method: "POST", body: new FormData(form) });
  if (result.ok) {
    notify("Uploaded version " + result.data.version + ".", "success");
    form.reset();
    load();
  } else {
    notify(result.data.message || "Upload failed.", "danger");
  }
});

load();