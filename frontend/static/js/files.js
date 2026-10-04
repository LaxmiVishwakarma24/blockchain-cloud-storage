const csrf = document.querySelector('meta[name="csrf-token"]').content;
const rows = document.getElementById("file-rows");
const message = document.getElementById("message");
const pager = document.getElementById("pager");
const filters = document.getElementById("filters");
const tabActive = document.getElementById("tab-active");
const tabTrash = document.getElementById("tab-trash");
let view = "active";
let page = 1;
let timer = null;

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

function actionButton(label, style, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-sm btn-outline-" + style + " me-1";
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function actionLink(label, href) {
  const link = document.createElement("a");
  link.className = "btn btn-sm btn-outline-primary me-1";
  link.href = href;
  link.textContent = label;
  return link;
}

async function rename(file) {
  const name = window.prompt("New file name (keep the extension):", file.name);
  if (!name || name === file.name) return;
  const result = await api("/api/files/" + file.id, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: name }),
  });
  if (result.ok) { notify("Renamed.", "success"); load(); }
  else { notify(result.data.message || "Rename failed.", "danger"); }
}

async function remove(file) {
  if (!window.confirm('Move "' + file.name + '" to the trash?')) return;
  const result = await api("/api/files/" + file.id, { method: "DELETE" });
  if (result.ok) { notify("Moved to the trash.", "success"); load(); }
  else { notify(result.data.message || "Delete failed.", "danger"); }
}

async function restore(file) {
  const result = await api("/api/files/" + file.id + "/restore", { method: "POST" });
  if (result.ok) { notify("Restored.", "success"); load(); }
  else { notify(result.data.message || "Restore failed.", "danger"); }
}

function statusMark(status) {
  if (status === "VERIFIED") return " \u2713";
  if (status === "MISMATCH" || status === "MISSING") return " \u26A0";
  return "";
}

function row(file) {
  const tr = document.createElement("tr");
  tr.appendChild(cell(file.name));
  tr.appendChild(cell(formatSize(file.size_bytes || 0)));
  tr.appendChild(cell(file.created_at ? new Date(file.created_at).toLocaleDateString() : ""));
  tr.appendChild(cell("v" + file.version));
  tr.appendChild(cell((file.sha256 ? file.sha256.slice(0, 12) + "..." : "") + statusMark(file.verification)));
  const actions = document.createElement("td");
  if (view === "trash") {
    actions.appendChild(actionButton("Restore", "success", () => restore(file)));
  } else {
    actions.appendChild(actionLink("Download", "/api/files/" + file.id + "/download"));
    actions.appendChild(actionLink("Versions", "/files/" + file.id + "/versions"));
    actions.appendChild(actionLink("Share", "/files/" + file.id + "/share"));
    actions.appendChild(actionLink("Verify", "/files/" + file.id + "/verify"));
    actions.appendChild(actionButton("Rename", "secondary", () => rename(file)));
    actions.appendChild(actionButton("Delete", "danger", () => remove(file)));
  }
  tr.appendChild(actions);
  return tr;
}

function renderPager(data) {
  pager.textContent = "";
  const pages = Math.max(Math.ceil(data.total / data.per_page), 1);
  const label = document.createElement("span");
  label.className = "mx-2";
  label.textContent = "Page " + data.page + " of " + pages + " (" + data.total + " files)";
  const prev = actionButton("Previous", "secondary", () => { page -= 1; load(); });
  prev.disabled = data.page <= 1;
  const next = actionButton("Next", "secondary", () => { page += 1; load(); });
  next.disabled = data.page >= pages;
  pager.append(prev, label, next);
}

async function load() {
  const params = new URLSearchParams();
  new FormData(filters).forEach((value, key) => { if (value) params.set(key, value); });
  params.set("view", view);
  params.set("page", page);
  const result = await api("/api/files?" + params.toString());
  if (!result.ok) {
    notify(result.data.message || "Could not load the files.", "danger");
    return;
  }
  rows.textContent = "";
  if (result.data.files.length === 0) {
    const tr = document.createElement("tr");
    const td = cell(view === "trash" ? "The trash is empty." : "No files found.");
    td.colSpan = 6;
    tr.appendChild(td);
    rows.appendChild(tr);
  }
  result.data.files.forEach((file) => rows.appendChild(row(file)));
  renderPager(result.data);
}

function setView(next) {
  view = next;
  page = 1;
  tabActive.className = "btn " + (view === "active" ? "btn-primary" : "btn-outline-primary");
  tabTrash.className = "btn " + (view === "trash" ? "btn-primary" : "btn-outline-primary");
  notify("", "info");
  load();
}

tabActive.addEventListener("click", () => setView("active"));
tabTrash.addEventListener("click", () => setView("trash"));
filters.addEventListener("submit", (event) => event.preventDefault());
filters.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(() => { page = 1; load(); }, 300);
});

load();