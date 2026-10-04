const root = document.getElementById("share-root");
const fileId = root.dataset.fileId;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const rows = document.getElementById("share-rows");
const message = document.getElementById("message");
const form = document.getElementById("share-form");
const expires = document.getElementById("expires");

expires.min = new Date(Date.now() + 86400000).toISOString().slice(0, 10);

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

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

async function revoke(share) {
  if (!window.confirm("Stop sharing with " + share.shared_with + "?")) return;
  const result = await api("/api/files/" + fileId + "/shares/" + share.id, { method: "DELETE" });
  if (result.ok) { notify("Share revoked.", "success"); load(); }
  else { notify(result.data.message || "Could not revoke the share.", "danger"); }
}

function row(share) {
  const tr = document.createElement("tr");
  tr.appendChild(cell(share.shared_with));
  tr.appendChild(cell(share.permissions.join(", ").toLowerCase()));
  tr.appendChild(cell(share.expires_at ? new Date(share.expires_at).toLocaleDateString() : "No expiry"));
  tr.appendChild(cell(share.revoked ? "Revoked" : (share.active ? "Active" : "Expired")));
  const actions = document.createElement("td");
  if (!share.revoked) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-sm btn-outline-danger";
    button.textContent = "Revoke";
    button.addEventListener("click", () => revoke(share));
    actions.appendChild(button);
  }
  tr.appendChild(actions);
  return tr;
}

async function load() {
  const result = await api("/api/files/" + fileId + "/shares");
  if (!result.ok) {
    notify(result.data.message || "Could not load the shares.", "danger");
    return;
  }
  rows.textContent = "";
  if (result.data.shares.length === 0) {
    const tr = document.createElement("tr");
    const td = cell("This file is not shared with anyone.");
    td.colSpan = 5;
    tr.appendChild(td);
    rows.appendChild(tr);
    return;
  }
  result.data.shares.forEach((share) => rows.appendChild(row(share)));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const permissions = ["VIEW"];
  document.querySelectorAll(".perm:checked").forEach((box) => permissions.push(box.value));
  const body = {
    email: document.getElementById("email").value.trim(),
    permissions: permissions,
    expires_at: expires.value || null,
  };
  const result = await api("/api/files/" + fileId + "/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (result.ok) {
    notify("Shared with " + result.data.shared_with + ".", "success");
    form.reset();
    load();
  } else {
    notify(result.data.message || "Could not share the file.", "danger");
  }
});

load();