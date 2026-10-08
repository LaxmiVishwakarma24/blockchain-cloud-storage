const rows = document.getElementById("shared-rows");
const message = document.getElementById("message");

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function link(label, href) {
  const a = document.createElement("a");
  a.className = "btn btn-sm btn-outline-primary me-1";
  a.href = href;
  a.textContent = label;
  return a;
}

async function load() {
  const response = await fetch("/api/shared");
  let data = {};
  try { data = await response.json(); } catch (error) { data = {}; }
  if (!response.ok) {
    message.textContent = data.message || "Could not load the shared files.";
    message.className = "alert alert-danger";
    return;
  }
  rows.textContent = "";
  if (data.files.length === 0) {
    const tr = document.createElement("tr");
    const td = cell("Nothing has been shared with you.");
    td.colSpan = 5;
    tr.appendChild(td);
    rows.appendChild(tr);
    return;
  }
  data.files.forEach((file) => {
    const tr = document.createElement("tr");
    tr.appendChild(cell(file.name));
    tr.appendChild(cell(file.owner));
    tr.appendChild(cell(file.permissions.join(", ").toLowerCase()));
    tr.appendChild(cell(file.expires_at ? new Date(file.expires_at).toLocaleDateString() : "No expiry"));
    const actions = document.createElement("td");
    if (file.permissions.includes("DOWNLOAD")) {
      actions.appendChild(link("Download", "/api/files/" + file.id + "/download"));
    }
    actions.appendChild(link("Versions", "/files/" + file.id + "/versions"));
    tr.appendChild(actions);
    rows.appendChild(tr);
  });
}

load();