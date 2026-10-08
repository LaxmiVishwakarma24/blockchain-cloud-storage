const root = document.getElementById("verify-root");
const fileId = root.dataset.fileId;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const select = document.getElementById("version");
const button = document.getElementById("verify-button");
const result = document.getElementById("result");

const TITLES = {
  VERIFIED: "\u2713 VERIFIED",
  MISMATCH: "\u26A0 INTEGRITY MISMATCH",
  MISSING: "\u26A0 STORED FILE MISSING",
};

async function api(url, options) {
  const settings = options || {};
  settings.headers = Object.assign({ "X-CSRFToken": csrf }, settings.headers || {});
  const response = await fetch(url, settings);
  let data = {};
  try { data = await response.json(); } catch (error) { data = {}; }
  return { ok: response.ok, data: data };
}

function showError(text) {
  result.textContent = text;
  result.className = "alert alert-danger";
}

function detail(label, value) {
  const row = document.createElement("div");
  const name = document.createElement("strong");
  name.textContent = label + ": ";
  const text = document.createElement("span");
  text.className = "text-break";
  text.textContent = String(value);
  row.append(name, text);
  return row;
}

function show(data) {
  const ok = data.status === "VERIFIED";
  result.textContent = "";
  result.className = "alert alert-" + (ok ? "success" : "danger");
  const title = document.createElement("h2");
  title.className = "h5";
  title.textContent = TITLES[data.status] || data.status;
  const message = document.createElement("p");
  message.textContent = data.message;
  result.append(title, message);
  result.appendChild(detail("Version", data.version));
  result.appendChild(detail("Recorded SHA-256", data.expected_sha256));
  result.appendChild(
    detail("Calculated SHA-256", data.calculated_sha256 || "not available (decryption failed or file missing)")
  );
  result.appendChild(detail("Reason", data.reason || "none"));
  result.appendChild(detail("Checked at", new Date(data.checked_at).toLocaleString()));
}

async function loadVersions() {
  const response = await api("/api/files/" + fileId + "/versions");
  if (!response.ok) {
    showError(response.data.message || "Could not load the versions.");
    return;
  }
  response.data.versions.forEach((version, index) => {
    const option = document.createElement("option");
    option.value = version.version;
    option.textContent = "Version " + version.version + (index === 0 ? " (current)" : "");
    select.appendChild(option);
  });
  const wanted = new URLSearchParams(window.location.search).get("version");
  if (wanted && Array.from(select.options).some((option) => option.value === wanted)) {
    select.value = wanted;
  }
}

button.addEventListener("click", async () => {
  button.disabled = true;
  result.className = "";
  result.textContent = "Verifying...";
  const response = await api("/api/files/" + fileId + "/versions/" + select.value + "/verify", { method: "POST" });
  button.disabled = false;
  if (response.ok) { show(response.data); }
  else { showError(response.data.message || "Verification could not be carried out."); }
});

loadVersions();