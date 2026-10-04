const form = document.getElementById("upload-form");
const result = document.getElementById("result");
const rows = document.getElementById("file-rows");

function show(message, kind) {
  result.textContent = message;
  result.className = "mt-3 alert alert-" + kind;
}

function addRow(file) {
  const tr = document.createElement("tr");
  [file.name, file.size_bytes + " bytes", file.sha256.slice(0, 16) + "..."].forEach((text) => {
    const td = document.createElement("td");
    td.textContent = text;
    tr.appendChild(td);
  });
  const link = document.createElement("a");
  link.href = "/api/files/" + file.id + "/download";
  link.textContent = "Download";
  const td = document.createElement("td");
  td.appendChild(link);
  tr.appendChild(td);
  rows.appendChild(tr);
}

async function loadFiles() {
  const response = await fetch("/api/files");
  if (!response.ok) return;
  const data = await response.json();
  rows.textContent = "";
  data.files.forEach(addRow);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const response = await fetch("/api/files/upload", {
      method: "POST",
      body: new FormData(form),
      headers: { "X-CSRFToken": form.dataset.csrf },
    });
    const data = await response.json();
    if (response.ok) {
      show("Uploaded. SHA-256: " + data.sha256, "success");
      form.reset();
      loadFiles();
    } else {
      show(data.message || "Upload failed.", "danger");
    }
  } catch (error) {
    show("Network error. Try again.", "danger");
  }
});

loadFiles();