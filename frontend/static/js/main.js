const el = document.getElementById("status");
fetch("/api/health")
  .then((r) => r.json())
  .then((d) => { el.textContent = `Backend: ${d.status}`; el.className = "badge bg-success fs-6"; })
  .catch(() => { el.textContent = "Backend unreachable"; el.className = "badge bg-danger fs-6"; });