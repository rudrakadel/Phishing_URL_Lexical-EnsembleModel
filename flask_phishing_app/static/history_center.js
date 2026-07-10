const searchInput = document.getElementById("history-search");
const refreshButton = document.getElementById("history-refresh-page");
const summaryBox = document.getElementById("history-summary-page");
const tableWrap = document.getElementById("history-table-page");
const detailPanel = document.getElementById("history-detail");
const detailTitle = document.getElementById("detail-title");
const detailBody = document.getElementById("detail-body");
const detailClose = document.getElementById("detail-close");
const filterButtons = document.querySelectorAll("[data-history-filter]");
const limitSelect = document.getElementById("history-limit");

let allItems = [];
let activeFilter = "all";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function riskClass(verdict) {
  const lower = (verdict || "").toLowerCase();
  if (lower.includes("known malicious") || lower.includes("high")) return "risk-high";
  if (lower.includes("medium")) return "risk-medium";
  return "risk-low";
}

function riskBucket(item) {
  const verdict = String(item?.verdict || "").toLowerCase();
  const score = Number(item?.risk_score || 0);
  if (verdict.includes("known malicious") || verdict.includes("high") || verdict.includes("medium") || score >= 40) {
    return "phishing";
  }
  return "not-phishing";
}

function riskLabel(item) {
  return riskBucket(item) === "phishing" ? "Phishing" : "Not phishing";
}

function riskBadgeClass(item) {
  return riskBucket(item) === "phishing" ? "risk-badge risk-badge-danger" : "risk-badge risk-badge-safe";
}

async function fetchJson(url) {
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function render(items) {
  const riskyCount = items.filter((item) => riskBucket(item) === "phishing").length;
  const safeCount = items.filter((item) => riskBucket(item) === "not-phishing").length;
  summaryBox.innerHTML = `
    <div class="inline-chip">Total: ${items.length}</div>
    <div class="inline-chip">Phishing: ${riskyCount}</div>
    <div class="inline-chip">Not phishing: ${safeCount}</div>
    <div class="inline-chip">Cached: ${items.filter((item) => item.cache_hit).length}</div>
  `;

  if (!items.length) {
    tableWrap.innerHTML = `<div class="muted">No history records found.</div>`;
    return;
  }

  tableWrap.innerHTML = `
    <div class="records-table">
      <div class="records-head">URL</div>
      <div class="records-head">User</div>
      <div class="records-head">Label</div>
      <div class="records-head">Verdict</div>
      <div class="records-head">Score</div>
      <div class="records-head">Cache</div>
      <div class="records-head">Created</div>
      ${items.map((item) => `
        <button class="records-cell records-link history-open" data-id="${item.id}" type="button">
          <div>${escapeHtml(item.url)}</div>
          <div class="row-subline">${escapeHtml(item.normalized_url || "")}</div>
        </button>
        <div class="records-cell">
          <div>${escapeHtml(item.username || "anonymous")}</div>
          <div class="row-subline">${escapeHtml(item.auth_provider || "local")}</div>
        </div>
        <div class="records-cell"><span class="${riskBadgeClass(item)}">${riskLabel(item)}</span></div>
        <div class="records-cell ${riskClass(item.verdict)}">${escapeHtml(item.verdict)}</div>
        <div class="records-cell">${escapeHtml(item.risk_score)}</div>
        <div class="records-cell">${item.cache_hit ? '<span class="inline-chip">Cached</span>' : 'Fresh'}</div>
        <div class="records-cell">${escapeHtml(item.created_at)}</div>
      `).join("")}
    </div>
  `;
  document.querySelectorAll(".history-open").forEach((row) => {
    row.addEventListener("click", async () => {
      await openDetail(row.dataset.id);
    });
  });
}

async function openDetail(id) {
  detailPanel.classList.add("is-open");
  detailTitle.textContent = "Loading record...";
  detailBody.innerHTML = `<div class="muted">Fetching saved analysis...</div>`;
  try {
    const data = await fetchJson(`/api/analysis/${id}`);
    detailTitle.textContent = data.url || "Analysis record";
    detailBody.innerHTML = `
      <div class="detail-grid">
        <div class="kv-row"><span>Verdict</span><strong class="${riskClass(data.verdict)}">${escapeHtml(data.verdict)}</strong></div>
        <div class="kv-row"><span>Hybrid Score</span><strong>${escapeHtml(data.hybrid_score)}</strong></div>
        <div class="kv-row"><span>Model Probability</span><strong>${escapeHtml(((Number(data.ml?.probability || 0) * 100).toFixed(2)))}%</strong></div>
        <div class="kv-row"><span>Enrichment</span><strong>${escapeHtml(data.enrichment?.status || "complete")}</strong></div>
      </div>
      <div class="soft-title">Analyst Summary</div>
      <p>${escapeHtml(data.human_summary || "No summary available.")}</p>
      <div class="soft-title">Threat Sources</div>
      <div>${escapeHtml((data.threat_intelligence?.sources || []).join(", ") || "None")}</div>
      <div class="soft-title">Top SHAP Features</div>
      <ul class="clean-list">
        ${(data.shap?.top_features || []).slice(0, 5).map((item) => `<li>${escapeHtml(item.feature)}: ${escapeHtml(item.impact.toFixed(4))}</li>`).join("") || "<li>No SHAP data</li>"}
      </ul>
      <div class="soft-title">Notes</div>
      <div class="stack">
        ${(data.notes || []).map((note) => `<div class="note"><div>${escapeHtml(note.note)}</div><div class="note-time">${escapeHtml(note.created_at)}</div></div>`).join("") || '<div class="muted">No notes saved.</div>'}
      </div>
      <details class="expandable">
        <summary>Show saved payload</summary>
        <pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>
    `;
  } catch (error) {
    detailTitle.textContent = "Record unavailable";
    detailBody.innerHTML = `<div class="muted">${escapeHtml(error.message)}</div>`;
  }
}

function applyFilter() {
  const term = searchInput.value.trim().toLowerCase();
  const filtered = allItems.filter((item) => {
    const matchesBucket = activeFilter === "all" || riskBucket(item) === activeFilter;
    if (!matchesBucket) return false;
    if (!term) return true;
    return [item.url, item.normalized_url, item.username, item.auth_provider, item.verdict, riskLabel(item)]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(term));
  });
  render(filtered);
}

function setActiveFilter(nextFilter) {
  activeFilter = nextFilter || "all";
  filterButtons.forEach((button) => {
    const isActive = button.dataset.historyFilter === activeFilter;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-pressed", isActive ? "true" : "false");
  });
  applyFilter();
}

async function loadHistory() {
  const limit = Number(limitSelect?.value || 250);
  const data = await fetchJson(`/api/history?limit=${limit}`);
  allItems = data.items || [];
  applyFilter();
}

searchInput.addEventListener("input", applyFilter);
filterButtons.forEach((button) => {
  button.addEventListener("click", () => setActiveFilter(button.dataset.historyFilter));
});
refreshButton.addEventListener("click", async () => {
  try {
    await loadHistory();
  } catch (error) {
    tableWrap.innerHTML = `<div class="muted">${escapeHtml(error.message)}</div>`;
  }
});
limitSelect?.addEventListener("change", async () => {
  try {
    await loadHistory();
  } catch (error) {
    tableWrap.innerHTML = `<div class="muted">${escapeHtml(error.message)}</div>`;
  }
});

detailClose.addEventListener("click", () => {
  detailPanel.classList.remove("is-open");
});

loadHistory().catch((error) => {
  tableWrap.innerHTML = `<div class="muted">${escapeHtml(error.message)}</div>`;
});
