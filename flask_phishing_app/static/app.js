const form = document.getElementById("analyze-form");
const composerInput = document.getElementById("composer-input");
const modeSingleButton = document.getElementById("mode-single");
const modeBatchButton = document.getElementById("mode-batch");
const composerHint = document.getElementById("composer-hint");
const composerModeLabel = document.getElementById("composer-mode-label");
const dashboardGreeting = document.getElementById("dashboard-greeting");
const dashboardLede = document.getElementById("dashboard-lede");
const dashboardQuote = document.getElementById("dashboard-quote");
const dashboardIstTime = document.getElementById("dashboard-ist-time");
const sessionIdentity = document.getElementById("session-identity");
const primaryNav = document.getElementById("primary-nav");
const batchStatus = document.getElementById("batch-status");
const batchResults = document.getElementById("batch-results");
const detectedUrlsBox = document.getElementById("detected-urls");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");
const summary = document.getElementById("summary");
const actions = document.getElementById("actions");
const components = document.getElementById("components");
const headers = document.getElementById("headers");
const threatIntel = document.getElementById("threat-intel");
const ollamaSummary = document.getElementById("ollama-summary");
const nlp = document.getElementById("nlp");
const shapSummary = document.getElementById("shap-summary");
const model = document.getElementById("model");
const screenshotWrap = document.getElementById("screenshot-wrap");
const sandboxFrame = document.getElementById("sandbox-frame");
const sandboxMeta = document.getElementById("sandbox-meta");
const sandboxSource = document.getElementById("sandbox-source");
const sandboxSourceWrap = document.getElementById("sandbox-source-wrap");
const network = document.getElementById("network");
const historyBox = document.getElementById("history");
const refreshHistory = document.getElementById("refresh-history");
const noteInput = document.getElementById("note-input");
const saveNoteButton = document.getElementById("save-note");
const notes = document.getElementById("notes");
const feedbackCorrectButton = document.getElementById("feedback-correct");
const feedbackIncorrectButton = document.getElementById("feedback-incorrect");
const feedbackLabelInput = document.getElementById("feedback-label");
const feedbackNoteInput = document.getElementById("feedback-note");
const feedbackStatus = document.getElementById("feedback-status");
const feedbackSummary = document.getElementById("feedback-summary");
const communityFeedback = document.getElementById("community-feedback");
const authPanel = document.getElementById("auth-panel");
const chartGauge = document.getElementById("chart-gauge");
const chartComponents = document.getElementById("chart-components");
const chartShap = document.getElementById("chart-shap");
const googleClientId = document.querySelector("meta[name='google-client-id']")?.content;

let currentAnalysisId = null;
let authState = { require_auth: false, authenticated: true };
let enrichmentPollId = null;
let composerMode = "single";
let lastBatchItems = [];
let selectedBatchUrl = null;
let greetingTimerId = null;

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeComparableUrl(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "";
  return text.replace(/(?<!:)\/+$/g, "");
}

function riskClass(verdict) {
  const lower = (verdict || "").toLowerCase();
  if (lower.includes("known malicious") || lower.includes("high")) return "risk-high";
  if (lower.includes("medium")) return "risk-medium";
  return "risk-low";
}

function probabilityClass(probability) {
  const value = Number(probability || 0);
  if (value >= 0.75) return "prob-high";
  if (value >= 0.4) return "prob-medium";
  return "prob-low";
}

function percent(probability) {
  return `${(Number(probability || 0) * 100).toFixed(2)}%`;
}

function scorePercent(value) {
  return `${Number(value || 0).toFixed(2)}%`;
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

function modelScoreValue(data) {
  if (!data?.ml?.available) return null;
  if (data.components?.ML != null) return Number(data.components.ML || 0);
  return Number(data.ml?.probability || 0) * 100;
}

function finalLikelihoodValue(data) {
  return Number(data?.hybrid_score || 0);
}

function renderList(items, emptyText = "None") {
  if (!items || !items.length) return `<div class="muted">${escapeHtml(emptyText)}</div>`;
  return `<ul class="clean-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderKvRows(data) {
  const entries = Object.entries(data || {});
  if (!entries.length) return `<div class="muted">No data</div>`;
  return entries.map(([key, value]) => `<div class="kv-row"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
}

function renderSignalSection(title, items, emptyText) {
  if (!items || !items.length) return "";
  return `
    <div class="soft-title">${escapeHtml(title)}</div>
    ${renderList(items, emptyText)}
  `;
}

function buildNetworkSummary(data) {
  const crawl = data?.network?.crawl || {};
  const ssl = data?.network?.ssl || {};
  const dns = data?.network?.dns || {};
  const reputation = data?.network?.reputation || {};
  const urlSignals = data?.network?.url_signals || {};
  const headersData = data?.network?.security_headers || {};

  const rows = [
    ["Page fetched", yesNo(crawl.html_ok)],
    ["Page title", crawl.title || "Unavailable"],
    ["HTTP status", crawl.status_code ?? "Unavailable"],
    ["Login form", yesNo(crawl.login_form)],
    ["Iframe detected", yesNo(crawl.iframe)],
    ["Suspicious form action", yesNo(crawl.suspicious_form_handler)],
    ["External links", `${Math.round(Number(crawl.ratio_external_links || 0) * 100)}%`],
    ["Null links", `${Math.round(Number(crawl.ratio_null_links || 0) * 100)}%`],
    ["HTTPS", yesNo(urlSignals.uses_https)],
    ["SSL certificate", ssl.has_ssl ? "Present" : "Unavailable"],
    ["Certificate issuer", ssl.issuer || "Unknown"],
    ["Expires in", ssl.days_until_expiry == null ? "Unknown" : `${ssl.days_until_expiry} days`],
    ["A record", yesNo(dns.has_a_record)],
    ["Mail record", yesNo(dns.has_mx_record)],
    ["SPF", yesNo(dns.has_spf)],
    ["DMARC", yesNo(dns.has_dmarc)],
    ["Domain age", reputation.domain_age_days == null ? "Unknown" : `${reputation.domain_age_days} days`],
    ["Security headers missing", (headersData.missing || []).length],
  ];

  const notes = [];
  if (reputation.risk_factors?.length) {
    notes.push(`Domain signals: ${reputation.risk_factors.join(", ")}`);
  }
  if (headersData.issues?.length) {
    notes.push(`Header issues: ${headersData.issues.slice(0, 3).join(", ")}`);
  }
  if (crawl.error) {
    notes.push(`Fetch note: ${crawl.error}`);
  }
  if (ssl.error) {
    notes.push(`SSL note: ${ssl.error}`);
  }
  if (dns.error) {
    notes.push(`DNS note: ${dns.error}`);
  }

  return `
    ${rows.map(([label, value]) => `<div class="kv-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}
    <div class="soft-title">Analyst Notes</div>
    ${renderList(notes, "No additional network concerns detected.")}
  `;
}

function renderNotes(items) {
  if (!items || !items.length) {
    notes.innerHTML = `<div class="muted">No notes yet.</div>`;
    return;
  }
  notes.innerHTML = items
    .map((item) => `<div class="note"><div>${escapeHtml(item.note)}</div><div class="note-time">${escapeHtml(item.created_at)}</div></div>`)
    .join("");
}

function setChart(img, value) {
  if (value) {
    img.src = `data:image/png;base64,${value}`;
    img.classList.remove("hidden-block");
  } else {
    img.removeAttribute("src");
    img.classList.add("hidden-block");
  }
}

function renderAuthPanel() {
  if (!authState.authenticated) {
    authPanel.classList.add("hidden");
    if (primaryNav && !primaryNav.querySelector('[data-auth-link="login"]')) {
      primaryNav.insertAdjacentHTML("beforeend", `<a href="/login" data-auth-link="login">Login</a>`);
    }
    return;
  }
  authPanel.classList.remove("hidden");
  const loginLink = primaryNav?.querySelector('[data-auth-link="login"]');
  if (loginLink) loginLink.remove();
  if (primaryNav && !primaryNav.querySelector('[data-auth-link="account"]')) {
    primaryNav.insertAdjacentHTML(
      "beforeend",
      `<button id="nav-account-button" type="button" class="nav-account" data-auth-link="account">${escapeHtml(authState.first_name || authState.username || "Analyst")} - Logout</button>`
    );
    document.getElementById("nav-account-button")?.addEventListener("click", logout);
  }
  authPanel.innerHTML = `
    <div class="auth-row">
      <div>Signed in as <strong>${escapeHtml(authState.first_name || authState.username || "Analyst")}</strong> <span class="inline-chip">${escapeHtml(authState.username || "user")}</span> <span class="inline-chip">${escapeHtml(authState.mobile || "no mobile")}</span></div>
      <button id="logout-button" type="button" class="ghost">Logout</button>
    </div>
  `;
  document.getElementById("logout-button").addEventListener("click", logout);
}

function renderGoogleButton() {
  const slot = document.getElementById("google-login-slot");
  if (!slot || !window.google?.accounts?.id || !authState.google_client_id) return;
  slot.innerHTML = "";
  window.google.accounts.id.initialize({
    client_id: authState.google_client_id,
    callback: async (response) => {
      try {
        await fetchJson("/api/auth/google", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ credential: response.credential }),
        });
        await loadAuthStatus();
        await loadHistory();
        statusBox.textContent = "Authenticated with Google.";
      } catch (error) {
        statusBox.textContent = error.message;
      }
    },
  });
  window.google.accounts.id.renderButton(slot, { theme: "outline", size: "large", text: "continue_with" });
}

function extractUrlsFromText(text) {
  const input = String(text || "").trim();
  if (!input) return [];
  const normalized = input
    .replace(/\bhxxps:\/\//gi, "https://")
    .replace(/\bhxxp:\/\//gi, "http://");
  const matches = normalized.match(/((?:(?:https?|ftp):\/\/|www\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s<>"]*)?)/gi) || [];
  const seen = new Set();
  return matches
    .map((item) => item.replace(/[()[\]{}<>,?!'"`]+$/g, ""))
    .map((item) => item.replace(/(?<!\/)\/+$/g, ""))
    .map((item) => item.startsWith("http://") || item.startsWith("https://") || item.startsWith("ftp://")
      ? item
      : `http://${item}`)
    .filter((item) => {
      if (!item || seen.has(item)) return false;
      seen.add(item);
      return true;
    });
}

function findBatchItemByUrl(url) {
  const target = normalizeComparableUrl(url);
  return lastBatchItems.find((item) => {
    const candidates = [item.url, item.input_url, item.normalized_url].map(normalizeComparableUrl).filter(Boolean);
    return candidates.includes(target);
  }) || null;
}

function renderDetectedUrls() {
  if (!detectedUrlsBox || !composerInput) return;
  const urls = extractUrlsFromText(composerInput.value);
  if (!urls.length) {
    detectedUrlsBox.classList.add("hidden-block");
    detectedUrlsBox.innerHTML = "";
    return;
  }
  detectedUrlsBox.classList.remove("hidden-block");
  detectedUrlsBox.innerHTML = `
    <div class="soft-title">Detected URLs</div>
    <div class="detected-url-list">
      ${urls.map((url) => {
        const hasResult = Boolean(findBatchItemByUrl(url));
        const selected = selectedBatchUrl === url;
        return `<button type="button" class="detected-url-chip ${hasResult ? "is-interactive" : ""} ${selected ? "is-selected" : ""}" data-detected-url="${escapeHtml(url)}">${escapeHtml(url)}</button>`;
      }).join("")}
    </div>
  `;
  detectedUrlsBox.querySelectorAll("[data-detected-url]").forEach((button) => {
    button.addEventListener("click", () => {
      const url = button.getAttribute("data-detected-url") || "";
      if (!url) return;
      selectedBatchUrl = url;
      renderDetectedUrls();
      const item = findBatchItemByUrl(url);
      if (item) {
        renderResult(item);
        batchStatus.textContent = `Showing result for ${url}`;
      } else if (composerMode === "single") {
        statusBox.textContent = "Single mode will analyze the first detected URL only.";
      } else {
        batchStatus.textContent = "Run batch analysis to view this URL result.";
      }
    });
  });
}

function renderCommunityFeedbackBox(data) {
  if (!communityFeedback) return;
  const feedback = data?.community_feedback || {};
  if (!feedback.available) {
    communityFeedback.innerHTML = `<div class="muted">No community feedback for this URL yet.</div>`;
    if (feedbackSummary) feedbackSummary.innerHTML = `<div class="muted">No feedback submitted yet.</div>`;
    return;
  }
  communityFeedback.innerHTML = `
    <div class="kv-row"><span>Helpful</span><strong>${escapeHtml(feedback.helpful_count)}</strong></div>
    <div class="kv-row"><span>Needs review</span><strong>${escapeHtml(feedback.not_helpful_count)}</strong></div>
    <p>${escapeHtml(feedback.caution || "Community feedback is advisory only.")}</p>
    <div class="soft-title">Top corrected labels</div>
    ${renderList((feedback.top_corrected_labels || []).map((item) => `${item.label} (${item.count})`), "No corrected labels submitted")}
  `;
  if (feedbackSummary) {
    feedbackSummary.innerHTML = `
      <div class="soft-title">Recent feedback</div>
      ${renderList((feedback.recent || []).map((item) => `${item.helpful ? "Helpful" : "Needs review"}${item.corrected_label ? ` · ${item.corrected_label}` : ""}${item.note ? ` · ${item.note}` : ""}`), "No feedback submitted yet")}
    `;
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    const text = await response.text();
    if (response.redirected || text.toLowerCase().includes("<!doctype html")) {
      window.location.href = "/login";
      throw new Error("Your session expired. Please sign in again.");
    }
    throw new Error(`Unexpected response from server: ${text.slice(0, 120)}`);
  }
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

async function loadAuthStatus() {
  authState = await fetchJson("/api/auth/status");
  updateGreeting();
  renderAuthPanel();
}

async function logout() {
  await fetchJson("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
}

function greetingPrefix(hours) {
  if (hours >= 5 && hours < 12) return "Good morning";
  if (hours >= 12 && hours < 17) return "Good afternoon";
  if (hours >= 17 && hours < 22) return "Good evening";
  return "Good night";
}

function getIstParts() {
  const formatter = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  const parts = formatter.formatToParts(new Date());
  const hour = Number(parts.find((part) => part.type === "hour")?.value ?? new Date().getHours());
  const minute = Number(parts.find((part) => part.type === "minute")?.value ?? 0);
  return { hour: hour === 24 ? 0 : hour, minute };
}

function formatIstTime({ hour, minute }) {
  const suffix = hour >= 12 ? "PM" : "AM";
  const displayHour = hour % 12 || 12;
  return `${displayHour}:${String(minute).padStart(2, "0")} ${suffix}`;
}

function updateGreeting() {
  if (!dashboardGreeting || !sessionIdentity) return;
  const ist = getIstParts();
  const hours = ist.hour;
  const firstName = authState.first_name || "Analyst";
  const quote = hours >= 5 && hours < 12
    ? '"Start sharp. Small signals become big catches."'
    : hours >= 12 && hours < 17
      ? '"Good investigations come from patient pattern reading."'
      : hours >= 17 && hours < 22
        ? '"Keep the review steady. Patterns show up with context."'
        : '"Slow down, verify, and let the evidence speak."';
  dashboardGreeting.textContent = `${greetingPrefix(hours)}, ${firstName}`;
  dashboardLede.textContent = composerMode === "batch"
    ? `Your protected phishing analysis desk is ready, ${firstName}. Paste multiple URLs and process them in a single review cycle.`
    : `Your protected phishing analysis desk is ready, ${firstName}. Drop in a suspicious URL and review the verdict, evidence, and enrichment layers.`;
  if (dashboardQuote) dashboardQuote.textContent = quote;
  if (dashboardIstTime) dashboardIstTime.textContent = `${formatIstTime(ist)} IST`;
  sessionIdentity.textContent = `${firstName} - ${authState.username || "analyst"}`;
}

function startGreetingClock() {
  if (greetingTimerId) clearInterval(greetingTimerId);
  greetingTimerId = setInterval(updateGreeting, 60000);
}

function setComposerMode(mode) {
  composerMode = mode;
  if (!composerInput) return;
  const batch = mode === "batch";
  modeSingleButton?.classList.toggle("active", !batch);
  modeBatchButton?.classList.toggle("active", batch);
  composerModeLabel.textContent = batch ? "Batch URLs" : "Single URL";
  composerInput.rows = batch ? 8 : 5;
  composerInput.placeholder = batch
    ? "Paste one suspicious URL per line for batch analysis."
    : "Paste a suspicious URL here for immediate analysis.";
  composerHint.textContent = batch
    ? "Batch mode accepts one URL per line and returns a compact decision table."
    : "Single mode is optimized for one target with full review and follow-up notes. Prompt-style text is supported.";
  updateGreeting();
  renderDetectedUrls();
}

function renderResult(data) {
  currentAnalysisId = data.analysis_id || null;
  selectedBatchUrl = data.url || data.input_url || selectedBatchUrl;
  const modelScore = modelScoreValue(data);
  const finalLikelihood = finalLikelihoodValue(data);
  results.classList.remove("hidden");
  summary.innerHTML = `
    <div class="hero-result">
      <div><div class="metric-label">Verdict</div><div class="metric-value ${riskClass(data.verdict)}">${escapeHtml(data.verdict)}</div></div>
      <div><div class="metric-label">Hybrid</div><div class="metric-value">${escapeHtml(data.hybrid_score)}</div></div>
      <div><div class="metric-label">Confidence</div><div class="metric-value">${escapeHtml(data.confidence)}</div></div>
    </div>
    <div class="summary-stack">
      <p><strong>URL:</strong> ${escapeHtml(data.url)}</p>
      <p><strong>Domain:</strong> ${escapeHtml(data.domain || "Unknown")}</p>
      <p><strong>Features Used:</strong> ${escapeHtml((data.selected_features || []).join(", "))}</p>
      <p><strong>Analyst Summary:</strong> ${escapeHtml(data.human_summary || "None")}</p>
    </div>
  `;

  actions.innerHTML = `
    <div class="kv-row"><span>Model ready</span><strong>${data.model_ready ? "Yes" : "No"}</strong></div>
    <div class="kv-row"><span>Base classifier</span><strong>${escapeHtml(data.ml?.prediction || "unknown")}</strong></div>
    <div class="kv-row probability-row"><span>Final phishing likelihood</span><strong class="${probabilityClass(finalLikelihood / 100)}">${escapeHtml(scorePercent(finalLikelihood))}</strong></div>
    <div class="probability-bar"><span class="${probabilityClass(finalLikelihood / 100)}" style="width:${Math.max(4, finalLikelihood || 0)}%"></span></div>
    <div class="kv-row"><span>Base model probability</span><strong>${escapeHtml(modelScore == null ? "Unavailable" : scorePercent(modelScore))}</strong></div>
    <div class="kv-row"><span>Confidence</span><strong>${scorePercent(data.confidence)}</strong></div>
    <div class="kv-row"><span>Cache</span><strong>${data.cache?.hit ? `Hit via ${data.cache.backend}` : "Miss"}</strong></div>
    <div class="kv-row"><span>Analysis time</span><strong>${escapeHtml(data.analysis_duration_ms ?? 0)} ms</strong></div>
    ${currentAnalysisId ? `<a class="button-link" href="/api/report/${currentAnalysisId}" target="_blank" rel="noopener">Download PDF Report</a>` : ""}
  `;

  components.innerHTML = renderKvRows(data.components);
  const explicit = data.network?.explicit_security || {};
  headers.innerHTML = `
    <div class="kv-row"><span>Security Risk Score</span><strong>${explicit.security_score ?? 0}/100</strong></div>
    <div class="kv-row"><span>HSTS Enabled</span><strong>${yesNo(explicit.hsts_present)}</strong></div>
    <div class="kv-row"><span>CSP Enabled</span><strong>${yesNo(explicit.csp_present)}</strong></div>
    <div class="kv-row"><span>X-Frame-Options</span><strong>${yesNo(explicit.x_frame_options_present)}</strong></div>
    <div class="kv-row"><span>JS Obfuscated</span><strong>${yesNo(explicit.js_obfuscated)}</strong></div>
    <div class="kv-row"><span>Body Frames / IFrames</span><strong>${yesNo(explicit.has_iframe)}</strong></div>
    
    <div class="soft-title" style="margin-top: 14px; margin-bottom: 8px;">Detected Issues & Findings</div>
    ${renderList(explicit.security_findings, "No security vulnerabilities or concerns flagged.")}

    <details class="expandable" style="margin-top: 14px;">
      <summary>Show raw HTTP response headers</summary>
      <div style="margin-top: 10px; display: grid; gap: 10px;">
        <div class="soft-title">Present Headers</div>
        ${renderKvRows(data.network?.security_headers?.present || {})}
        <div class="soft-title">Missing Critical Headers</div>
        ${renderList(data.network?.security_headers?.missing, "No missing critical headers")}
      </div>
    </details>
  `;
  threatIntel.innerHTML = `
    <div class="kv-row"><span>Known malicious</span><strong>${data.threat_intelligence?.known_malicious ? "Yes" : "No"}</strong></div>
    <div class="kv-row"><span>Sources</span><strong>${escapeHtml((data.threat_intelligence?.sources || []).join(", ") || "None")}</strong></div>
    <details class="expandable"><summary>Show details</summary><pre>${escapeHtml(pretty(data.threat_intelligence || {}))}</pre></details>
  `;
  const ollamaAvailable = Boolean(data.ollama?.available);
  ollamaSummary.innerHTML = `
    <div class="kv-row"><span>Available</span><strong>${data.ollama?.available ? "Yes" : "No"}</strong></div>
    <div class="kv-row"><span>Review Type</span><strong>${escapeHtml(ollamaAvailable ? "Ollama" : "Heuristic fallback")}</strong></div>
    <div class="kv-row"><span>Final Decision</span><strong>${escapeHtml(data.ollama?.final_decision || data.ollama?.risk_level || "Unknown")}</strong></div>
    <p>${escapeHtml(data.ollama?.summary || data.ollama?.error || "No Ollama analysis available.")}</p>
    ${renderSignalSection("Why It Looks Phishing", data.ollama?.phishing_signals, "No phishing signals returned")}
    ${renderSignalSection("Why It Might Be Legitimate", data.ollama?.legitimate_signals, "No legitimate signals returned")}
    ${renderSignalSection("Reasoning", data.ollama?.verdict_reasoning, "No reasoning returned")}
    ${renderSignalSection("Findings", data.ollama?.findings, "No findings")}
    ${renderSignalSection("Recommendations", data.ollama?.recommendations, "No recommendations")}
  `;
  nlp.innerHTML = `
    <div class="kv-row"><span>Content Risk</span><strong>${escapeHtml(data.nlp?.risk_score ?? 0)}</strong></div>
    <p>${escapeHtml(data.nlp?.summary || "No visible text summary available.")}</p>
    <div class="soft-title">Suspicious Phrases</div>
    ${renderList(data.nlp?.suspicious_phrases, "No suspicious phrases detected in visible text")}
  `;
  shapSummary.innerHTML = `
    <div class="kv-row"><span>Available</span><strong>${data.shap?.available ? "Yes" : "No"}</strong></div>
    <div class="kv-row"><span>Explanation method</span><strong>${escapeHtml(data.shap?.method || data.shap?.estimator || data.shap?.reason || "None")}</strong></div>
    <div class="kv-row"><span>Explained model</span><strong>${escapeHtml(data.shap?.estimator || "None")}</strong></div>
    ${renderList((data.shap?.top_features || []).map((item) => `${item.feature}: ${item.impact > 0 ? "+" : ""}${item.impact.toFixed(4)} vs reference ${item.reference_value ?? "n/a"} (value ${item.value})`), "No feature contributions")}
  `;

  model.textContent = pretty(data.ml);
  network.innerHTML = buildNetworkSummary(data);

  screenshotWrap.innerHTML = data.screenshot?.available
    ? `<img class="screenshot-image" src="${escapeHtml(data.screenshot.path)}" alt="Captured screenshot">`
    : `<div class="muted">${escapeHtml(data.screenshot?.error || "Screenshot unavailable")}</div>`;

  sandboxMeta.innerHTML = `
    <div class="kv-row"><span>Removed tags</span><strong>${escapeHtml(data.sandbox?.removed?.dangerous_tags ?? 0)}</strong></div>
    <div class="kv-row"><span>Removed handlers</span><strong>${escapeHtml(data.sandbox?.removed?.event_handlers ?? 0)}</strong></div>
    <div class="kv-row"><span>Removed JS URLs</span><strong>${escapeHtml(data.sandbox?.removed?.javascript_urls ?? 0)}</strong></div>
    <div class="kv-row"><span>Source length</span><strong>${escapeHtml(data.sandbox?.source_length ?? 0)}</strong></div>
  `;
  sandboxFrame.srcdoc = "";
  sandboxFrame.srcdoc = `${data.sandbox?.html || "<div>Sandbox unavailable</div>"}<!-- ${escapeHtml(data.generated_at || Date.now())} -->`;
  sandboxSource.textContent = data.sandbox?.source_excerpt || "";
  if ((data.sandbox?.source_length || 0) > 500) {
    sandboxSourceWrap.classList.remove("hidden-block");
    sandboxSourceWrap.querySelector("summary").textContent = data.sandbox?.truncated ? "Show sanitized source excerpt" : "Show sanitized source";
  } else {
    sandboxSourceWrap.classList.add("hidden-block");
  }

  setChart(chartGauge, data.charts?.gauge);
  setChart(chartComponents, data.charts?.components);
  setChart(chartShap, data.charts?.shap);
  renderNotes(data.notes || []);
  renderCommunityFeedbackBox(data);
}

async function pollEnrichment(analysisId) {
  if (enrichmentPollId) {
    clearInterval(enrichmentPollId);
  }
  enrichmentPollId = setInterval(async () => {
    try {
      const data = await fetchJson(`/api/analysis/${analysisId}`);
      if ((data.enrichment?.status || "complete") === "pending") {
        statusBox.textContent = "Fast result ready. Deep enrichment is still running...";
        return;
      }
      clearInterval(enrichmentPollId);
      enrichmentPollId = null;
      renderResult(data);
      statusBox.textContent = data.enrichment?.status === "complete"
        ? "Deep enrichment completed."
        : `Enrichment stopped: ${data.enrichment?.error || "unknown error"}`;
      await loadHistory();
    } catch (error) {
      clearInterval(enrichmentPollId);
      enrichmentPollId = null;
      statusBox.textContent = error.message;
    }
  }, 3000);
}

async function analyze(url) {
  statusBox.textContent = "Running fast analysis...";
  const data = await fetchJson("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, text: composerInput.value }),
  });
  lastBatchItems = [];
  selectedBatchUrl = data.url || null;
  renderResult(data);
  if ((data.enrichment?.status || "complete") === "pending" && data.analysis_id) {
    statusBox.textContent = "Fast result ready. Deep enrichment queued.";
    pollEnrichment(data.analysis_id);
  } else {
    statusBox.textContent = "Complete report ready.";
  }
  await loadHistory();
}

async function loadHistory() {
  if (!historyBox) {
    return;
  }
  if (authState.require_auth && !authState.authenticated) {
    historyBox.innerHTML = `<div class="muted">Login required.</div>`;
    return;
  }
  const data = await fetchJson("/api/history?limit=10");
  const items = data.items || [];
  if (!items.length) {
    historyBox.innerHTML = "No analysis history yet.";
    return;
  }
  historyBox.innerHTML = items
    .map(
      (item) => `
        <button class="history-row" data-id="${item.id}" type="button">
          <div>
            <div>${escapeHtml(item.url)}</div>
            <div class="row-subline">${escapeHtml(item.username || "anonymous")} · ${escapeHtml(item.auth_provider || "local")}</div>
          </div>
          <div class="${riskClass(item.verdict)}">${escapeHtml(item.verdict)}</div>
          <div>${escapeHtml(item.risk_score)}${item.cache_hit ? ' <span class="inline-chip">cached</span>' : ""}</div>
          <div>${escapeHtml(item.created_at)}</div>
        </button>
      `
    )
    .join("");
  document.querySelectorAll(".history-row").forEach((row) => {
    row.addEventListener("click", async () => {
      const data = await fetchJson(`/api/analysis/${row.dataset.id}`);
      renderResult(data);
    });
  });
}

function renderBatchResults(items) {
  lastBatchItems = items || [];
  if (lastBatchItems.length && !selectedBatchUrl) {
    selectedBatchUrl = lastBatchItems[0].url || lastBatchItems[0].input_url || null;
  }
  if (!items.length) {
    batchResults.innerHTML = `<div class="muted">No batch results.</div>`;
    batchResults.classList.remove("hidden-block");
    renderDetectedUrls();
    return;
  }
  batchResults.innerHTML = `
    <div class="batch-table">
      <div class="batch-head">URL</div>
      <div class="batch-head">Verdict</div>
      <div class="batch-head">Hybrid</div>
      <div class="batch-head">Status</div>
      ${items.map((item) => `
        <button class="batch-cell batch-link ${normalizeComparableUrl(selectedBatchUrl) === normalizeComparableUrl(item.url || item.input_url || "") ? "is-selected" : ""}" data-analysis-id="${escapeHtml(item.analysis_id || "")}" data-batch-url="${escapeHtml(item.url || item.input_url || "")}" type="button">
          <div>${escapeHtml(item.url || item.input_url || "")}</div>
          <div class="row-subline">${escapeHtml(item.domain || item.normalized_url || "")}</div>
        </button>
        <div class="batch-cell ${riskClass(item.verdict)}">${escapeHtml(item.verdict || "Unknown")}</div>
        <div class="batch-cell">${escapeHtml(item.hybrid_score ?? "-")}</div>
        <div class="batch-cell">${escapeHtml(item.enrichment?.status || "complete")}</div>
      `).join("")}
    </div>
  `;
  batchResults.classList.remove("hidden-block");
  batchResults.querySelectorAll(".batch-link").forEach((button) => {
    button.addEventListener("click", async () => {
      const url = button.getAttribute("data-batch-url") || "";
      const analysisId = Number(button.getAttribute("data-analysis-id") || "0");
      selectedBatchUrl = url;
      const cachedItem = findBatchItemByUrl(url);
      if (cachedItem) {
        renderResult(cachedItem);
      }
      renderBatchResults(lastBatchItems);
      batchStatus.textContent = `Showing result for ${url}`;
      if (!analysisId) return;
      const latest = await fetchJson(`/api/analysis/${analysisId}`);
      const index = lastBatchItems.findIndex((item) => Number(item.analysis_id || 0) === analysisId);
      if (index >= 0) {
        lastBatchItems[index] = latest;
      }
      renderResult(latest);
      renderBatchResults(lastBatchItems);
      if ((latest.enrichment?.status || "complete") === "pending") {
        pollEnrichment(analysisId);
      }
    });
  });
  renderDetectedUrls();
  const activeItem = findBatchItemByUrl(selectedBatchUrl || "") || lastBatchItems[0];
  if (activeItem) {
    renderResult(activeItem);
    if ((activeItem.enrichment?.status || "complete") === "pending" && activeItem.analysis_id) {
      pollEnrichment(activeItem.analysis_id);
    }
  }
}

async function runBatchAnalysis() {
  const urls = extractUrlsFromText(composerInput.value);
  if (!urls.length) {
    batchStatus.textContent = "Enter at least one URL or prompt containing URLs.";
    return;
  }
  batchStatus.textContent = `Running fast batch analysis for ${urls.length} URLs...`;
  batchResults.classList.add("hidden-block");
  const data = await fetchJson("/api/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls, text: composerInput.value }),
  });
  renderBatchResults(data.items || []);
  const pendingCount = (data.items || []).filter((item) => (item.enrichment?.status || "complete") === "pending").length;
  const processedCount = data.count || 0;
  const skippedCount = data.skipped_count || 0;
  const detectedCount = data.detected_count || urls.length;
  const capNote = skippedCount
    ? ` ${skippedCount} of ${detectedCount} detected URL(s) were skipped because the current batch cap is ${data.max_urls || processedCount}.`
    : "";
  batchStatus.textContent = pendingCount
    ? `Fast batch pass completed for ${processedCount} URLs. ${pendingCount} deep enrichment job(s) queued.${capNote}`
    : `Completed ${processedCount} batch analyses.${capNote} Select any detected URL tab to inspect that specific output.`;
  await loadHistory();
}

async function saveNote() {
  if (!currentAnalysisId) {
    statusBox.textContent = "Run an analysis first.";
    return;
  }
  const note = noteInput.value.trim();
  if (!note) {
    statusBox.textContent = "Enter a note.";
    return;
  }
  const data = await fetchJson(`/api/analysis/${currentAnalysisId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note }),
  });
  noteInput.value = "";
  renderNotes(data.items || []);
  statusBox.textContent = "Note saved.";
}

async function submitFeedback(helpful) {
  if (!currentAnalysisId) {
    feedbackStatus.textContent = "Run an analysis first.";
    return;
  }
  const data = await fetchJson(`/api/analysis/${currentAnalysisId}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      helpful,
      corrected_label: feedbackLabelInput?.value || "",
      note: feedbackNoteInput?.value || "",
    }),
  });
  feedbackStatus.textContent = helpful ? "Marked as helpful." : "Marked for review.";
  renderCommunityFeedbackBox({ community_feedback: data });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (composerMode === "batch") {
      await runBatchAnalysis();
      return;
    }
    const url = composerInput.value.trim();
    if (!url) {
      statusBox.textContent = "Enter a URL.";
      return;
    }
    await analyze(url);
  } catch (error) {
    statusBox.textContent = error.message;
  }
});

saveNoteButton.addEventListener("click", async () => {
  try {
    await saveNote();
  } catch (error) {
    statusBox.textContent = error.message;
  }
});

feedbackCorrectButton?.addEventListener("click", async () => {
  try {
    await submitFeedback(true);
  } catch (error) {
    feedbackStatus.textContent = error.message;
  }
});

feedbackIncorrectButton?.addEventListener("click", async () => {
  try {
    await submitFeedback(false);
  } catch (error) {
    feedbackStatus.textContent = error.message;
  }
});

modeSingleButton?.addEventListener("click", () => setComposerMode("single"));
modeBatchButton?.addEventListener("click", () => setComposerMode("batch"));
composerInput?.addEventListener("input", renderDetectedUrls);

if (refreshHistory) {
  refreshHistory.addEventListener("click", async () => {
    try {
      await loadHistory();
    } catch (error) {
      statusBox.textContent = error.message;
    }
  });
}

(async () => {
  try {
    await loadAuthStatus();
    startGreetingClock();
    setComposerMode("single");
    if (historyBox) {
      await loadHistory();
    }
  } catch (error) {
    statusBox.textContent = error.message;
  }
})();
