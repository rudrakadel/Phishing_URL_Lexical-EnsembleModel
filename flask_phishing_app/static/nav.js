(async () => {
  const nav = document.getElementById("primary-nav");
  if (!nav) return;

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      throw new Error("Unexpected auth response");
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  function setLoginLink() {
    document.querySelector(".brandmark")?.setAttribute("href", "/login");
    nav.querySelector('[data-auth-link="account"]')?.remove();
    if (!nav.querySelector('[data-auth-link="login"]')) {
      nav.insertAdjacentHTML("beforeend", `<a href="/login" data-auth-link="login">Login</a>`);
    }
  }

  function setAccountLink(authState) {
    document.querySelector(".brandmark")?.setAttribute("href", "/dashboard");
    nav.querySelector('[data-auth-link="login"]')?.remove();
    nav.querySelector('[data-auth-link="account"]')?.remove();
    const label = escapeHtml(authState.first_name || authState.username || "Account");
    nav.insertAdjacentHTML(
      "beforeend",
      `<button id="nav-account-button" type="button" class="nav-account" data-auth-link="account">${label} - Logout</button>`
    );
    document.getElementById("nav-account-button")?.addEventListener("click", async () => {
      await fetchJson("/api/auth/logout", { method: "POST" });
      window.location.href = "/login";
    });
  }

  try {
    const authState = await fetchJson("/api/auth/status");
    if (authState.authenticated) {
      setAccountLink(authState);
    } else {
      setLoginLink();
    }
  } catch {
    setLoginLink();
  }
})();
