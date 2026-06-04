async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

const loginStatus = document.getElementById("login-page-status");
const signinPanel = document.getElementById("signin-panel");
const registerPanel = document.getElementById("register-panel");
const signinTab = document.getElementById("show-signin");
const registerTab = document.getElementById("show-register");
const googleClientId = document.body.dataset.googleClientId || "";

function switchMode(mode) {
  const signin = mode === "signin";
  signinPanel.classList.toggle("hidden-block", !signin);
  registerPanel.classList.toggle("hidden-block", signin);
  signinTab.classList.toggle("active", signin);
  registerTab.classList.toggle("active", !signin);
  loginStatus.textContent = "";
}

document.getElementById("login-button-page").addEventListener("click", async () => {
  try {
    await fetchJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("login-username-page").value.trim(),
        password: document.getElementById("login-password-page").value,
      }),
    });
    window.location.href = "/dashboard";
  } catch (error) {
    loginStatus.textContent = error.message;
  }
});

document.getElementById("register-button-page").addEventListener("click", async () => {
  try {
    await fetchJson("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: document.getElementById("register-first-name-page").value.trim(),
        last_name: document.getElementById("register-last-name-page").value.trim(),
        mobile: document.getElementById("register-mobile-page").value.trim(),
        username: document.getElementById("register-username-page").value.trim(),
        password: document.getElementById("register-password-page").value,
      }),
    });
    window.location.href = "/dashboard";
  } catch (error) {
    loginStatus.textContent = error.message;
  }
});

signinTab.addEventListener("click", () => switchMode("signin"));
registerTab.addEventListener("click", () => switchMode("register"));

if (googleClientId) {
  window.addEventListener("load", () => {
    const slot = document.getElementById("google-login-page");
    if (!slot || !window.google?.accounts?.id) return;
    window.google.accounts.id.initialize({
      client_id: googleClientId,
      callback: async (response) => {
        try {
          await fetchJson("/api/auth/google", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ credential: response.credential }),
          });
          window.location.href = "/dashboard";
        } catch (error) {
          loginStatus.textContent = error.message;
        }
      },
    });
    window.google.accounts.id.renderButton(slot, { theme: "filled_black", size: "large", text: "signin_with" });
  });
}
