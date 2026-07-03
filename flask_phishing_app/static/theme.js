const themeStorageKey = "phishscope-theme";

function applyTheme(theme) {
  const resolved = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = resolved;
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.textContent = resolved === "dark" ? "Light mode" : "Dark mode";
    button.setAttribute("aria-pressed", resolved === "dark" ? "true" : "false");
  });
}

function loadPreferredTheme() {
  const saved = window.localStorage.getItem(themeStorageKey);
  if (saved === "dark" || saved === "light") {
    return saved;
  }
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  window.localStorage.setItem(themeStorageKey, next);
  applyTheme(next);
}

applyTheme(loadPreferredTheme());

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", toggleTheme);
  });
});
