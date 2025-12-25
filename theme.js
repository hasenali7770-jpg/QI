// theme.js ✅ Global Theme + Animation
(function () {
  const KEY = "kb_theme";

  function apply(mode) {
    document.body.classList.remove("light", "dark");
    document.body.classList.add(mode);

    // ✨ small flash animation
    document.body.classList.add("theme-flash");
    setTimeout(() => document.body.classList.remove("theme-flash"), 220);
  }

  const saved = localStorage.getItem(KEY) || "light";
  apply(saved);

  window.KB_THEME = {
    get() {
      return localStorage.getItem(KEY) || "light";
    },
    set(mode) {
      localStorage.setItem(KEY, mode);
      apply(mode);
      window.dispatchEvent(new CustomEvent("kb-theme-changed", { detail: mode }));
    },
    toggle() {
      const next = this.get() === "dark" ? "light" : "dark";
      this.set(next);
    }
  };
})();
