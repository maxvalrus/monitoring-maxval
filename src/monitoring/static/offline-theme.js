try {
  const theme = localStorage.getItem("monitoring-theme");
  document.documentElement.dataset.theme = ["light", "dark", "auto"].includes(theme) ? theme : "auto";
  const dark = document.documentElement.dataset.theme === "dark"
    || (document.documentElement.dataset.theme === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.querySelector('meta[name="theme-color"]').content = dark ? "#10151b" : "#f4f6f8";
} catch (_) {}
