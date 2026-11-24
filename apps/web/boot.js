// Zero-flash theme boot — runs synchronously before first paint (CSP-safe).
// NTOD is dark-only: always Obsidian night, whatever localStorage holds.
(function () {
  try {
    document.documentElement.dataset.view = "night";
    var m = document.getElementById("meta-theme");
    if (m) m.setAttribute("content", "#05080F");
  } catch (e) {}
})();
