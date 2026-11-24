// NTOD — report tabs/drill-down, local timestamps,
// table filtering, drag-and-drop PCAP upload, secret reveal, copy-to-clipboard,
// and keyboard shortcuts. Zero inline handlers (strict CSP-safe).
// Dark-only: data-view is pinned to "night" in boot.js / layout.rs.
(function () {
  var ROUTE_KEYS = { "1": "/scan", "2": "/sniff", "3": "/wifi", "4": "/analyze", "5": "/tools", "6": "/devices" };

  // ---------- Local timezone formatting for <time data-ts> ----------
  function formatTimes(root) {
    if (!root || !root.querySelectorAll) return;
    root.querySelectorAll("time[data-ts]").forEach(function (el) {
      var ts = Number(el.getAttribute("data-ts"));
      if (!Number.isFinite(ts) || ts <= 0) return;
      var d = new Date(ts);
      el.textContent = d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      el.setAttribute("title", d.toLocaleString());
    });
  }

  // ---------- Report tabs + finding drill-down ----------
  function reportRoot(el) {
    return el && el.closest ? el.closest("#report-workspace") : null;
  }

  function clearFindingFilter(root) {
    if (!root) return;
    root.querySelectorAll("[data-rtab] tbody tr").forEach(function (tr) {
      tr.hidden = false;
    });
    root.querySelectorAll(".finding.active").forEach(function (c) {
      c.classList.remove("active");
    });
    var bar = root.querySelector("#report-filter-bar");
    if (bar) bar.hidden = true;
    root.querySelectorAll("[data-rtab]").forEach(function (panel) {
      var tab = panel.getAttribute("data-rtab");
      var empty = panel.querySelector("#empty-" + tab);
      var hasRows = panel.querySelectorAll("tbody tr").length > 0;
      if (empty) {
        empty.hidden = hasRows;
        if (!hasRows) empty.textContent = "No " + tab + " in this capture.";
      }
    });
  }

  function showTab(root, tab) {
    root.querySelectorAll('input[name="rtab"]').forEach(function (inp) {
      inp.checked = inp.value === tab;
    });
    root.querySelectorAll("[data-rtab]").forEach(function (p) {
      p.hidden = p.getAttribute("data-rtab") !== tab;
    });
  }

  function activateFinding(card) {
    var root = reportRoot(card);
    if (!root) return;
    var tab = card.getAttribute("data-tab") || "conversations";
    var title = card.getAttribute("data-ftitle") || "Finding";
    var evs = [];
    try { evs = JSON.parse(card.getAttribute("data-ev") || "[]"); } catch (_) {}
    root.querySelectorAll(".finding.active").forEach(function (c) {
      c.classList.remove("active");
    });
    card.classList.add("active");
    showTab(root, tab);
    var panel = root.querySelector('[data-rtab="' + tab + '"]');
    if (!panel) return;
    var vis = 0;
    panel.querySelectorAll("tbody tr").forEach(function (tr) {
      var t = tr.textContent || "";
      var show = !evs.length || evs.some(function (ev) { return ev && t.indexOf(ev) >= 0; });
      tr.hidden = !show;
      if (show) vis++;
    });
    var empty = panel.querySelector("#empty-" + tab);
    if (empty) {
      empty.hidden = vis > 0;
      if (!vis) empty.textContent = "No " + tab + " matching this finding.";
    }
    var bar = root.querySelector("#report-filter-bar");
    var lbl = root.querySelector("#report-filter-label");
    if (bar && lbl) {
      lbl.textContent = "Filtered " + tab + " by: " + title + " (" + vis + " match" + (vis === 1 ? "" : "es") + ")";
      bar.hidden = false;
    }
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ---------- Table search filter ----------
  function applyTableFilter(input) {
    var sel = input.getAttribute("data-table-filter");
    var scope = input.closest(".dt, .rtab-panel, #view-body") || document;
    var table = sel ? scope.querySelector(sel) : scope.querySelector("table");
    if (!table) return;
    var q = (input.value || "").trim().toLowerCase();
    var total = 0;
    var shown = 0;
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      total++;
      var ok = !q || (tr.textContent || "").toLowerCase().indexOf(q) >= 0;
      tr.hidden = !ok;
      if (ok) shown++;
    });
    var counter = scope.querySelector(".dt-count");
    if (counter) {
      counter.textContent = q ? shown + " / " + total : total + " row" + (total === 1 ? "" : "s");
    }
  }

  // ---------- Toast feedback for copy ----------
  var toastTimer = 0;
  function showToast(msg) {
    var t = document.getElementById("ntod-toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "ntod-toast";
      t.className = "ntod-toast";
      t.setAttribute("role", "status");
      t.setAttribute("aria-live", "polite");
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 1800);
  }

  // ---------- Delegated click handlers ----------
  document.addEventListener("click", function (e) {
    // Close open menus on outside click or menu-item click
    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      if (!m.contains(e.target) || (e.target.closest && e.target.closest(".menu-item"))) {
        m.removeAttribute("open");
      }
    });

    // Clear report filter
    var clearBtn = e.target.closest && e.target.closest("[data-clear-filter]");
    if (clearBtn) {
      clearFindingFilter(reportRoot(clearBtn));
      return;
    }

    // Drillable finding card
    var card = e.target.closest && e.target.closest("[data-fidx]");
    if (card) {
      activateFinding(card);
      return;
    }

    // Cleartext credential reveal/mask toggle
    var secBtn = e.target.closest && e.target.closest(".secret-toggle");
    if (secBtn) {
      var wrap = secBtn.closest(".secret-cell");
      var val = wrap && wrap.querySelector(".secret-val");
      if (val) {
        var revealed = val.getAttribute("data-revealed") === "true";
        val.textContent = revealed ? "••••••••" : (val.getAttribute("data-secret") || "");
        val.setAttribute("data-revealed", revealed ? "false" : "true");
        secBtn.textContent = revealed ? "Reveal" : "Hide";
        secBtn.setAttribute("aria-expanded", revealed ? "false" : "true");
      }
      return;
    }

    // Click-to-copy cells
    var copyEl = e.target.closest && e.target.closest("[data-copy]");
    if (copyEl && navigator.clipboard) {
      var text = copyEl.getAttribute("data-copy");
      if (text) {
        navigator.clipboard.writeText(text).then(function () {
          showToast("Copied " + text);
        }).catch(function () {});
      }
      return;
    }

    // Sniff toggle fallback — the real handler lives in the Svelte island;
    // if its bundle is missing the button must still fail honestly.
    var snf = e.target.closest && e.target.closest("[data-sniff-toggle]");
    if (snf && !window.ntodSniff) {
      var st = document.getElementById("status");
      if (st) {
        st.textContent = "Sniff UI bundle missing — run `npm run build` in apps/islands, then reload.";
        st.className = "pill err";
        st.hidden = false;
      }
      return;
    }

    // Dropzone click opens file picker
    var dz = e.target.closest && e.target.closest("#pcap-dropzone");
    if (dz) {
      var inp = document.getElementById("pcap-file");
      if (inp) inp.click();
    }
  });

  // ---------- Change & Input delegation ----------
  document.addEventListener("change", function (e) {
    var r = e.target.closest && e.target.closest('input[name="rtab"]');
    if (r) {
      var root = reportRoot(r);
      if (root) {
        clearFindingFilter(root);
        showTab(root, r.value);
      }
      return;
    }
    // Sync Tools primary submit button label with selected engine
    var eng = e.target.closest && e.target.closest("#tool-engine");
    if (eng) {
      var sub = document.getElementById("tool-submit-btn");
      if (sub) {
        var opt = eng.options[eng.selectedIndex];
        sub.textContent = "Run " + (opt ? opt.text : eng.value);
      }
    }
  });

  document.addEventListener("input", function (e) {
    var f = e.target.closest && e.target.closest("[data-table-filter]");
    if (f) applyTableFilter(f);
  });

  // ---------- Drag-and-drop PCAP upload ----------
  document.addEventListener("dragover", function (e) {
    var dz = e.target.closest && e.target.closest("#pcap-dropzone");
    if (!dz) return;
    e.preventDefault();
    dz.classList.add("drag-over");
  });
  document.addEventListener("dragleave", function (e) {
    var dz = e.target.closest && e.target.closest("#pcap-dropzone");
    if (!dz) return;
    dz.classList.remove("drag-over");
  });
  document.addEventListener("drop", function (e) {
    var dz = e.target.closest && e.target.closest("#pcap-dropzone");
    if (!dz) return;
    e.preventDefault();
    dz.classList.remove("drag-over");
    var files = e.dataTransfer && e.dataTransfer.files;
    var inp = document.getElementById("pcap-file");
    if (inp && files && files.length) {
      try {
        var dt = new DataTransfer();
        dt.items.add(files[0]);
        inp.files = dt.files;
        inp.dispatchEvent(new Event("change", { bubbles: true }));
      } catch (_) {}
    }
  });

  // ---------- Keyboard accessibility + power-user shortcuts ----------
  document.addEventListener("keydown", function (e) {
    // Enter/Space on interactive finding cards or dropzone
    if (e.key === "Enter" || e.key === " ") {
      var card = e.target.closest && e.target.closest("[data-fidx]");
      if (card) {
        e.preventDefault();
        activateFinding(card);
        return;
      }
      var dz = e.target.closest && e.target.closest("#pcap-dropzone");
      if (dz) {
        e.preventDefault();
        var inp = document.getElementById("pcap-file");
        if (inp) inp.click();
        return;
      }
    }

    if (e.key === "Escape") {
      document.querySelectorAll("details.menu[open]").forEach(function (m) {
        m.removeAttribute("open");
      });
      var root = document.getElementById("report-workspace");
      if (root) clearFindingFilter(root);
      return;
    }

    // Skip shortcuts while typing in inputs/selects/textareas or with modifiers
    var tag = e.target && e.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || e.metaKey || e.ctrlKey || e.altKey) {
      return;
    }

    if (e.key === "/") {
      var search = document.querySelector("[data-table-filter]:not([hidden])");
      if (search) {
        e.preventDefault();
        search.focus();
      }
      return;
    }

    if (ROUTE_KEYS[e.key]) {
      var link = document.querySelector('.nav a[href="' + ROUTE_KEYS[e.key] + '"]');
      if (link) {
        e.preventDefault();
        link.click();
      }
    }
  });

  // ---------- Lifecycle hooks ----------
  function init(root) {
    formatTimes(root || document);
  }

  document.addEventListener("DOMContentLoaded", function () { init(document); });
  document.addEventListener("htmx:afterSwap", function (e) {
    init(e.detail && e.detail.target ? e.detail.target : document);
  });
  document.addEventListener("htmx:oobAfterSwap", function (e) {
    formatTimes(e.detail && e.detail.target ? e.detail.target : document);
  });
})();
