<script>
  // Sniff island — the one place client state earns its keep. Packets
  // can arrive at hundreds/sec: they buffer into `pending` and flush
  // into the capped row list on requestAnimationFrame, while the wave
  // redraws on a 1s tick. Everything else (status pills) is written
  // straight to the shell DOM the same way server fragments do.
  import { onMount, onDestroy } from "svelte";

  const COLS = ["Time", "Proto", "Source", "Destination", "Bytes"];
  const MAX_ROWS = 300;
  const BUCKETS = 48;

  let rows = $state([]); // newest first
  let filterText = $state("");
  let waveSig = $state("");
  let waveFill = $state("");
  let wavePeak = $state(0);
  let waveTotal = $state(0);
  let protoSummary = $state("—");
  let capturing = $state(false);
  let stopping = $state(false); // sent "stop", awaiting server's "stopped"
  let started = $state(false); // island visible once a capture ran
  let emptyMsg = $state("Nothing yet — start a capture.");
  let emptySub = $state("");
  let showEmpty = $state(true);
  let elapsedTxt = $state("0s");
  let byteTxt = $state("0 B");

  let ring = new Array(BUCKETS).fill(0);
  let protoCount = {};
  let pending = [];
  let ws = null;
  let tickTimer = null;
  let raf = 0;
  let pendingTotal = $state(0);
  let byteTotal = 0;
  let t0 = 0;
  let stopTimer = 0;

  let filteredRows = $derived.by(() => {
    const q = filterText.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (p) =>
        p.proto.toLowerCase().includes(q) ||
        p.src.toLowerCase().includes(q) ||
        p.dst.toLowerCase().includes(q)
    );
  });

  function protoName(pr) {
    if (typeof pr === "string") return pr.toUpperCase();
    if (pr && typeof pr === "object" && pr.Other != null) return "PROTO-" + pr.Other;
    return "?";
  }

  // Same pill contract as the maud fragments: #status + #sys/#sys-state.
  function status(msg, kind) {
    var el = document.getElementById("status");
    if (!el) return;
    el.textContent = msg;
    el.className = "pill" + (kind ? " " + kind : "");
    el.hidden = !msg;
  }
  function setSys(live, label) {
    var sys = document.getElementById("sys");
    var st = document.getElementById("sys-state");
    if (sys) sys.className = live ? "sys-pill live" : "sys-pill";
    if (st) st.textContent = label;
  }

  function splinePath(pts) {
    if (pts.length < 2) return "";
    var d = "M" + pts[0][0].toFixed(1) + " " + pts[0][1].toFixed(1);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[Math.max(0, i - 1)];
      var p1 = pts[i];
      var p2 = pts[i + 1];
      var p3 = pts[Math.min(pts.length - 1, i + 2)];
      var c1x = p1[0] + (p2[0] - p0[0]) / 6,
        c1y = p1[1] + (p2[1] - p0[1]) / 6;
      var c2x = p2[0] - (p3[0] - p1[0]) / 6,
        c2y = p2[1] - (p3[1] - p1[1]) / 6;
      d +=
        "C" + c1x.toFixed(1) + " " + c1y.toFixed(1) + " " +
        c2x.toFixed(1) + " " + c2y.toFixed(1) + " " +
        p2[0].toFixed(1) + " " + p2[1].toFixed(1);
    }
    return d;
  }

  function drawWave() {
    var peak = Math.max.apply(null, ring.concat([4]));
    var pts = ring.map(function (v, i) {
      return [i * (480 / (BUCKETS - 1)), 64 - (v / peak) * 58];
    });
    var d = splinePath(pts);
    waveSig = d;
    waveFill = d + " L480 68 L0 68 Z";
    wavePeak = Math.max.apply(null, ring);
    var parts = Object.keys(protoCount)
      .sort(function (a, b) { return protoCount[b] - protoCount[a]; })
      .map(function (k) { return k.toLowerCase() + " " + protoCount[k]; });
    protoSummary = parts.join(" · ") || "—";
  }

  function total() {
    return waveTotal + pendingTotal;
  }

  function flush() {
    if (pending.length) {
      rows = pending.concat(rows).slice(0, MAX_ROWS);
      waveTotal += pendingTotal;
      pending = [];
      pendingTotal = 0;
    }
    raf = requestAnimationFrame(flush);
  }

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }
  function fmtElapsed(ms) {
    var s = Math.floor(ms / 1000);
    var m = Math.floor(s / 60);
    return m ? m + ":" + String(s % 60).padStart(2, "0") : s + "s";
  }

  function tick() {
    ring.shift();
    ring.push(0);
    drawWave();
    if (capturing && t0) {
      elapsedTxt = fmtElapsed(Date.now() - t0);
      byteTxt = fmtBytes(byteTotal);
    }
  }

  function btn() {
    return document.getElementById("go");
  }
  function setBtn() {
    var b = btn();
    if (!b) return;
    if (stopping) {
      b.textContent = "Stopping…";
      b.className = "btn danger";
      b.disabled = true;
    } else {
      b.textContent = capturing ? "Stop" : "Capture";
      b.className = capturing ? "btn danger" : "btn";
      b.disabled = false;
    }
    b.setAttribute("aria-pressed", capturing ? "true" : "false");
  }

  // Capture-source inputs live in the page (maud), outside the island —
  // read them at start; lock them while a capture runs.
  function fieldVal(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : "";
  }
  function setCtlDisabled(d) {
    ["sniff-backend", "sniff-iface", "sniff-bpf"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.disabled = d;
    });
  }

  function start() {
    if (capturing || stopping) return;
    // New session: reset stats + table, hide last capture's export link.
    capturing = true;
    started = true;
    showEmpty = false;
    rows = [];
    ring.fill(0);
    protoCount = {};
    waveTotal = 0;
    pendingTotal = 0;
    byteTotal = 0;
    t0 = Date.now();
    elapsedTxt = "0s";
    byteTxt = "0 B";
    protoSummary = "—";
    emptySub = "";
    var d = document.getElementById("dl");
    if (d) d.hidden = true;
    setBtn();
    setCtlDisabled(true);

    // Blank backend = built-in raw socket (needs Administrator); a
    // wsl:/ssh: spec streams tcpdump from that host instead.
    var via = fieldVal("sniff-backend");
    var cmd = { action: "sniff", batch: true };
    if (via) {
      cmd.via = via;
      var iface = fieldVal("sniff-iface");
      var bpf = fieldVal("sniff-bpf");
      if (iface) cmd.iface = iface;
      if (bpf) cmd.bpf = bpf;
    }
    status(
      via ? "Capturing via " + via + "…" : "Capturing — the daemon must run as Administrator…",
      "running"
    );
    setSys(true, "Running");
    if (!tickTimer) tickTimer = setInterval(tick, 1000);

    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var s;
    try {
      s = new WebSocket(proto + "//" + location.host + "/ws");
    } catch (e) {
      fail(e.message);
      return;
    }
    ws = s;
    s.onopen = function () {
      s.send(JSON.stringify(cmd));
    };
    s.onmessage = function (ev) {
      var m;
      try { m = JSON.parse(ev.data); } catch (_) { return; }
      if (m.type === "packet" || m.type === "packets") {
        var list = m.type === "packets" ? m.packets : [m.packet];
        for (var i = 0; i < list.length; i++) {
          var p = list[i];
          ring[BUCKETS - 1]++;
          pendingTotal++;
          byteTotal += p.len;
          var pn = protoName(p.proto);
          protoCount[pn] = (protoCount[pn] || 0) + 1;
          pending.push({
            ts: new Date(p.ts).toLocaleTimeString([], { hour12: false }),
            proto: pn,
            src: p.src + (p.sport ? ":" + p.sport : ""),
            dst: p.dst + (p.dport ? ":" + p.dport : ""),
            len: p.len,
          });
        }
        status(total() + " packet" + (total() === 1 ? "" : "s"), "running");
      } else if (m.type === "stopped") {
        finishStop(m);
      } else if (m.type === "error") {
        fail(m.msg, m.hint);
      }
    };
    s.onclose = function () {
      ws = null;
      if (stopping) {
        finishStop(null); // socket went before `stopped` — finalize locally
      } else if (capturing) {
        fail("Connection to the daemon lost");
      }
    };
    s.onerror = function () {
      // onclose follows and does the cleanup
    };
  }

  // Client asks, server cancels + retains + answers `stopped` with the
  // export id — the socket stays open until then or the 3s fallback.
  function stop() {
    if (!capturing || stopping) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      finishStop(null);
      return;
    }
    stopping = true;
    setBtn();
    status("Stopping…", "running");
    ws.send(JSON.stringify({ action: "stop" }));
    stopTimer = setTimeout(function () { finishStop(null); }, 3000);
  }

  function finishStop(m) {
    clearTimeout(stopTimer);
    stopping = false;
    capturing = false;
    setCtlDisabled(false);
    var n = m && typeof m.packets === "number" ? m.packets : total();
    if (m && m.capture_id != null) {
      var d = document.getElementById("dl");
      if (d) {
        d.href = "/api/capture/" + m.capture_id + "/pcap";
        d.title = m.partial ? "Export truncated at 32 MB" : "";
        d.hidden = false;
      }
    }
    if (ws) ws.close();
    ws = null;
    setSys(false, "Ready");
    setBtn();
    status(
      n ? n + " packet" + (n === 1 ? "" : "s") + " — saved" : "Stopped — nothing captured",
      "done"
    );
  }

  function fail(msg, hint) {
    clearTimeout(stopTimer);
    capturing = false;
    stopping = false;
    setCtlDisabled(false);
    status(msg, "err");
    var el = document.getElementById("status");
    if (el) el.title = hint || "";
    setSys(false, "Ready");
    setBtn();
    if (ws) ws.close();
    ws = null;
    if (!rows.length) {
      showEmpty = true;
      emptyMsg = msg || "Capture failed — check the daemon and retry.";
      emptySub = hint || "";
    }
  }

  function onToggleClick(e) {
    if (e.target && e.target.closest && e.target.closest("[data-sniff-toggle]")) {
      capturing ? stop() : start();
    }
  }

  onMount(function () {
    window.ntodSniff = { toggle: function () { capturing ? stop() : start(); }, start: start, stop: stop };
    document.addEventListener("click", onToggleClick);
    setBtn();
    raf = requestAnimationFrame(flush);
  });

  onDestroy(function () {
    document.removeEventListener("click", onToggleClick);
    if (tickTimer) clearInterval(tickTimer);
    clearTimeout(stopTimer);
    cancelAnimationFrame(raf);
    if (ws) ws.close();
    if (window.ntodSniff && window.ntodSniff.start === start) delete window.ntodSniff;
  });
</script>

<div class="telemetry-island" id="island-sniff" hidden={!started}>
  <div class="sec-head">
    <h2 class="sec-title">Packet rate</h2>
    <span class="legend"><span id="wave-proto">{protoSummary}</span></span>
  </div>
  <svg
    class="wave"
    id="wave"
    viewBox="0 0 480 68"
    preserveAspectRatio="none"
    role="img"
    aria-label="Packets per second"
  >
    <path class="base" d="M0 34 H480" />
    <path class="fill" id="wave-fill" d={waveFill} />
    <path class="sig" id="wave-sig" d={waveSig} />
  </svg>
  <div class="wave-meta">
    <span>48s window</span>
    <span><span class="peak" id="wave-peak">{wavePeak}</span> pkt/s peak</span>
    <span id="wave-total">{waveTotal + pendingTotal} total</span>
    <span>{elapsedTxt}</span>
    <span>{byteTxt}</span>
  </div>
</div>

<div class="dt">
  {#if rows.length > 0}
    <div class="dt-tools">
      <div class="field-in dt-search-wrap">
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
        </svg>
        <input
          class="txt"
          type="search"
          aria-label="Filter packets"
          placeholder="Filter proto, IP, port…"
          bind:value={filterText}
        />
      </div>
      <span class="dt-count">{filteredRows.length} / {rows.length} (cap {MAX_ROWS})</span>
    </div>
  {/if}
  <div class="panel flush" id="table-panel">
    <table>
      <thead id="cols">
        <tr>{#each COLS as c}<th>{c}</th>{/each}</tr>
      </thead>
      <tbody id="rows">
        {#each filteredRows as p (p)}
          <tr class="flash">
            <td>{p.ts}</td>
            <td><span class={"proto-badge p-" + p.proto.toLowerCase()}>{p.proto}</span></td>
            <td data-copy={p.src}>{p.src}</td>
            <td data-copy={p.dst}>{p.dst}</td>
            <td class="num">{p.len}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <div class="empty" id="empty" hidden={!showEmpty}>
      <span class="empty-ic" aria-hidden="true">
        <svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 12h4l2.5-6.5 4.5 13L16.5 12H21" />
        </svg>
      </span>
      <span class="empty-title">{emptyMsg}</span>
      {#if emptySub}<span class="empty-sub">{emptySub}</span>{/if}
    </div>
  </div>
</div>
