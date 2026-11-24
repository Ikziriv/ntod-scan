# ntod-scan — Architecture

System architecture for the ntod-scan workspace: crate topology, runtime
models, data flows, concurrency, resource bounds, and the security model.
Component-level detail lives in [SDD.md](SDD.md); API and wire-level specs
in [TSD.md](TSD.md).

## 1. Design principles

| Principle | Enforcement |
|---|---|
| Local-first | No telemetry, accounts, or required upstream calls; optional seams degrade to warnings |
| Bounded everything | Hard caps on feeds, workers, timeouts, body sizes, stores, report lists |
| `Result`, not panic | Expected failures return typed errors; nothing panics on network-controlled input |
| One engine, many shells | Libraries (`core`, `capture`, `analysis`, `tools`) carry all logic; `cli` and `api` are thin |
| Untrusted wire data | Frames, pcap bytes, WS messages, SSIDs/hostnames are attacker-influenced and treated as such |

## 2. Crate topology

```
                ┌──────────┐
                │ ntod-cli │   the `ntod` binary (clap, tokio)
                └────┬─────┘
                     │
                ┌────▼─────┐         ┌──────────┐  (optional)
                │ ntod-api │────────►│ ntod-ai  │  Ollama seam
                └────┬─────┘         ├──────────┤  HTTP proxy
                     │               │ ntod-proxy│
        ┌────────────┼──────────┐    ├──────────┤  external tools
        │            │          │    │ ntod-tools│ (nmap/masscan/
   ┌────▼────┐  ┌────▼─────┐  ┌─▼───▼──────┐   │  tcpdump/airodump)
   │ntod-core│◄─┤ntod-     │◄─┤ntod-       │   ├──────────┤  ARP control
   │scan,    │  │capture   │  │analysis    │   │ntod-     │
   │discover,│  │pcapr/w   │  │triage +    │   │control   │
   │wifi, arp│  │backends  │  │detectors   │   └──────────┘
   └─────────┘  └──────────┘  └────────────┘
```

Dependency direction is strictly **shells → seam → engines**. `ntod-core`
has no dependency on any other workspace crate; `ntod-analysis` depends on
`ntod-capture` and `ntod-core`; `ntod-api` composes everything and adds no
engine logic.

| Crate | Role | Hard boundary |
|---|---|---|
| `ntod-core` | Scanning engine: subnet scan, enrich (hostname/OUI/ports), wifi, arp | Pure library; no UI, no HTTP |
| `ntod-capture` | Frame acquisition + pcap I/O: `pcapdev`/`rcvall` backends, `pcapr`, `pcapw`, `decode` | No analysis |
| `ntod-analysis` | Triage engine: flows, L7 dissectors, detectors, history | One report model for files and live |
| `ntod-api` | axum seam: `/api/*`, `/ws`, maud pages, `/partials/*`, `/sse/*` | No engine logic; thin glue + bounded stores |
| `ntod-cli` | `ntod` binary | Arg parse → library call → print |
| `ntod-tools` | argv adapters for nmap/masscan/tcpdump/airodump over local/WSL/SSH | argv only, no shell; deadline kill; capped output |
| `ntod-ai` | Ollama-backed filter/summarize | Optional; absent = routes not mounted |
| `ntod-proxy` | Explicit HTTP/CONNECT proxy | Optional seam |
| `ntod-control` | ARP cut/throttle | Feature-gated `live`; needs pnet/Npcap |

## 3. Runtime models

### 3.1 One-shot CLI

```
argv → clap → library call → stdout table / JSON
```

`scan`, `sniff`, `wifi`, `analyze`, `proxy`, `cut`, `throttle`, `tool *`
all run to completion (or until Ctrl+C) in one process. `sniff` and `proxy`
use a bounded channel + worker thread for frame/event printing.

### 3.2 Daemon (`ntod serve`)

```
axum::serve(127.0.0.1:port, ntod_api::router(web_root))
├─ /api/*        REST JSON (scan, wifi, analyze upload, devices, alerts, export)
├─ /ws           command channel: scan / sniff / analyze / monitor / stop
├─ /, /scan…     maud SSR pages
├─ /partials/*   htmx fragments
├─ /sse/*        HTML event streams
└─ ServeDir      apps/web static fallback (css, js, fonts, vendor, islands)
```

Bound to loopback by default. In-memory stores are all bounded:
reports (newest 4), carved objects (newest 64), retained frames
(newest 2 uploads ≤ 32 MB each).

## 4. Data flows

### 4.1 LAN scan

```
ntod_core::scan(subnet, timeout, workers)
  → ping sweep (bounded worker pool, per-probe timeout)
  → Host{ip, mac?}
discover::enrich(&mut hosts)
  → reverse DNS · OUI vendor · top-port probes
  → Host{hostname?, vendor?, open_ports}
```

CLI prints TSV. The API runs the same pipeline in two phases over WS/SSE:
`found` events stream as probes land (fast phase), `host` events as
enrichment completes (slow phase) — the UI lights port-map cells per row.

### 4.2 Packet capture

```
ntod_capture::start(ip) → CaptureHandle + rx<RawFrame{ts_ms, linktype, data}>
  backends: pcap device (feature pcap-backend, needs Npcap)
            RcvAll raw socket (windows-sys, no SDK)
decode::decode_frame(linktype, data, ts) → Option<PacketEvent>
```

`stop()` on the handle drains and joins. Frames are never retained
unbounded — the feed is a channel with a fixed cap.

### 4.3 Capture triage (the flagship path)

```
bytes (.pcap/.pcapng) → pcapr::for_each → Analyzer::feed(ts, linktype, data)
  per frame:
    flow.rs      bidirectional flow key + byte/packet counters
    l7/dns.rs    queries, answers, suspected tunnel signals
    l7/http.rs   requests, responses, object carving (head-budgeted)
    l7/tls.rs    ClientHello parse → JA3, SNI; cert hygiene via x509.rs
    l7/dhcp.rs   leases, fingerprints
    l7/creds.rs  credential extraction (basic auth, form posts, …)
    l7/magic.rs  file-magic sniffing for carved objects
  finish() → detect.rs
    port_scans · dns_tunnels · arp_spoof · beacon · TLS cert hygiene
  → Report{meta, hosts, conversations, dns, http, tls, dhcp,
           credentials, findings, objects}
```

`analyze()` is the file path; `analyze_live()` runs the same engine on a
timed capture. `analyze_retain()` additionally keeps raw frames (bounded)
so `/api/capture/{id}/pcap` can re-export filtered subsets; the report
flags `export_partial` when the retain budget ran out.

**One model, three inputs:** uploaded file, live capture, remote capture
over `ntod-tools` (`tcpdump -w -` stream) all produce the same `Report`.

### 4.4 History & device baseline

`history` is a bounded JSON store at `$NTOD_DATA_DIR` or `~/.ntod-scan`.
Only *live* captures update it (`history_observe` in the API layer,
serialized under a mutex) — uploads never touch local history.
`/api/devices` and `/api/alerts` read it: new-device and anomaly events
arrive as `finding` messages on `/ws`.

### 4.5 External tools

```
ntod_tools::Backend::from_spec("local" | "wsl[:distro]" | "ssh:[user@]host")
  → bounded subprocess runner:
      argv only (no shell interpolation)
      deadline kill
      capped stdout/stderr
  adapters: nmap -oX (quick-xml), masscan -oL,
            tcpdump -w - (pcap stream → ntod-analysis),
            airodump-ng CSV (fetched via fixed sh -c script)
```

## 5. Concurrency model

- **Scan**: bounded worker pool (`--workers`, default 64); each probe owns
  its timeout. No shared mutable state until enrichment merge.
- **Capture**: one producer thread → bounded mpsc → consumer. Stop is a
  flag + drain; no unbounded buffering on stall.
- **API**: axum on tokio; CPU-bound parsing runs via `spawn_blocking`.
  Shared stores are `OnceLock<Mutex<BTreeMap>>` with eviction policies;
  history writes serialize under a single mutex.
- **WS**: one active command per connection; `stop` cancels via a
  cancellation token shared with the worker.
- **HashDoS defense**: engine maps use `foldhash::quality::RandomState`
  (seeded per map) so a hostile capture can't precompute colliding keys.

## 6. Resource bounds (selected)

| Resource | Cap | Where |
|---|---|---|
| Analyze upload body | 64 MiB | `MAX_UPLOAD` |
| Report lists | dns/http/tls ≤ 4 000 each; dhcp ≤ 1 000; hosts ≤ 100 000 | `report::Limits` |
| Top-N surfaces | hosts 500, conversations 1 000 | `report::Limits` |
| Head-buffer budget (carving) | 64 MiB global | `report::Limits` |
| Retained frames for export | ≤ 32 MiB/upload, newest 2 uploads | API capture store |
| Retained reports | newest 4 | API report store |
| Carved objects | newest 64 | API object store |
| Web packet feed | 300 rows | `apps/web` (display) |
| Tool subprocess | deadline kill + capped output | `tools/runner.rs` |
| Remote sniff duration | 1–3 600 s | CLI clamp |

## 7. Web UI architecture

Server-rendered, no hydration framework:

- **Pages**: maud (`crates/api/src/web/pages.rs`) at `/scan`, `/sniff`,
  `/wifi`, `/analyze`, `/tools`, `/devices` — layout + components shared
  via `layout.rs`/`components.rs`.
- **Interactivity**: htmx (`/partials/*`), SSE (`/sse/*`) for streams,
  `/ws` for the command channel. `ntod.js` holds the theme menu, report
  tabs, and drill-in JS.
- **Islands**: exactly one Svelte component (packet-rate chart in Sniff),
  built by `apps/islands` vite build into `apps/web/islands/` (gitignored).
- **Assets**: self-hosted woff2 fonts, vendored htmx — fully offline.
- **Design system**: `apps/web/app.css` is vendored verbatim from
  ntok-scan and never edited here; ntod deltas live in `ntod.css`.
  Authority: `DESIGN.md` (shared). Three views (`paper`, `night`,
  `terminal`) via `<html data-view>`.
- **XSS posture**: all remote-provided strings are escaped before
  `innerHTML` (`esc()` in `ntod.js`); maud escapes by construction.

## 8. Error & failure model

- Library crates: `thiserror` enums per crate (`core::Error`,
  `capture::Error`, `analysis::Error`, `tools::Error`), converted at seams.
- App edge (`cli`): `anyhow`.
- API edge: errors map to `(StatusCode, String)` / maud error partials;
  WS errors are `{"type":"error","msg":…}` events — the socket stays up.
- Capture/analysis never panic on malformed input: decoders return
  `Option`/`Result`, dropped/unsupported frames are counted in
  `Meta::dropped`, not thrown.
- Optional seams are `#[cfg(feature)]`-gated at route mount — an absent
  feature is a 404, not a crash.

## 9. Security model

- **Trust boundary**: everything on the wire (frames, pcap, WS payloads,
  SSIDs, hostnames, tool output) is untrusted input.
- **Outbound posture**: zero required egress; `ntod-ai` only speaks to a
  configured Ollama endpoint; `ntod-tools` SSH uses the host's ssh agent.
- **Active features** (`cut`, `throttle`, `masscan`) are gated behind
  feature flags and warn on every invocation; documented for
  own-network use only.
- **Privilege**: `sniff`/capture needs admin/root by OS requirement, not
  by design choice; everything else runs unprivileged.
