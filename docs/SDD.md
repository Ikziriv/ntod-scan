# ntod-scan — Software Design Document (SDD)

## 1. Introduction

### 1.1 Purpose

This document describes the component-level software design of ntod-scan:
module responsibilities, key types, state management, error handling, and
the reasoning behind each structural choice. System-level context is in
[ARCHITECTURE.md](ARCHITECTURE.md); wire-level specs in [TSD.md](TSD.md).

### 1.2 Scope

All crates in the workspace (`crates/*`), the `ntod` binary, and the web
shell assets under `apps/`. External tools are documented only to their
adapter boundary.

### 1.3 Definitions

| Term | Definition |
|---|---|
| Report | The serializable triage output of `ntod-analysis` |
| Flow | A bidirectional conversation keyed by normalized 5-tuple |
| Finding | A detector output (severity + title + detail) |
| Backend | A `ntod-tools` execution target: local, WSL, or SSH |
| Island | A client-rendered Svelte component embedded in an SSR page |
| Shell | A user-facing front end: CLI binary or HTTP daemon |

---

## 2. System architecture

### 2.1 Layers

```
Shells     ntod-cli (clap)          Web UI (maud + htmx + SSE + 1 island)
Seam       ntod-api (axum router, bounded stores, web module)
Engines    ntod-core  ntod-capture  ntod-analysis  ntod-tools
Optional   ntod-ai  ntod-proxy  ntod-control   (feature-gated)
```

### 2.2 Design patterns

| Pattern | Where | Why |
|---|---|---|
| Facade / thin seam | `ntod-api`, `ntod-cli` | Engines stay UI-agnostic and reusable |
| Strategy | capture backends (`pcapdev`, `rcvall`), tool backends (`local`/`wsl`/`ssh`) | Same operation, different transport — chosen at runtime |
| Iterator/visitor | `pcapr::for_each` → `Analyzer::feed` | Streaming parse, constant memory per frame |
| Registry (static) | L7 dissectors invoked per port/proto in `engine.rs` | One dissection pass, additive modules |
| Bounded store | `OnceLock<Mutex<BTreeMap<id, T>>>` + FIFO evict | Daemon retains N newest items; O(log n), no leaks |
| Feature gating | `#[cfg(feature)]` route mounts & CLI variants | Absent capability = absent surface, not runtime failure |

### 2.3 Technology stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Rust, edition 2024 | Single toolchain, memory safety |
| Async | tokio (rt-multi-thread) | API daemon, proxy, signals |
| HTTP/WS | axum 0.8 + tower-http | API, SSR pages, static fallback |
| SSR | maud 0.27 | Type-checked HTML, escaped by default |
| Client JS | htmx (vendored) + vanilla `ntod.js` | Partial swaps, SSE, WS |
| Island | Svelte 5 + vite (apps/islands) | Packet-rate chart only |
| CLI | clap 4 derive | Subcommand tree |
| Serialization | serde / serde_json, quick-xml | Reports, history, nmap -oX |
| Packet parse | etherparse 0.15 | L2–L4 header decode |
| Capture | pcap (optional), windows-sys RcvAll | Frame acquisition |
| Hashing | hashbrown + foldhash | HashDoS-resistant engine maps |
| Crypto-hash | md5, sha2 | JA3, object digests |
| Errors | thiserror (libs), anyhow (cli edge) | Typed failures, context at edge |

---

## 3. Component design

### 3.1 `ntod-core` — scanning engine

```
pub mod scan      local_subnet(), scan(), scan_stream()
pub mod discover  enrich(&mut [Host]) — rDNS, OUI, top-port probes
pub mod wifi      networks() -> Vec<WifiNetwork>
pub mod arp       ARP helpers (resolution, table)
pub mod oui       OUI → vendor lookup
pub mod model     Host, Proto, Filter
pub mod error     Error (thiserror)
```

**Key decisions**

- Pure library with no I/O framework deps beyond `ping`/`dns-lookup` —
  callable from CLI, axum handlers, and tests identically.
- `scan()` returns all live hosts; `scan_stream()` exposes the two-phase
  stream (reply → enrichment) the API needs for progressive UI.
- `Host` fields are `Option` — "not probed" and "probed, absent" are
  distinct states the UI renders differently.

### 3.2 `ntod-capture` — acquisition & pcap I/O

```
start(ip) -> CaptureHandle { take_rx() -> rx<RawFrame>, stop() }
decode::decode_frame(linktype, bytes, ts) -> Option<PacketEvent>
pcapr::for_each(bytes, |Packet|) — streaming .pcap/.pcapng reader
pcapw — classic-pcap writer for filtered exports
pcapdev (feature pcap-backend) / rcvall (windows-sys)
```

**Key decisions**

- Two acquisition backends behind one `start()` seam: pcap where the SDK
  exists, RcvAll raw sockets on Windows where it doesn't.
- `RawFrame` stays undecoded bytes — decode is a separate pure function so
  the same frames feed CLI printing, the analysis engine, and pcapw
  re-export.
- `decode_frame` returns `Option`, never `Result`: an undecodable frame is
  a normal event (counted as dropped), not a failure.

### 3.3 `ntod-analysis` — triage engine

```
lib.rs       analyze(), analyze_retain(), analyze_live(), FastMap/FastSet
engine.rs    Analyzer: feed()/finish() — the per-frame pipeline
flow.rs      FlowKey normalization + counters
l7/          dns, http, tls (+x509, JA3), dhcp, creds, magic
detect.rs    deterministic detectors over aggregates
report.rs    Report model + Limits (all caps in one type)
history.rs   bounded JSON device/baseline store
```

**Key decisions**

- Single-pass `feed()` per frame; detectors run once in `finish()` over
  aggregates — O(packets), no re-walk of data.
- Every list in `Report` is capped by `Limits` (defaults: 4 000
  dns/http/tls, 64 MiB head budget); overflow lands in `Meta::dropped` so
  truncation is visible, not silent.
- `FastMap` = `hashbrown::HashMap` with `foldhash::quality::RandomState`
  — per-map seeding defeats precomputed-key HashDoS at near-zero cost.
- Credential extraction is deliberately *detection of exposure*, not
  replay material: it reports what was observable on the wire.

### 3.4 `ntod-api` — HTTP/WS seam

```
lib.rs        router(), /api/* handlers, bounded stores
              (reports ≤4, objects ≤64, captures ≤2×32 MiB)
web/          maud pages, layout, components, report rendering,
              /partials/* (htmx), /sse/* (event streams)
ws.rs         command channel: scan|sniff|analyze|monitor|stop
```

**Key decisions**

- Store types are private; `store_*`/`with_*` functions are the only
  access — eviction policy can't be bypassed by a handler.
- `store_objects` *moves* carved bytes out of the report (`mem::take`) and
  stamps download ids: the report stays a summary, payloads are fetched
  by reference.
- `with_history` serializes the whole open→mutate→save cycle under one
  mutex — two live captures can never interleave a corrupt JSON write.
- Blocking work (`analyze`, scan enrichment) runs on `spawn_blocking` —
  CPU-bound parsing never stalls the reactor.

### 3.5 `ntod-cli` — binary

One file (`main.rs`): clap derive tree → library call → tabular/JSON
output. No logic worth testing lives here by design — behavior lives in
libraries where `cargo test` reaches it.

### 3.6 `ntod-tools` — external adapters

```
Backend::from_spec(spec) → Local | Wsl{distro} | Ssh{host}
runner.rs   argv spawn + deadline kill + capped output
nmap.rs     -oX XML → quick-xml → NmapHost{ports[], os, mac}
masscan.rs  -oL list → host set
sniff.rs    tcpdump -w - → raw pcap bytes → ntod-analysis
airodump.rs remote CSV survey → fixed `sh -c` fetch script
```

**Key decisions**

- argv-only execution: no shell string is ever built from user input on
  the local backend; the single `sh -c` fetch for airodump uses a fixed
  script.
- Backends are data (`Backend` enum), not traits — the argv differs,
  the contract doesn't.

### 3.7 Optional crates

- `ntod-ai`: `Ollama` client; `filter` (natural language → Filter) and
  `summarize` (Report → prose). Mounted only under `--features ai`.
- `ntod-proxy`: explicit HTTP/CONNECT proxy emitting `ProxyEvent`
  (client, method, target, bytes up/down) on an mpsc channel.
- `ntod-control`: `Cut::start` / `Throttle::start` behind feature `live`;
  RAII — `drop` restores poisoned ARP entries.

---

## 4. Data models

### 4.1 `Host` (core)

```rust
pub struct Host {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<u16>,
}
```

### 4.2 `RawFrame` / `PacketEvent` (capture)

```rust
pub struct RawFrame { pub ts_ms: i64, pub linktype: u16, pub data: Bytes }
pub struct PacketEvent { ts_ms, proto: Proto, src, sport, dst, dport, len }
```

### 4.3 `Report` (analysis)

```rust
pub struct Report {
    pub meta: Meta,            // packets, bytes, window, linktypes,
                               // dropped counters, capture_id, export_partial
    pub hosts: Vec<HostAgg>,          // ≤ top_hosts
    pub conversations: Vec<Conv>,     // ≤ top_conversations
    pub dns: Vec<Dns>,                // ≤ max_dns
    pub http: Vec<Http>,              // ≤ max_http
    pub tls: Vec<Tls>,                // ≤ max_tls
    pub dhcp: Vec<Dhcp>,              // ≤ max_dhcp
    pub credentials: Vec<Cred>,
    pub findings: Vec<Finding>,
    pub objects: Vec<Object>,         // carved; bytes moved out at API
}
```

Everything `Serialize`; everything capped. A report is a summary of a
capture, never the capture itself.

### 4.4 `Limits` — the single source of bounds

```rust
pub struct Limits {
    max_dns: 4_000, max_http: 4_000, max_tls: 4_000, max_dhcp: 1_000,
    max_hosts: 100_000, top_hosts: 500, top_conversations: 1_000,
    head_budget: 64 << 20,
}
```

## 5. State management

| State | Owner | Scope | Bound |
|---|---|---|---|
| Scan progress | `scan_stream` producer | per operation | worker pool cap |
| Live capture | `CaptureHandle` + mpsc | per operation | channel cap |
| Retained reports | API `report_store` | daemon lifetime | newest 4 |
| Carved objects | API `object_store` | daemon lifetime | newest 64 |
| Retained frames | API `capture_store` | daemon lifetime | 2 × 32 MiB |
| Device history | `history::History` JSON | `$NTOD_DATA_DIR` or `~/.ntod-scan` | bounded file |
| UI view pref | `localStorage["ntok-view"]` | browser | shared with ntok |

No database, no write-ahead log — local-first means the only persisted
state is the history JSON, written under a single mutex.

## 6. Error handling

```
network input (frames/pcap/WS/tool output)
   → decoders: Option / counted-dropped
   → parsers: Result<_, Error> (thiserror)
crate boundaries → #[from] into caller's Error enum
cli edge         → anyhow::Result (context added at exit)
api edge         → (StatusCode, String) | {"type":"error"} WS event
```

Panics are programmer-bug-only (`expect` on invariant channel handoff).
Nothing reachable from a remote frame may panic — enforced by malformed-
input tests per CONTRIBUTING.

## 7. Performance considerations

- **Scan throughput**: bounded worker pool; wall-clock ≈
  `ceil(hosts/workers) × timeout`. `--fast` skips enrichment.
- **Analysis**: single O(n) frame pass; flow map lookup is foldhash-fast;
  head buffers stop carving once the 64 MiB global budget is spent.
- **Memory**: report size is a function of `Limits`, not input size —
  a 10 GB pcap produces the same bound report as a 10 MB one.
- **UI**: WS/SSE streams; packet table capped at 300 DOM rows;
  `transform`/`opacity` animations only.

## 8. Security considerations

- [x] No required outbound network calls; optional seams warn-and-degrade
- [x] argv-only subprocess execution (no shell injection surface)
- [x] All remote strings escaped before `innerHTML`
- [x] Upload body limit (64 MiB) before any parsing
- [x] Per-map-seeded hashing against HashDoS
- [x] Daemon binds loopback by default
- [x] Active features behind feature flags + runtime warnings
- [x] No secrets in reports: credentials found on the wire are flagged as
      findings, not exfiltrated anywhere

## 9. Deployment / build

- `cargo build --release -p ntod-cli` → single `ntod` binary
  (thin LTO, `codegen-units = 1`).
- `cargo build --release -p ntod-cli --features tools|ai|cut|all` for
  optional capabilities.
- `npm run build` in `apps/islands` regenerates `apps/web/islands/`
  (required only when the island source changes).
- Windows note: `pcap-backend`/`cut` need the Npcap SDK at build time;
  the default build has no SDK requirement.

## 10. Document control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-11-22 | Devin | Initial release |
