# ntod-scan — Technical Specification Document (TSD)

Wire-level and API-level specification: public library signatures, REST
routes, the WebSocket protocol, CLI grammar, configuration, testing, and
build instructions. Design rationale lives in [SDD.md](SDD.md).

## 1. Technical overview

ntod-scan is a Rust 2024 workspace (`resolver = "3"`, `members = crates/*`)
producing one binary (`ntod`) and eight reusable crates. Two runtime
modes: one-shot CLI commands, and `ntod serve` — a loopback axum daemon
exposing REST, WebSocket, SSE, and server-rendered pages.

### 1.1 Objectives

- Byte-exact local triage of `.pcap`/`.pcapng` captures
- Bounded live capture without a pcap SDK on Windows (RcvAll)
- Uniform `Report` across file / live / remote captures
- Optional external-tool execution over local / WSL / SSH backends

## 2. Technology stack

### 2.1 Workspace dependency versions

| Crate | Key deps | Version |
|---|---|---|
| ntod-core | ipnetwork 0.20, ping 0.7, dns-lookup 2, thiserror 2 | — |
| ntod-capture | etherparse 0.15, pcap 2 (opt), windows-sys 0.60 (win) | — |
| ntod-analysis | etherparse 0.15, hashbrown 0.17, foldhash 0.2, base64 0.22, md5 0.7, sha2 0.10 | — |
| ntod-api | axum 0.8 (multipart, ws), maud 0.27, tokio 1, tower-http 0.6, tokio-stream 0.1 | — |
| ntod-cli | clap 4 (derive), anyhow 1, axum 0.8, tokio 1 | — |
| ntod-tools | quick-xml 0.37, serde | — |
| ntod-ai | reqwest 0.12 (json), async-trait 0.1 | — |
| ntod-proxy | tokio 1 | — |
| ntod-control | pnet 0.35 (feature `live`) | — |

Dev: criterion 0.8 (analysis bench `analyze`). Workspace clippy:
`all = "warn"`; release: `lto = "thin"`, `codegen-units = 1`.

### 2.2 External requirements

| Requirement | Needed for |
|---|---|
| Administrator / root | `sniff`, live capture backends |
| Npcap SDK (Windows, build-time) | `pcap-backend`, `cut` features |
| nmap / masscan / tcpdump / airodump-ng | `tools` feature, on the chosen backend |
| OpenSSH client | `tools` `--via ssh:` |
| Ollama endpoint | `ai` feature |
| Node.js 20+ | rebuilding `apps/web/islands/` only |

## 3. Library API surface

### 3.1 ntod-core

```rust
pub fn local_subnet() -> Result<Ipv4Network, Error>;
pub fn scan(subnet: Ipv4Network, timeout: Duration, workers: usize) -> Vec<Host>;
pub fn scan_stream(/* same + filter */) -> impl Stream<Item = ScanEvent>; // two-phase
pub mod discover { pub fn enrich(hosts: &mut Vec<Host>); }
pub mod wifi     { pub fn networks() -> Result<Vec<WifiNetwork>, Error>; }
pub struct Host { ip, mac: Option<String>, hostname: Option<String>,
                  vendor: Option<String>, open_ports: Vec<u16> }
pub struct Filter { /* proto, host, port, direction predicates */ }
pub enum Proto { Tcp, Udp, Icmp, Other }
```

### 3.2 ntod-capture

```rust
pub fn start(ip: IpAddr) -> Result<CaptureHandle, Error>;
impl CaptureHandle {
    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<RawFrame>>;
    pub fn stop(self);
}
pub struct RawFrame { pub ts_ms: i64, pub linktype: u16, pub data: Bytes }
pub mod decode { pub fn decode_frame(u16, &[u8], i64) -> Option<PacketEvent>; }
pub mod pcapr  { pub fn for_each(bytes: &[u8], f: impl FnMut(Packet) -> bool)
                 -> Result<(), Error>; }   // .pcap and .pcapng
pub mod pcapw  { /* write classic pcap from RawFrame iter */ }
```

### 3.3 ntod-analysis

```rust
pub fn analyze(bytes: &[u8]) -> Result<Report, Error>;
pub fn analyze_retain(bytes: &[u8], keep_budget: usize)
    -> Result<(Report, Vec<RawFrame>, bool /* complete */), Error>;
pub fn analyze_live(/* iface + duration */) -> Result<Report, Error>;
pub struct Report { meta, hosts, conversations, dns, http, tls, dhcp,
                    credentials, findings, objects }
pub struct Limits { /* all report caps; Default impl in SDD §4.4 */ }
pub mod history {
    pub struct History;
    pub fn data_dir() -> PathBuf;              // $NTOD_DATA_DIR | ~/.ntod-scan
    impl History { pub fn open(dir) -> Self; pub fn save(&self); /* observe */ }
}
```

### 3.4 ntod-tools

```rust
pub struct Backend;                       // Local | Wsl | Ssh
impl Backend { pub fn from_spec(&str) -> Result<Self, Error>; }
pub fn probe(&Backend) -> Vec<ToolInfo>;  // name + version | MISSING
pub mod nmap     { pub fn scan(&Backend, &[&str], top_ports, service)
                   -> Result<Vec<NmapHost>, Error>; }
pub mod masscan  { pub fn scan(&Backend, &[&str], ports, rate)
                   -> Result<Vec<NmapHost>, Error>; }
pub mod airodump { pub fn survey(&Backend, iface, seconds)
                   -> Result<Vec<AirodumpAp>, Error>; }
pub mod sniff    { pub fn capture(&Backend, iface, seconds, bpf, cap)
                   -> Result<Vec<u8>, Error>; }   // raw pcap
```

### 3.5 ntod-api

```rust
pub fn router(web_root: &str) -> Router;
```

## 4. REST API

Base: `http://127.0.0.1:{port}` (default 7878). All JSON.

| Method | Path | Params | Response |
|---|---|---|---|
| GET | `/api/subnet` | — | `{subnet: "a.b.c.d/n"}` |
| GET | `/api/scan` | `subnet?`, `timeout_ms?`, `workers?` | `Host[]` |
| GET | `/api/wifi` | — | `WifiNetwork[]` |
| POST | `/api/analyze` | body = raw .pcap/.pcapng (≤ 64 MiB) | `Report` |
| GET | `/api/analyze/live` | `seconds?` | `Report` |
| GET | `/api/devices` | — | history device list |
| GET | `/api/alerts` | — | history alerts |
| GET | `/api/objects/{id}` | — | carved bytes + filename |
| GET | `/api/capture/{id}/pcap` | `host?`, `port?`, `proto?` | filtered .pcap |
| GET | `/api/report/{id}` | — | retained `Report` JSON |

Feature-gated:

| Method | Path | Feature | Params |
|---|---|---|---|
| POST | `/api/ai/filter` | `ai` | `{text}` → `Filter` |
| POST | `/api/ai/summarize` | `ai` | `{report_id}` → `{summary}` |
| GET | `/api/tools` | `tools` | `via?` → tool availability |
| GET | `/api/tools/nmap` | `tools` | `targets`, `top_ports?`, `service?`, `via?` |
| GET | `/api/tools/masscan` | `tools` | `targets`, `ports?`, `rate?`, `via?` |
| GET | `/api/tools/airodump` | `tools` | `iface?`, `seconds?`, `via?` |
| GET | `/api/tools/sniff` | `tools` | `iface?`, `seconds?`, `bpf?`, `via?` |

Error form: `(StatusCode, String)` — 400 bad input, 413 over upload cap,
404 absent report/object/feature route, 500 backend/parse failure.

## 5. WebSocket protocol — `/ws`

One active command per connection. Client → server:

```json
{"action":"scan",    "subnet"?: "a.b.c.d/n", "timeout_ms"?: 800, "workers"?: 64}
{"action":"sniff",   "filter"?: Filter}
{"action":"analyze", "seconds"?: 15, "via"?: "local|wsl[:d]|ssh:[u@]h",
                     "iface"?: "any", "bpf"?: "host x and port 53"}
{"action":"monitor", "window"?: 10, "via"?: ..., "iface"?: ...}
{"action":"stop"}
```

Server → client events:

```json
{"type":"found",     "ip":"..."}                  scan fast phase
{"type":"host",      "host":{...}}                scan slow phase (enriched)
{"type":"packet",    "packet":{...}}              sniff frames
{"type":"analyzing", "packets":N, "elapsed_ms":M} triage progress
{"type":"report",    "report":{...}}              finished Report
{"type":"monitor",   "window":N, "packets":N}     monitor window done
{"type":"finding",   "finding":{...}}             new-device/anomaly alert
{"type":"done",      "hosts":N}
{"type":"error",     "msg":"..."}                 socket stays open
```

## 6. SSR pages, partials, SSE

- Pages (maud): `/` → `/scan`, `/sniff`, `/wifi`, `/analyze`, `/tools`,
  `/devices`.
- htmx partials: `/partials/{wifi,devices,alerts,scan/run,analyze-live,
  monitor/run,stop/{tk}}`, `POST /partials/analyze`, tools partials under
  `tools` feature, `POST /partials/ai-summary/{id}` under `ai`.
- SSE (HTML fragment events): `/sse/{scan,analyze,monitor}`.

## 7. CLI grammar

```
ntod scan [--subnet CIDR] [--timeout-ms 800] [--workers 64] [--fast]
ntod sniff [--count N]
ntod wifi
ntod analyze <file.pcap|pcapng> [--json] [--carve DIR]
ntod proxy [--port 8888]
ntod cut <target> --gateway <ip>                  (feature cut)
ntod throttle <target> --gateway <ip> [--rate B/s] (feature cut)
ntod tool probe|nmap|masscan|airodump|sniff [...] --via local|wsl[:d]|ssh:[u@]h
        nmap <targets...> [--top-ports 100] [--service] [--json]
        masscan <targets...> [--ports 1-1000] [--rate 1000] [--json]
        airodump [--iface wlan0mon] [--seconds 10] [--json]
        sniff [--iface any] [--seconds 15] [--bpf EXPR] [--save FILE] [--json]
ntod serve [--port 7878] [--web-root apps/web]
```

## 8. Data flow specifics

### 8.1 Filtered pcap export

```
GET /api/capture/{id}/pcap?host=&port=&proto=
→ capture_store lookup → filter RawFrames via decode_frame predicates
→ pcapw write → application/vnd.tcpdump.pcap
→ report.meta.export_partial=true means later frames were never retained
```

### 8.2 Live analyze (history path)

```
analyze_live(seconds) → capture backend start → timed collect
→ Analyzer (same engine as files) → Report
→ API history_observe(Report) under single mutex → devices/alerts
→ WS/SSE finding events for new devices / anomalies
```

## 9. Implementation guidelines

- **Thread safety**: shared state only through `OnceLock<Mutex<_>>`
  stores; engines hold no statics; `Send + Sync` required on anything
  crossing `spawn_blocking`.
- **Errors**: `thiserror` enums inside crates, `anyhow` at the binary
  edge; `?` propagation; context strings at the edge only.
- **Logging**: `eprintln!` for progress/warnings, `println!` for results —
  stdout stays pipe-safe (`--json` guaranteed clean).
- **Config**: env `NTOD_DATA_DIR` for history; everything else is CLI
  flags with defaults. No config files.
- **Untrusted input**: frames, pcap bytes, WS JSON, tool stdout, SSIDs —
  parse, bound, escape; never `unwrap` on any of it.

## 10. Testing strategy

| Layer | Coverage target | Key scenarios |
|---|---|---|
| pcapr/pcapw | every reader path | malformed headers, truncated records, pcapng endianness, round-trip |
| L7 dissectors | all modules | malformed payloads, empty sections, boundary lengths |
| detectors | each detector | true-positive fixtures + negative controls |
| report | round-trip | serialize → deserialize equality; caps honored |
| ws/api | handler tests | bad JSON, stop semantics, feature-absent 404 |
| benches | `cargo bench -p ntod-analysis` | analyze throughput regression |

Gates (must all pass): `cargo fmt --all`, `cargo clippy --workspace --
-D warnings`, `cargo test --workspace`.

## 11. Build & platform notes

- **Windows**: default build needs no SDK (RcvAll backend);
  `pcap-backend`/`cut` need Npcap SDK. Admin terminal for capture.
- **Linux/macOS**: capture via pcap backend or `tool sniff`; root for
  raw sockets.
- **WSL**: `--via wsl[:distro]` runs adapters in a distro's userspace —
  useful for tcpdump/airodump without leaving Windows.
- `apps/web/islands/` is generated (`npm run build` in `apps/islands`)
  and gitignored — rebuild after cloning if the island is missing.

## 12. Security checklist

- [x] Loopback bind for the daemon; no auth layer exists by design —
      do not expose the port
- [x] Upload cap before parse; report caps after parse
- [x] argv-only subprocess; deadline kill; capped output
- [x] Escaped remote strings in HTML (maud + `esc()` in ntod.js)
- [x] No persistence of captured credentials beyond the report in memory
- [x] `cut`/`throttle` gated and warn on every run

## 13. Document control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-11-22 | Devin | Initial release |
