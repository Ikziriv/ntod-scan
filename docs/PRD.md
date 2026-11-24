# ntod-scan — Product Requirements Document (PRD)

## 1. Product vision

### 1.1 Vision statement

Give anyone responsible for a network a complete, private, one-binary
answer to "who is on my LAN and what is it saying" — the depth of hosted
pcap analyzers and commercial scanners, without a packet ever leaving
the machine.

### 1.2 Target users

- **Primary — home-lab / power user**: wants to inventory devices, spot
  unknown hardware, and understand traffic on their own network.
- **Secondary — security analyst / pentester (authorized)**: needs fast
  local pcap triage — credentials in the clear, TLS hygiene, tunneling —
  without uploading evidence to a cloud service.
- **Tertiary — network admin / sysadmin**: needs scripted discovery,
  remote captures from a Linux/Kali box, and exportable evidence.

### 1.3 Product goals

1. **Local-first**: zero telemetry, zero accounts, zero required egress.
2. **One model**: identical Report for file, live, and remote captures.
3. **Bounded by design**: no input — however hostile — can exhaust memory.
4. **Depth on demand**: CLI for scripts, daemon + web UI for exploration.

---

## 2. User stories

### 2.1 Discovery

- US-01: As a home user, I want `ntod scan` to list every live host with
  MAC, vendor, hostname, and open ports, so that I can spot unfamiliar
  devices.
- US-02: As an admin, I want `--fast` and `--workers` controls, so that
  I can trade detail for speed in scripts.
- US-03: As a web UI user, I want hosts to stream in as they're found
  (fast phase) then fill in enrichment (slow phase), so that the UI
  feels live instead of batch.

### 2.2 Capture & sniffing

- US-04: As an analyst, I want `ntod sniff` to capture live frames with
  a packet cap, so that I can eyeball traffic quickly.
- US-05: As an analyst, I want the Sniff view's packet-rate chart and a
  bounded packet table, so that live traffic is legible.

### 2.3 Capture triage

- US-06: As an analyst, I want `ntod analyze file.pcap` to produce
  hosts, conversations, DNS, HTTP, TLS/JA3, DHCP, credentials, and
  findings, so that I get a complete triage in one pass.
- US-07: As an analyst, I want `--json` on everything, so that reports
  feed jq/pipelines.
- US-08: As an analyst, I want `--carve` to extract HTTP objects, so
  that I can inspect transferred files.
- US-09: As a web UI user, I want to upload a pcap and browse the same
  report with tabs and drill-ins, so that I don't need the CLI for
  exploration.
- US-10: As an analyst, I want filtered pcap re-export from a retained
  capture, so that I can hand a smaller capture to Wireshark.

### 2.4 Wireless

- US-11: As a user, I want `ntod wifi` to list SSIDs with BSSID, signal,
  channel, and security, so that I can survey my RF environment.
- US-12: As a Kali user, I want airodump-ng surveys over WSL/SSH, so that
  I can use monitor-mode hardware remotely.

### 2.5 Devices & history

- US-13: As an admin, I want live captures to build a device baseline and
  raise new-device/anomaly findings, so that I notice when something new
  joins.
- US-14: As a privacy-conscious user, I want uploaded pcaps to never
  touch my history, so that analysis of foreign captures doesn't pollute
  my baseline.

### 2.6 External tools

- US-15: As an admin, I want nmap/masscan/tcpdump adapters that run
  locally, in WSL, or over SSH with one `--via` flag, so that one CLI
  drives my whole toolkit.

### 2.7 Optional seams

- US-16: As a user with Ollama, I want natural-language filters and AI
  report summaries, so that triage is faster — but the product must work
  fully without it.
- US-17: As a lab owner, I want ARP `cut`/`throttle` for testing on my
  own network, with ARP automatically restored when I stop.

---

## 3. Functional specifications

### 3.1 CLI (`ntod`)

| Command | Behavior | Errors |
|---|---|---|
| `scan` | sweep subnet → enrich → TSV to stdout, counts to stderr | subnet parse fail = exit 1 |
| `sniff` | capture on local IP → decode → print `proto src:port → dst:port (len)` | requires admin; Ctrl+C stops |
| `wifi` | list `SSID BSSID SIGNAL CH` | empty list + hint when adapter off |
| `analyze` | file → Report summary or `--json`; `--carve DIR` extracts objects | unreadable/malformed file = exit 1 |
| `proxy` | CONNECT proxy on 127.0.0.1:port, events to stdout | bind fail = exit 1 |
| `serve` | daemon on 127.0.0.1:port, `--web-root` for assets | bind fail = exit 1 |
| `tool *` | adapter run on backend selected by `--via` | backend unreachable / tool MISSING |
| `cut`/`throttle` | ARP poison + forward/drop; Ctrl+C → restore (feature `cut`) | warns on start, restores on exit |

### 3.2 Web UI (daemon)

| View | Contents | Interactivity |
|---|---|---|
| `/scan` | host table with per-host 24-port grid | htmx run + WS stream; row flash on arrival |
| `/sniff` | packet-rate island, proto counts, packet table (≤300 rows) | WS sniff + filter |
| `/wifi` | networks table, 5-pip signal meter | htmx refresh |
| `/analyze` | upload + tabbed report (flows/DNS/HTTP/TLS/creds/findings/objects) | upload, drill-in, AI summary (opt) |
| `/devices` | history baseline + alerts | htmx partials |
| `/tools` | probe + run nmap/masscan/sniff on a backend | `tools` feature only |

Chrome: floating `.top` nav, view switch (paper/night/terminal), `.sys-pill`
engine status. Theme preference shared with ntok via
`localStorage["ntok-view"]`.

### 3.3 API / WS

Full route table and WS message schema in [TSD.md](TSD.md) §4–6.

---

## 4. Non-functional specifications

### 4.1 Performance

- Scan of a /24 completes in bounded time: `hosts/workers × timeout`
  worst case; `--fast` skips enrichment.
- `analyze` is O(frames), single pass; memory bounded by `Limits`, not
  input size.
- Packet feed renders ≤ 300 DOM rows; UI never scrolls the page for
  overflow.

### 4.2 Reliability

- No panics on network input; malformed input counted as dropped, not
  fatal.
- Optional seams absent → routes unmounted / warnings, never crashes.
- `stop` on `/ws` cancels the running command promptly.

### 4.3 Usability

- One binary; defaults work with zero flags (`ntod scan`, `ntod serve`).
- stdout = results, stderr = progress — pipe-safe.
- Offline-complete UI: self-hosted fonts, vendored htmx.

### 4.4 Compatibility

- Windows, Linux, macOS; capture needs OS privilege; `cut`/`pcap-backend`
  need Npcap SDK at build time on Windows.
- `.pcap` and `.pcapng` both readable; export is classic `.pcap`.

---

## 5. Acceptance criteria

### 5.1 Scan (US-01, US-03)

```gherkin
Given a host on the local /24 responds to ping
When I run `ntod scan --fast`
Then its IP appears on stdout before the command exits
And with `--workers 64 --timeout-ms 800` the sweep of 254 hosts
    completes in ≤ ~4 s worst case
```

### 5.2 Analyze (US-06, US-14)

```gherkin
Given a .pcap containing HTTP basic-auth traffic and a DNS tunnel pattern
When I run `ntod analyze capture.pcap --json`
Then the report lists the credential in `credentials`
And a finding for DNS tunneling appears in `findings`
And my device history file is unchanged
```

### 5.3 Upload bounds (bounded-everything)

```gherkin
Given the daemon is running
When I POST a 100 MiB body to /api/analyze
Then the response is 413 and no parsing occurs
And when I upload a valid pcap with 10 000 DNS queries
Then the report contains ≤ 4 000 dns entries and meta.dropped.dns > 0
```

### 5.4 Live analyze + history (US-13)

```gherkin
Given the daemon has run one live analyze
When a device never seen before appears in a second live capture
Then a finding event arrives on /ws
And the device appears under /api/devices
```

### 5.5 Remote tools (US-15)

```gherkin
Given an SSH-reachable host with tcpdump
When I run `ntod tool sniff --via ssh:user@host --seconds 10`
Then I receive the same Report shape as a local analyze
And on backend unreachable, the command exits non-zero with an error
```

### 5.6 Optional seams (US-16)

```gherkin
Given ntod built without --features ai
When I request POST /api/ai/summarize
Then the route is absent (404)
And all core commands function normally
```

---

## 6. Out of scope

- Cloud sync, accounts, multi-user, or any hosted backend — by design.
- Passive IDS with signature feeds (this is triage, not Snort/Suricata).
- TLS interception/decryption — TLS is fingerprinted (JA3/SNI/certs),
  not MITM-decrypted.
- Packet crafting/fuzzing frameworks beyond the gated ARP tools.
- GUI desktop/mobile shells (the web UI *is* the shell; the api crate is
  designed so other shells can attach later).

## 7. Release criteria

### 7.1 Blockers

- [ ] `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`,
      `cargo test --workspace` all pass
- [ ] Upload cap, report caps, and store eviction verified by tests
- [ ] No `unwrap`/panic reachable from crafted pcap (malformed-input tests)

### 7.2 Checklist

- [ ] `ntod scan` / `sniff` / `wifi` / `analyze` / `serve` verified on
      Windows and Linux
- [ ] Web UI verified in all three views; XSS strings (e.g. SSID with
      `<script>`) render escaped
- [ ] Feature-flag builds (`tools`, `ai`, `cut`, `all`) compile cleanly
- [ ] islands bundle rebuilt and checked in apps/web/islands (generated)

## 8. Document control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-11-22 | Devin | Initial release |
