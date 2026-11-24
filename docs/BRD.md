# ntod-scan — Business Requirements Document (BRD)

## 1. Executive summary

### 1.1 Project overview

ntod-scan is a local-first network discovery and packet-triage toolkit:
a single Rust binary plus a server-rendered web UI that replaces a
collection of consumer apps (Fing-style scanners), manual toolchains
(tcpdump + Wireshark triage), and paid cloud services (hosted pcap
analyzers) — while keeping every byte of capture data on the user's own
hardware.

### 1.2 Business problem

1. **Privacy vs. capability trade-off.** Hosted pcap analyzers require
   uploading raw traffic — which may contain credentials, internal
   hostnames, and payloads — to a third party. Sensitive captures
   (incident response, client sites) often *can't* be uploaded at all.
2. **Fragmented toolchain.** Discovery (Fing/nmap), capture (tcpdump),
   triage (Wireshark tedium), and reporting live in separate tools with
   separate output formats and no unified model.
3. **Cost of the hosted tier.** Cloud analyzers meter by upload size,
   cap free tiers (~50 MB), and retain uploaded data under their terms.
4. **Skill floor.** Wireshark triage is powerful but slow to read; there
   is no one-command "tell me what's suspicious in this capture" local
   tool with a deterministic, bounded report.

### 1.3 Business opportunity

A single local binary that delivers the cloud-analyzer report on-device
turns a privacy compromise into a non-decision, collapses the toolchain
to one CLI + one UI, and costs nothing per capture. The Rust workspace
layout also yields a reusable library foundation (scan, capture,
analysis engines) for future products.

## 2. Business objectives

### 2.1 Primary objectives

| # | Objective | Success metric | Target |
|---|---|---|---|
| O1 | Replace hosted pcap upload workflow | % of triage done via `analyze` vs. cloud sites | 100% for sensitive captures |
| O2 | One-command triage | Time from file to actionable findings | < 60 s incl. findings list |
| O3 | Deterministic safety under hostile input | Memory growth vs. capture size | Bounded (report caps; see TSD §Limits) |
| O4 | Unified output | Report model shared across file/live/remote | 1 model, 3 inputs |

### 2.2 Secondary objectives

- Ship a premium, offline-complete web UI as the primary interactive
  shell (matching the shared design system with ntok-scan).
- Provide an adapter layer so existing Kali tooling runs behind one
  `--via` flag rather than bespoke scripts.
- Keep every optional capability (AI, tools, ARP control) removable at
  compile time.

## 3. Stakeholder requirements

### 3.1 Primary stakeholders

**Security analyst / IR responder**
- Needs: defensible local analysis, credential/tunnel detection,
  exportable evidence (filtered pcap, carved objects).
- Pain: can't upload client captures; cloud tiers cap at ~50 MB.
- Success: complete triage locally, evidence exported in standard pcap.

**Network administrator**
- Needs: scripted discovery, device baseline, alerts on new devices,
  remote capture from Linux/Kali hosts.
- Pain: separate tools per task; no baseline without an agent.
- Success: `ntod serve` + `/api/devices` + `/api/alerts` + WS findings.

**Home-lab / power user**
- Needs: "what's on my network" with vendor/hostname detail and an
  approachable UI.
- Pain: consumer apps are closed, cloud-linked, or paid.
- Success: `ntod scan` and the `/scan` view answer it in seconds.

### 3.2 Stakeholder matrix

| Stakeholder | Influence | Interest | Engagement |
|---|---|---|---|
| Analyst / IR | High | High | CLI + report correctness, evidence export |
| Admin | Med | High | daemon mode, devices/alerts, tools adapters |
| Home-lab user | Low | Med | web UI polish, zero-config defaults |
| OSS contributor | Med | Med | CONTRIBUTING conventions, verify gates |

## 4. Functional requirements (MoSCoW)

### 4.1 Discovery & wireless

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | ICMP/ARP discovery of live hosts on an IPv4 subnet | Must |
| FR-02 | Enrichment: MAC, OUI vendor, reverse-DNS hostname, top ports | Must |
| FR-03 | Wi-Fi survey: SSID, BSSID, signal, channel, security | Must |
| FR-04 | airodump-ng monitor-mode survey via remote backend | Could |

### 4.2 Capture & triage

| ID | Requirement | Priority |
|---|---|---|
| FR-10 | Streaming read of .pcap and .pcapng | Must |
| FR-11 | Bidirectional flow aggregation | Must |
| FR-12 | L7 dissectors: DNS, HTTP (+object carving), TLS (+JA3, cert hygiene), DHCP | Must |
| FR-13 | Credential-exposure extraction | Must |
| FR-14 | Deterministic detectors: port-scan, DNS-tunnel, ARP-spoof, beaconing, TLS hygiene | Must |
| FR-15 | Live capture (pcap or raw-socket backend) feeding the same engine | Must |
| FR-16 | Bounded report: all lists capped, drops counted | Must |
| FR-17 | Filtered pcap re-export from retained frames | Should |
| FR-18 | Remote capture via `tcpdump -w -` on a backend | Should |

### 4.3 Surfaces

| ID | Requirement | Priority |
|---|---|---|
| FR-20 | CLI covering all engine functions, `--json` everywhere | Must |
| FR-21 | Loopback daemon: REST, WS command channel, SSE | Must |
| FR-22 | Server-rendered UI: Scan / Sniff / Wi-Fi / Analyze / Tools / Devices | Must |
| FR-23 | Device baseline + alerts from live captures only | Should |
| FR-24 | AI filter/summarize via local Ollama | Could |
| FR-25 | ARP cut/throttle for authorized own-network testing | Could |

## 5. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | Privacy | Zero required egress; uploads never touch device history |
| NFR-02 | Memory safety under hostile input | All report lists capped; global head budget 64 MiB |
| NFR-03 | Upload limit | 64 MiB body cap, enforced pre-parse |
| NFR-04 | Startup to first result | `ntod scan` useful output with zero flags |
| NFR-05 | UI offline completeness | Self-hosted fonts, vendored htmx, no CDN |
| NFR-06 | Failure mode | No panic on any network-controlled input |
| NFR-07 | Feature modularity | `ai`, `tools`, `cut` compile-time optional |
| NFR-08 | Subprocess safety | argv-only, deadline kill, capped output |

## 6. Success metrics and KPIs

### 6.1 Operational

| Metric | Baseline (status quo) | Target | Measurement |
|---|---|---|---|
| Captures analyzed locally | 0% (all via cloud/manual) | 100% sensitive captures | usage |
| Time to findings | 10–30 min manual Wireshark | < 60 s | `analyze` wall clock |
| Tools in triage loop | 3–4 separate tools | 1 binary + 1 UI | count |
| Cost per capture | metered upload tier | $0 | — |

### 6.2 Technical

| Metric | Target |
|---|---|
| Report memory vs. input size | Independent (bounded by Limits) |
| Malformed-pcap robustness | No panic; drops counted |
| Verify gates | fmt + clippy -D warnings + workspace tests green |

## 7. Constraints and assumptions

**Constraints**

- Rust only, edition 2024; MIT OR Apache-2.0.
- Design system shared with ntok-scan: `apps/web/app.css` is vendored,
  never edited here.
- Local-first is non-negotiable: no telemetry, accounts, or phone-home.
- Capture requires OS-level privilege (admin/root) — inherent to raw
  sockets, cannot be designed away.

**Assumptions**

- Users operate on networks they own or are authorized to test.
- Optional backends (SSH host, WSL, Ollama) are user-provisioned.
- Windows users needing `cut`/pcap backend can install the Npcap SDK.

## 8. Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Misuse of active features (cut/throttle) on third-party networks | Med | High | Feature-gated, warn on every run, legal banner in README/SECURITY |
| Captured credentials visible in reports | Med | Med | Findings flag exposure; nothing persisted beyond daemon memory; loopback-only UI |
| Privilege requirement deters users | Med | Low | Most commands unprivileged; `tool sniff --via ssh` avoids local privilege |
| Platform capture gaps (no Npcap on Windows) | Med | Med | RcvAll raw-socket backend needs no SDK |
| Untrusted strings → XSS in UI | Low | High | Escape discipline (maud + esc()), malformed-input tests |
| Report truncation hides data | Low | Med | `meta.dropped` counters make truncation explicit |

## 9. Timeline and milestones

| Phase | Deliverables | Status |
|---|---|---|
| Core engine | scan, discover, wifi, arp, oui | Done |
| Capture | pcapr/pcapw, RcvAll + pcap backends, decode | Done |
| Analysis | flows, L7 dissectors, detectors, report, history | Done |
| Surfaces | CLI, axum API+WS, SSR web UI, islands | Done |
| Optional seams | tools adapters, ai, proxy, control | Done (feature-gated) |
| Professional docs | README, BRD, PRD, SDD, TSD, ARCHITECTURE | This doc set |

## 10. Document control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-11-22 | Devin | Initial release |
