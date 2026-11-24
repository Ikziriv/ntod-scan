# Contributing

Participation in this project is covered by the
[Contributor Covenant 3.0](CODE_OF_CONDUCT.md) — read it before opening
issues or pull requests.

- **Language:** Rust only, edition 2024.
- **License:** contributions are MIT OR Apache-2.0 (`LICENSE-MIT`,
  `LICENSE-APACHE`). `apps/web/app.css` is vendored verbatim from
  ntok-scan's design system — never edit it; put ntod-only rules in
  `apps/web/ntod.css`.
- **Local-first:** no telemetry, no accounts, no required network calls
  to ntod's own infra. Optional capabilities (AI seam, proxy) degrade to
  warnings when unavailable — a capture or scan must never fail because
  an optional piece is missing.
- **Bounded everything:** capture feeds, worker counts, timeouts, body
  sizes, channels. No unbounded queues or retries.
- **Errors:** expected failures return `Result`; don't panic on
  network-controlled input (frames, L7 payloads, pcap files, WS
  messages).
- **Untrusted strings:** SSIDs, hostnames, and other remote-provided
  values must be escaped before `innerHTML` in `apps/web/app.js`.
- **Tests:** required for behavior changes — dissectors and file
  readers get malformed-input tests, report formats get round-trip
  tests. Run `cargo test --workspace` and
  `cargo clippy --workspace -- -D warnings` before submitting.
- **Style:** `cargo fmt --all`. Match surrounding code. Comments
  explain *why*.
- **Commits:** small, focused, clear subject line.
- **Security:** report vulnerabilities privately per `SECURITY.md` —
  never in a public issue or PR description.

## Layout

```
crates/
  core/      scanning engine library — scan, discover, wifi, arp, oui
  capture/   packet capture — pcap device and RcvAll raw socket
             backends; pcapr reads .pcap/.pcapng, pcapw writes
  analysis/  triage engine — flows, L7 dissectors, detectors, history
  api/       axum HTTP+WS seam (/api/*, /ws); serves apps/web via ServeDir
  cli/       `ntod` binary (clap)
  ai/        optional AI seam
  control/   optional control seam
  proxy/     optional HTTP(S) proxy
apps/
  web/       web shell — index.html + app.css (vendored) + ntod.css +
             app.js; no build step
```

## Adding a dissector or detector

- L7 dissector: new module under `crates/analysis/src/l7/` — pure
  functions over byte slices (see `dns.rs`, `http.rs`, `tls.rs`); export
  it from `l7/mod.rs` and call it from the dissection pass in
  `engine.rs`.
- Detector: add a deterministic function over the accumulated aggregates
  in `crates/analysis/src/detect.rs` and extend it in the findings pass
  in `engine.rs` (see `port_scans`, `dns_tunnels`, `arp_spoof`).
- Keep the history split intact: `analyze_live()` captures update the
  `$NTOD_DATA_DIR`/`~/.ntod-scan` store; `analyze()` on uploaded files
  never does.

## Adding a capture backend

- Implement it under `crates/capture/` and wire it into `start()`'s
  backend selection — backends yield `RawFrame { ts, linktype, bytes }`
  on a bounded channel, decoded to `PacketEvent` via
  `decode::decode_frame` so the same frames feed both the analysis
  engine and `pcapw` writes.
- Missing privileges or an unavailable backend degrade to a clear
  error, not a panic.
