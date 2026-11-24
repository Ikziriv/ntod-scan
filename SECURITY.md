# Security Policy

ntod is a LAN discovery and packet analysis tool: it captures live traffic
(pcap device and raw-socket backends), parses hostile input (captured
frames, L7 payloads, uploaded .pcap/.pcapng files), extracts credentials
from cleartext flows, and serves a web UI over HTTP and WebSocket. Treat
captured traffic, uploaded captures, and web-UI requests as potentially
malicious.

ntod itself is dual-use. Only scan and capture on networks you own or
have written permission to test.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through [GitHub Security Advisories](../../security/advisories/new)
("Report a vulnerability" on the Security tab). If private reporting is not
enabled or you cannot reach it, contact the maintainer through the channels
listed on the repository owner profile and ask for a private transfer method
before sharing details.

Give the maintainers a reasonable opportunity to investigate and ship a fix
before publishing exploitable details, proof-of-concept code, or weaponized
inputs.

## What to include

- affected ntod version, commit, or release artifact;
- OS, architecture, build profile, and enabled cargo features;
- the affected component (`ntod-core` scan/discovery, `ntod-capture`
  backends, `ntod-analysis` dissectors/detectors/history, `ntod-api`
  HTTP+WS surface, `ntod-cli`, `ntod-proxy`);
- security impact and the access an attacker needs;
- exact reproduction steps — packet input, pcap file, command line, or
  request;
- expected vs actual behavior;
- crash logs, backtraces, or sanitizer output when applicable;
- whether it reproduces from a clean checkout;
- any known workaround.

Remove credentials, API keys, internal hostnames/IPs, and unrelated system
information from logs before attaching them — ntod extracts cleartext
credentials from flows, so check reports and history files especially
carefully.

## Malicious test inputs

Do not attach a potentially harmful or non-redistributable packet capture
or traffic sample to a public issue. Describe its format, size, hash,
observed effect, and the command that reproduces the problem; coordinate a
private transfer before sending the sample.

## Scope

Security reports may cover:

- parsing of attacker-controlled bytes: captured frames, the
  DNS/HTTP/TLS/DHCP dissectors, credential extraction, and the
  .pcap/.pcapng readers — panics, over-reads, decompression or
  allocation bombs;
- capture backends (pcap device, Windows RcvAll raw socket) — privilege
  handling and malformed-frame handling;
- the `ntod-api` HTTP+WS surface — request validation, upload size
  limits, `/api/*` and `/ws` handling;
- the `ntod-proxy` HTTP(S) proxy — request forwarding and header
  handling;
- the history store (`$NTOD_DATA_DIR` or `~/.ntod-scan`) — path
  handling and secrets written to disk;
- the optional AI seam (`NTOD_AI_*`) — where secrets or captured
  content could leak into logs, reports, or history;
- dependency, CI, packaging, and release-artifact integrity.

Out of scope: the fact that ntod captures and inspects LAN traffic (that
is its purpose), denial-of-service *of a target* caused by scanning, and
general bugs with no security impact — those use the normal issue
tracker.

## Current limitations

- `ntod serve` binds `127.0.0.1` and has **no authentication**. Any
  local process or user that can reach the port can run captures and
  read history. Do not expose it on a shared machine or forward the
  port.
- The history store (`~/.ntod-scan` or `$NTOD_DATA_DIR`) is unencrypted
  JSON and may contain hostnames, MAC addresses, and protocol metadata
  from your network — treat it as sensitive.
- Reports include credentials extracted from cleartext flows by design —
  handle and share them as sensitive material.
- The AI seam sends flow-derived context to the configured endpoint
  (`NTOD_AI_BASE`, default a local Ollama). Point it at a local model if
  captured content must not leave the machine.
