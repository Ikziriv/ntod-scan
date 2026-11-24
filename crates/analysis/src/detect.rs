//! Deterministic triage detectors — every finding is a rule over
//! aggregates, no LLM required. Each returns evidence, not just a label.

use std::net::{IpAddr, Ipv4Addr};

use crate::flow::FlowTable;
use crate::l7::dns;
use crate::report::{CredentialOut, DnsEvent, Finding, HostStat, Severity, TlsEvent, fmt_mac};
use crate::{FastMap, FastSet};

const MAX_FINDINGS_PER_KIND: usize = 50;

/// Per-source scan fan-out tracked during ingest. Observations are
/// appended raw and deduplicated at report time — the hot path does
/// no hashing or dedup work at all.
#[derive(Debug, Default)]
pub struct ScanAgg {
    /// Probed destination ports, in arrival order.
    pub ports: Vec<u16>,
    /// Probed destinations, in arrival order.
    pub dsts: Vec<IpAddr>,
    /// Per-dst probed ports — detects one host being swept deeply.
    pub per_dst: FastMap<IpAddr, Vec<u16>>,
}

/// Raw-observation caps; a full 65k-port sweep still fits `ports`.
const PORT_SAMPLE_CAP: usize = 65_536;
const DST_SAMPLE_CAP: usize = 4096;
/// Max distinct destination keys tracked in `per_dst` per source IP.
const PER_DST_CAP: usize = 1024;
/// Deep-sweep triggers at 32 distinct ports, so 256 samples per dst is ample.
const PER_DST_PORT_CAP: usize = 256;

impl ScanAgg {
    pub fn observe(&mut self, dst: IpAddr, dport: u16) {
        if self.ports.len() < PORT_SAMPLE_CAP {
            self.ports.push(dport);
        }
        if self.dsts.len() < DST_SAMPLE_CAP {
            self.dsts.push(dst);
        }
        if self.per_dst.len() < PER_DST_CAP || self.per_dst.contains_key(&dst) {
            let e = self.per_dst.entry(dst).or_default();
            if e.len() < PER_DST_PORT_CAP {
                e.push(dport);
            }
        }
    }
}

/// Sorted-unique copy of a raw-append observation set — runs once per
/// source at report time, never per packet.
fn uniq<T: Ord + Clone>(v: &[T]) -> Vec<T> {
    let mut v = v.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

fn uniq_count<T: Ord + Clone>(v: &[T]) -> usize {
    uniq(v).len()
}

/// Vertical/horizontal port-scan detection from TCP SYN or UDP probes.
pub fn port_scans(aggs: &FastMap<IpAddr, ScanAgg>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (src, a) in aggs {
        if out.len() >= MAX_FINDINGS_PER_KIND {
            break;
        }
        let ports_n = uniq_count(&a.ports);
        // Deep sweep against one target — per-dst distinct port counts.
        let deep: Vec<String> = a
            .per_dst
            .iter()
            .map(|(d, ps)| (d, uniq_count(ps)))
            .filter(|(_, n)| *n >= 32)
            .map(|(d, n)| format!("{d}: {n} ports"))
            .collect();
        if !deep.is_empty() {
            out.push(Finding {
                severity: Severity::Alert,
                kind: "port-scan",
                title: format!("{src} ran a deep port sweep"),
                detail: format!(
                    "{src} probed {ports_n} distinct ports; {} destination(s) hit hard.",
                    deep.len()
                ),
                evidence: deep.into_iter().take(5).collect(),
            });
            continue;
        }
        // Broad sweep across the segment.
        let dsts = uniq(&a.dsts);
        if dsts.len() >= 8 && ports_n >= 8 {
            out.push(Finding {
                severity: Severity::Warn,
                kind: "port-scan",
                title: format!("{src} fanned out across {} hosts", dsts.len()),
                detail: format!(
                    "{src} probed {ports_n} ports on {} distinct destinations — \
                     consistent with discovery scanning.",
                    dsts.len()
                ),
                evidence: dsts.iter().take(8).map(IpAddr::to_string).collect(),
            });
        }
    }
    out
}

/// DNS-tunnel heuristic: many unique high-entropy subdomains under one
/// registered domain — the iodine/dnscat signature.
/// Tunnels favor TXT/NULL/ANY/CNAME queries and long encoded labels;
/// high-cardinality legit domains (telemetry, CDNs) mostly ask A/AAAA
/// with short labels — that's the false-positive gate.
fn tunnelish(e: &DnsEvent) -> bool {
    const TUNNEL_QTYPES: &[&str] = &["TXT", "NULL", "ANY", "CNAME"];
    TUNNEL_QTYPES.contains(&e.qtype.as_ref()) || e.name.split('.').any(|l| l.len() >= 32)
}

pub fn dns_tunnels(events: &[DnsEvent]) -> Vec<Finding> {
    let mut by_base: FastMap<&str, (FastSet<&str>, u32, u32)> = FastMap::default();
    for e in events.iter().filter(|e| !e.is_response) {
        let ent = by_base.entry(dns::base_domain(&e.name)).or_default();
        ent.0.insert(&e.name);
        ent.1 += 1;
        if tunnelish(e) {
            ent.2 += 1;
        }
    }
    let mut out = Vec::new();
    for (base, (names, total, tunnelish)) in &by_base {
        if names.len() < 30 || out.len() >= MAX_FINDINGS_PER_KIND {
            continue;
        }
        // Second signal beyond cardinality: a third of queries looking
        // tunnel-shaped, or an extreme count alone.
        let share = *tunnelish as f64 / (*total).max(1) as f64;
        if share < 0.34 && names.len() < 80 {
            continue;
        }
        // Entropy/length over the subdomain portion only.
        let mut entropy = 0.0;
        let mut maxlen = 0usize;
        for n in names {
            let sub = n.strip_suffix(*base).unwrap_or(*n);
            entropy += dns::shannon(sub);
            maxlen = maxlen.max(sub.len());
        }
        entropy /= names.len() as f64;
        if entropy >= 3.5 || maxlen >= 50 {
            let mut sample: Vec<String> = names.iter().take(4).map(|s| s.to_string()).collect();
            sample.push(format!(
                "{} unique names · avg entropy {entropy:.2} bits",
                names.len()
            ));
            out.push(Finding {
                severity: if names.len() >= 80 || share >= 0.6 {
                    Severity::Alert
                } else {
                    Severity::Warn
                },
                kind: "dns-tunnel",
                title: format!("Possible DNS tunnel under {base}"),
                detail: format!(
                    "{} unique subdomains of {base} ({}% tunnel-shaped queries) \
                     with high entropy ({entropy:.2} bits/char, longest label \
                     {maxlen}) — typical of encoded tunnel traffic.",
                    names.len(),
                    (share * 100.0).round() as u32,
                ),
                evidence: sample,
            });
        }
    }
    out
}

/// Beacon/C2 heuristic: steady-period connections, low jitter.
/// `min_n`: needs ≥8 intervals to be credible.
pub fn beacons(flows: &FlowTable) -> Vec<Finding> {
    let mut out = Vec::new();
    for (k, f) in flows.iter() {
        if out.len() >= MAX_FINDINGS_PER_KIND {
            break;
        }
        for a_to_b in [true, false] {
            let Some((n, mean, cv)) = f.cadence(a_to_b) else {
                continue;
            };
            // Size regularity separates a beacon (fixed check-in shape)
            // from a keepalive channel (mixed app payload sizes).
            let Some(scv) = f.size_cv(a_to_b) else {
                continue;
            };
            if n >= 8 && cv < 0.2 && scv < 0.2 && (500.0..=300_000.0).contains(&mean) {
                let (src, sport, dst, dport) = if a_to_b {
                    (k.a_ip, k.a_port, k.b_ip, k.b_port)
                } else {
                    (k.b_ip, k.b_port, k.a_ip, k.a_port)
                };
                out.push(Finding {
                    severity: Severity::Warn,
                    kind: "beacon",
                    title: format!("{src} checks in to {dst} every {:.1}s", mean / 1000.0),
                    detail: format!(
                        "{src}:{sport} → {dst}:{dport} shows {n} transfers at \
                         {mean:.0}ms intervals (jitter {cv:.2}) — periodicity \
                         consistent with beaconing.",
                    ),
                    evidence: vec![format!("{src}:{sport} → {dst}:{dport}")],
                });
            }
        }
    }
    out.sort_by(|x, y| x.title.cmp(&y.title));
    out
}

/// Heavy-hitter outlier (Noction-lite): hosts dominating byte share —
/// z-score over host bytes, requiring both 3σ and ≥30% of the capture.
pub fn heavy_hitters(hosts: &[HostStat]) -> Vec<Finding> {
    if hosts.len() < 4 {
        return Vec::new();
    }
    let total: f64 = hosts.iter().map(|h| h.bytes as f64).sum();
    let mean = total / hosts.len() as f64;
    let var = hosts
        .iter()
        .map(|h| (h.bytes as f64 - mean).powi(2))
        .sum::<f64>()
        / hosts.len() as f64;
    let std = var.sqrt();
    if std <= 0.0 || total <= 0.0 {
        return Vec::new();
    }
    hosts
        .iter()
        .filter(|h| h.bytes as f64 > mean + 3.0 * std && h.bytes as f64 > total * 0.3)
        .take(MAX_FINDINGS_PER_KIND)
        .map(|h| Finding {
            severity: Severity::Info,
            kind: "heavy-hitter",
            title: format!(
                "{} dominates traffic — {:.0}% of capture bytes",
                h.ip,
                h.bytes as f64 * 100.0 / total
            ),
            detail: format!(
                "{:.1} MB moved by {} vs. {:.1} MB mean across {} hosts — \
                 an outlier worth a look (bulk transfer, backup, or exfil).",
                h.bytes as f64 / 1e6,
                h.ip,
                mean / 1e6,
                hosts.len()
            ),
            evidence: vec![format!("{} pkts · {} bytes", h.pkts, h.bytes)],
        })
        .collect()
}

/// Cleartext interactive sessions — a Telnet login is visible on the
/// wire even when no credential line was extracted.
pub fn cleartext_sessions(flows: &FlowTable) -> Vec<Finding> {
    flows
        .iter()
        .filter(|(k, f)| {
            k.proto == 6
                && k.service_port() == 23
                && !f.stream_data(true).is_empty()
                && !f.stream_data(false).is_empty()
        })
        .take(MAX_FINDINGS_PER_KIND)
        .map(|(k, _)| Finding {
            severity: Severity::Warn,
            kind: "cleartext-telnet",
            title: format!("Telnet session {} ↔ {}", k.a_ip, k.b_ip),
            detail: "Interactive Telnet carries credentials and keystrokes \
                     in cleartext — replace with SSH."
                .into(),
            evidence: vec![format!("{}:{} ↔ {}:{}", k.a_ip, k.a_port, k.b_ip, k.b_port)],
        })
        .collect()
}

/// ARP spoof indicator: one IP claimed by multiple MACs in `is-at` replies.
pub fn arp_spoof(claims: &FastMap<Ipv4Addr, Vec<[u8; 6]>>) -> Vec<Finding> {
    claims
        .iter()
        .filter(|(_, macs)| macs.len() > 1)
        .take(MAX_FINDINGS_PER_KIND)
        .map(|(ip, macs)| Finding {
            severity: Severity::Alert,
            kind: "arp-spoof",
            title: format!("{ip} claimed by {} MACs", macs.len()),
            detail: format!(
                "Multiple MAC addresses answered is-at for {ip} — \
                 classic ARP spoof/poison signature."
            ),
            evidence: macs.iter().take(6).map(fmt_mac).collect(),
        })
        .collect()
}

/// Widely documented JA3 hashes from public threat-intel lists —
/// a match means the client's TLS stack looks like that malware's.
const JA3_BAD: &[(&str, &str)] = &[
    ("6734f37431670b3ab4292b8f60f29984", "TrickBot"),
    ("4d7a28d6f2263ed61de88ca66eb53e8b", "Emotet"),
    ("51c64c77e60f3980eea90869b68c58a8", "Dridex"),
    ("72a589da586844d7f0818ce684948eea", "Cobalt Strike"),
];

/// Does `cn` (a cert subject CN, possibly "*.dom") cover `sni`?
fn cn_covers(cn: &str, sni: &str) -> bool {
    if let Some(base) = cn.strip_prefix("*.") {
        !base.is_empty()
            && (sni.eq_ignore_ascii_case(base)
                || (sni.len() > base.len()
                    && sni.as_bytes()[sni.len() - base.len() - 1] == b'.'
                    && sni[sni.len() - base.len()..].eq_ignore_ascii_case(base)))
    } else {
        sni.eq_ignore_ascii_case(cn)
    }
}

/// Dedup key for `tls_flags` — one finding per (kind, subject), no
/// string formatting just to dedupe.
#[derive(PartialEq, Eq, Hash)]
enum Seen<'a> {
    Heartbeat(IpAddr),
    WeakTls(IpAddr),
    Ja3(IpAddr),
    Cert(Option<&'a str>, Option<&'a str>, i64),
    SniMismatch(&'a str),
}

/// TLS hygiene flags from parsed certificates and records.
pub fn tls_flags(events: &[TlsEvent], now_ms: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: FastSet<Seen> = FastSet::default();
    // Per-kind caps so warn-level cert findings cannot starve alert-level findings.
    let mut counts = [0usize; 6]; // [heartbeat, weak, ja3, expired, self_signed, mismatch]
    for e in events {
        if e.heartbeat
            && counts[0] < MAX_FINDINGS_PER_KIND
            && seen.insert(Seen::Heartbeat(e.server))
        {
            counts[0] += 1;
            out.push(Finding {
                severity: Severity::Alert,
                kind: "heartbleed",
                title: format!("Heartbeat frames on {}", e.server),
                detail: format!(
                    "TLS heartbeat records between {} and {}:{} — \
                     could be a Heartbleed probe.",
                    e.client, e.server, e.server_port
                ),
                evidence: vec![
                    e.sni
                        .as_deref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| e.server.to_string()),
                ],
            });
        }
        // Obsolete protocol negotiated (TLS < 1.2 — SSLv3 / 1.0 / 1.1).
        if let Some(v) = e.server_version
            && v < 0x0303
            && counts[1] < MAX_FINDINGS_PER_KIND
            && seen.insert(Seen::WeakTls(e.client))
        {
            counts[1] += 1;
            out.push(Finding {
                severity: Severity::Warn,
                kind: "weak-tls",
                title: format!("{} negotiated TLS {v:#06x}", e.client),
                detail: format!(
                    "Server {}:{} accepted an obsolete TLS version — \
                     POODLE/BEAST-era protocol still in use.",
                    e.server, e.server_port
                ),
                evidence: vec![
                    e.sni
                        .as_deref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| e.server.to_string()),
                ],
            });
        }
        // Client's TLS stack matches a documented malware fingerprint.
        if let Some(j) = &e.ja3
            && counts[2] < MAX_FINDINGS_PER_KIND
            && let Some((_, name)) = JA3_BAD.iter().find(|(h, _)| *h == &**j)
            && seen.insert(Seen::Ja3(e.client))
        {
            counts[2] += 1;
            out.push(Finding {
                severity: Severity::Alert,
                kind: "ja3-known-bad",
                title: format!("{}'s TLS fingerprint matches {name}", e.client),
                detail: format!(
                    "JA3 {j} is publicly associated with {name} — \
                     investigate {e_client} for malware.",
                    e_client = e.client
                ),
                evidence: vec![format!("{}:{}", e.server, e.server_port)],
            });
        }
        for c in &e.certs {
            let key = Seen::Cert(
                c.subject_cn.as_deref(),
                c.issuer_cn.as_deref(),
                c.not_after_ms,
            );
            if !seen.insert(key) {
                continue;
            }
            if c.not_after_ms > 0 && c.not_after_ms < now_ms {
                if counts[3] >= MAX_FINDINGS_PER_KIND {
                    continue;
                }
                counts[3] += 1;
                out.push(Finding {
                    severity: Severity::Warn,
                    kind: "cert-expired",
                    title: format!(
                        "Expired certificate for {}",
                        c.subject_cn.as_deref().unwrap_or("?")
                    ),
                    detail: format!(
                        "Presented by {}:{} — notAfter passed.",
                        e.server, e.server_port
                    ),
                    evidence: vec![
                        e.sni
                            .as_deref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                    ],
                });
            } else if c.self_signed {
                if counts[4] >= MAX_FINDINGS_PER_KIND {
                    continue;
                }
                counts[4] += 1;
                out.push(Finding {
                    severity: Severity::Warn,
                    kind: "cert-self-signed",
                    title: format!(
                        "Self-signed certificate for {}",
                        c.subject_cn.as_deref().unwrap_or("?")
                    ),
                    detail: format!("Presented by {}:{}.", e.server, e.server_port),
                    evidence: vec![
                        e.sni
                            .as_deref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                    ],
                });
            }
        }
        // Cert presented for a name the client didn't ask for — classic
        // MITM/decoy-server tell. Wildcard-aware, first (leaf) cert only.
        if counts[5] < MAX_FINDINGS_PER_KIND
            && let (Some(sni), Some(leaf)) = (&e.sni, e.certs.first())
            && let Some(cn) = &leaf.subject_cn
            && !cn_covers(cn, sni)
            && seen.insert(Seen::SniMismatch(sni))
        {
            counts[5] += 1;
            out.push(Finding {
                severity: Severity::Warn,
                kind: "sni-cert-mismatch",
                title: format!("Cert for {cn} served on SNI {sni}"),
                detail: format!(
                    "Client asked {}:{} for {sni} but the certificate \
                     names {cn} — interception or a misdirected vhost.",
                    e.server, e.server_port
                ),
                evidence: vec![
                    leaf.issuer_cn
                        .as_deref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    e.client.to_string(),
                ],
            });
        }
    }
    out
}

/// Summary finding for cleartext credentials.
pub fn cleartext(creds: &[CredentialOut]) -> Option<Finding> {
    if creds.is_empty() {
        return None;
    }
    Some(Finding {
        severity: Severity::Alert,
        kind: "cleartext-creds",
        title: format!("{} cleartext credential(s) captured", creds.len()),
        detail: "Logins crossed the wire readable by anyone on the segment. \
                 See the Credentials view for protocols and hosts."
            .into(),
        evidence: creds
            .iter()
            .take(6)
            .map(|c| format!("{} {} → {}", c.proto, c.src, c.dst))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_deep_sweep() {
        let mut aggs = FastMap::default();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let a = aggs.entry(src).or_insert_with(ScanAgg::default);
        for p in 1..50u16 {
            a.observe(dst, p);
        }
        let fs = port_scans(&aggs);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, "port-scan");
        assert_eq!(fs[0].severity, Severity::Alert);
    }

    #[test]
    fn flags_tunnel_entropy() {
        let mut evs = Vec::new();
        for i in 0..40 {
            evs.push(DnsEvent {
                ts: 0,
                client: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
                server: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                service: "dns",
                name: format!("a9f{i}kx7q2m8zb4v1n6y5j0d3w.evil.com").into(),
                qtype: "TXT".into(),
                is_response: false,
                rcode: None,
                answers: vec![],
            });
        }
        let fs = dns_tunnels(&evs);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, "dns-tunnel");
    }

    #[test]
    fn flags_arp_conflict() {
        let mut claims = FastMap::default();
        claims.insert(Ipv4Addr::new(192, 168, 1, 1), vec![[0xaa; 6], [0xcc; 6]]);
        let fs = arp_spoof(&claims);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].kind, "arp-spoof");
    }

    #[test]
    fn cn_covers_enforces_wildcard_prefix() {
        assert!(cn_covers("example.com", "example.com"));
        assert!(!cn_covers("example.com", "sub.example.com"));
        assert!(cn_covers("*.example.com", "sub.example.com"));
        assert!(!cn_covers("*.example.com", "evil-example.com"));
    }
}
