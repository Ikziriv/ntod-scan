//! The analysis engine: frame in, aggregates out.
//!
//! One pass over packets builds flow state and per-datagram events;
//! `finish()` then runs the TCP dissectors over head buffers and the
//! detectors over the aggregates. Bounded everywhere.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use ntod_capture::pcapr::Pkt;
use ntod_core::Proto;

use crate::detect::{self, ScanAgg};
use crate::flow::{FlowKey, FlowTable};
use crate::l7::{creds, dhcp, dns, http, magic, tls};
use crate::report::*;
use crate::{FastMap, FastSet};

/// Bounds on the ingest-side maps beyond `Limits` — every entry costs
/// one packet, so these mostly cap memory on capture-sized hostile
/// input rather than normal captures.
const MAX_SCAN_SRCS: usize = 100_000;
const MAX_ARP_IPS: usize = 65_536;
const MAX_CREDS: usize = 4_096;
const MAX_FORM_CREDS: usize = 64;
/// Distinct strings the interner will deduplicate; past this it still
/// allocates, just without sharing.
const MAX_INTERN: usize = 65_536;

#[derive(Debug, Default)]
struct HostAcc {
    pkts: u64,
    bytes: u64,
    first_ts: i64,
    last_ts: i64,
    /// First-seen names, capped at 4 — a Vec beats a BTreeSet here.
    names: Vec<Arc<str>>,
    /// Highest TTL seen as a source — nearest hint to the initial value
    /// (hop count only ever lowers it).
    ttl: u8,
}

pub(crate) struct Engine {
    limits: Limits,
    packets: u64,
    bytes: u64,
    first_ts: i64,
    last_ts: i64,
    /// DLTs seen, first-seen order — typically one entry.
    linktypes: Vec<u16>,
    flows: FlowTable,
    hosts: FastMap<IpAddr, HostAcc>,
    dns: Vec<DnsEvent>,
    dhcp_events: Vec<DhcpEvent>,
    http: Vec<HttpExchange>,
    tls: Vec<TlsEvent>,
    creds: Vec<CredentialOut>,
    /// Carved HTTP objects and bytes spent on them.
    objects: Vec<CarvedOut>,
    objects_bytes: usize,
    /// is-at claims: claimed IPv4 → claimant MACs (usually one).
    arp_claims: FastMap<Ipv4Addr, Vec<[u8; 6]>>,
    /// sender MAC for each claimed IPv4 (for host enrichment).
    arp_macs: FastMap<Ipv4Addr, [u8; 6]>,
    scan: FastMap<IpAddr, ScanAgg>,
    /// String interner — repeated names, fingerprints, and MACs share
    /// one allocation across all event vectors.
    intern: FastSet<Arc<str>>,
    form_creds: Vec<String>,
    dropped: Dropped,
}

/// UDP ports that speak the DNS wire format, and the service label.
fn dns_service(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("dns"),
        5353 => Some("mdns"),
        5355 => Some("llmnr"),
        137 => Some("nbns"),
        _ => None,
    }
}

impl Engine {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            packets: 0,
            bytes: 0,
            first_ts: i64::MAX,
            last_ts: 0,
            linktypes: Vec::new(),
            flows: FlowTable::new(limits.head_budget),
            hosts: FastMap::default(),
            dns: Vec::new(),
            dhcp_events: Vec::new(),
            http: Vec::new(),
            tls: Vec::new(),
            creds: Vec::new(),
            objects: Vec::new(),
            objects_bytes: 0,
            arp_claims: FastMap::default(),
            arp_macs: FastMap::default(),
            scan: FastMap::default(),
            intern: FastSet::default(),
            form_creds: Vec::new(),
            dropped: Dropped::default(),
        }
    }

    /// Ingest one captured frame. Never fails — malformed frames drop.
    /// Packets ingested so far — for live progress reporting.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn ingest(&mut self, p: &Pkt<'_>) {
        self.packets += 1;
        self.bytes += p.data.len() as u64;
        if p.ts_ms > 0 {
            self.first_ts = self.first_ts.min(p.ts_ms);
            self.last_ts = self.last_ts.max(p.ts_ms);
        }
        if !self.linktypes.contains(&p.linktype) {
            self.linktypes.push(p.linktype);
        }

        // Strip the link layer by DLT.
        let Some((etype, l3)) = strip_l2(p.linktype, p.data) else {
            self.dropped.unsupported_frames += 1;
            return;
        };
        match etype {
            0x0806 => return self.arp(l3, p.ts_ms),
            0x0800 => {}
            0x86DD => {}
            _ => {
                self.dropped.unsupported_frames += 1;
                return;
            }
        }

        let Some((src, dst, proto, ttl, l4)) = strip_l3(etype, l3) else {
            return;
        };

        self.host(src, p.data.len() as u64, p.ts_ms, ttl);
        self.host(dst, p.data.len() as u64, p.ts_ms, 0);

        match proto {
            6 => self.tcp(src, dst, l4, p.ts_ms, p.data.len() as u64),
            17 => self.udp(src, dst, l4, p.ts_ms, p.data.len() as u64),
            _ => {}
        }
    }

    fn host(&mut self, ip: IpAddr, len: u64, ts: i64, ttl: u8) {
        // get_mut first: one lookup for hits — the common case — and the
        // cap check only ever runs on a miss (each new host once).
        let h = match self.hosts.get_mut(&ip) {
            Some(h) => h,
            None => {
                if self.hosts.len() >= self.limits.max_hosts {
                    return;
                }
                self.hosts.entry(ip).or_default()
            }
        };
        h.pkts += 1;
        h.bytes += len;
        if h.first_ts == 0 {
            h.first_ts = ts;
        }
        h.last_ts = ts;
        h.ttl = h.ttl.max(ttl);
    }

    /// Shared-storage interner: one allocation per distinct string.
    /// Associated fn (not a method) so callers can borrow `self.intern`
    /// disjoint from `self.dns`, `self.hosts`, etc.
    fn intern(intern: &mut FastSet<Arc<str>>, s: &str) -> Arc<str> {
        if let Some(r) = intern.get(s) {
            return r.clone();
        }
        let r: Arc<str> = Arc::from(s);
        if intern.len() < MAX_INTERN {
            intern.insert(r.clone());
        }
        r
    }

    fn host_name(&mut self, ip: IpAddr, name: &str) {
        if let Some(h) = self.hosts.get_mut(&ip)
            && h.names.len() < 4
            && !h.names.iter().any(|n| n.as_ref() == name)
        {
            h.names.push(Self::intern(&mut self.intern, name));
        }
    }

    /// One scan-fan-out observation, bounded like every other map.
    fn scan_observe(&mut self, src: IpAddr, dst: IpAddr, port: u16) {
        match self.scan.get_mut(&src) {
            Some(a) => a.observe(dst, port),
            None => {
                if self.scan.len() >= MAX_SCAN_SRCS {
                    self.dropped.scan_srcs += 1;
                    return;
                }
                self.scan.entry(src).or_default().observe(dst, port);
            }
        }
    }

    /// Ethernet II ARP frame (fixed 28-byte body after opcode).
    fn arp(&mut self, b: &[u8], _ts: i64) {
        if b.len() < 28 || b[0..2] != [0, 1] || b[2..4] != [0x08, 0x00] {
            return;
        }
        let op = u16::from_be_bytes([b[6], b[7]]);
        if op != 2 {
            return; // only is-at replies feed spoof detection
        }
        let sha: [u8; 6] = match b[8..14].try_into() {
            Ok(s) => s,
            Err(_) => return,
        };
        let spa = Ipv4Addr::new(b[14], b[15], b[16], b[17]);
        let macs = match self.arp_claims.get_mut(&spa) {
            Some(m) => m,
            None => {
                if self.arp_claims.len() >= MAX_ARP_IPS {
                    self.dropped.arp_ips += 1;
                    return;
                }
                self.arp_claims.entry(spa).or_default()
            }
        };
        if !macs.contains(&sha) {
            macs.push(sha);
        }
        self.arp_macs.insert(spa, sha);
    }

    fn tcp(&mut self, src: IpAddr, dst: IpAddr, l4: &[u8], ts: i64, len: u64) {
        let Some(tcp) = TcpHeaderSlice::from_slice(l4).ok() else {
            return;
        };
        let (sport, dport) = (tcp.source_port(), tcp.destination_port());
        let payload = &l4[tcp.slice().len()..];
        let (key, fwd) = FlowKey::new(src, sport, dst, dport, 6);
        let flags = tcp_flags(&tcp);
        // One flow-table lookup covers observe + flags + stream feed.
        if !self
            .flows
            .update_tcp(key, fwd, ts, len, flags, tcp.sequence_number(), payload)
        {
            return;
        }
        // SYN without ACK = outbound probe → scan fan-out signal.
        if tcp.syn() && !tcp.ack() {
            self.scan_observe(src, dst, dport);
        }
    }

    fn udp(&mut self, src: IpAddr, dst: IpAddr, l4: &[u8], ts: i64, len: u64) {
        let Some(udp) = UdpHeaderSlice::from_slice(l4).ok() else {
            return;
        };
        let (sport, dport) = (udp.source_port(), udp.destination_port());
        let payload = &l4[8..];

        let (ukey, ufwd) = FlowKey::new(src, sport, dst, dport, 17);
        if let Some(f) = self.flows.update(ukey, ufwd, ts, len)
            && !payload.is_empty()
        {
            f.size_sample(ufwd, payload.len());
        }

        // UDP probes count toward fan-out too (e.g. nmap -sU).
        if dport < 1024 {
            self.scan_observe(src, dst, dport);
        }

        if let Some(svc) = dns_service(dport).or_else(|| dns_service(sport)) {
            self.dns_udp(src, dst, dport, svc, payload, ts);
        } else if dport == 67 || dport == 68 || sport == 67 || sport == 68 {
            self.dhcp_udp(src, dst, payload, ts);
        } else if (dport == 161 || dport == 162)
            && self.creds.len() < MAX_CREDS
            && let Some(community) = creds::snmp_community(payload)
        {
            // SNMP read/write community — device-management cleartext secret.
            self.creds.push(CredentialOut {
                ts,
                proto: "snmp-community",
                src,
                dst,
                user: Self::intern(&mut self.intern, "community"),
                secret: Self::intern(&mut self.intern, &community),
            });
        }
    }

    fn dns_udp(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        dport: u16,
        svc: &'static str,
        payload: &[u8],
        ts: i64,
    ) {
        let Some(msg) = dns::parse(payload) else {
            return;
        };
        // client/server orientation: query goes to the well-known port.
        let (client, server) = if dns_service(dport).is_some() {
            (src, dst)
        } else {
            (dst, src)
        };
        // Passive DNS: A/AAAA answers name the IPs they resolved to —
        // feeds HostStat.names alongside DHCP/mDNS/SNI.
        if msg.is_response
            && let Some((name, _)) = msg.queries.first()
        {
            for a in &msg.answers {
                if let Ok(ip) = a.parse::<IpAddr>() {
                    self.host_name(ip, name);
                }
            }
        }
        let _ = msg.queries.len();
        for (name, qt) in msg.queries.into_iter() {
            if self.dns.len() < self.limits.max_dns {
                self.dns.push(DnsEvent {
                    ts,
                    client,
                    server,
                    service: svc,
                    name: Self::intern(&mut self.intern, &name),
                    qtype: dns::qtype_name(qt),
                    is_response: msg.is_response,
                    rcode: msg.is_response.then_some(msg.rcode),
                    answers: if msg.is_response {
                        msg.answers
                            .iter()
                            .map(|a| Self::intern(&mut self.intern, a))
                            .collect()
                    } else {
                        Vec::new()
                    },
                });
            } else {
                self.dropped.dns += 1;
            }
        }
    }

    fn dhcp_udp(&mut self, _src: IpAddr, _dst: IpAddr, payload: &[u8], ts: i64) {
        let Some(m) = dhcp::parse(payload) else {
            return;
        };
        // Hostname (opt 12) and vendor-class (opt 60) both feed the
        // device-name pool — "android-dhcp-15" classifies a phone with
        // no hostname at all.
        let ip = m.requested.unwrap_or(m.yiaddr);
        if !ip.is_unspecified() {
            if let Some(hn) = &m.hostname {
                self.host_name(IpAddr::V4(ip), hn);
            }
            if let Some(vc) = &m.vendor_class {
                self.host_name(IpAddr::V4(ip), vc);
            }
        }
        if self.dhcp_events.len() < self.limits.max_dhcp {
            self.dhcp_events.push(DhcpEvent {
                ts,
                client_mac: Self::intern(&mut self.intern, &m.client_mac),
                msg_type: dhcp::msg_type_name(m.msg_type),
                yiaddr: IpAddr::V4(m.yiaddr),
                hostname: m.hostname.map(|h| Self::intern(&mut self.intern, &h)),
                requested: m.requested.map(IpAddr::V4),
            });
        } else {
            self.dropped.dhcp += 1;
        }
    }

    /// Second pass: TCP dissectors over head buffers, then detectors.
    pub fn finish(mut self) -> Report {
        let flows = std::mem::take(&mut self.flows);
        for (key, flow) in flows.iter() {
            if key.proto != 6 {
                continue;
            }
            self.dissect_flow(&key, flow);
        }
        self.flows = flows;
        self.assemble()
    }

    fn dissect_flow(&mut self, key: &FlowKey, flow: &crate::flow::Flow) {
        // DNS over TCP: 2-byte length-prefixed messages on port 53.
        if key.service_port() == 53 {
            self.dns_tcp(key, flow.stream_data(true));
            self.dns_tcp(key, flow.stream_data(false));
        }

        // TLS: whichever stream holds the ClientHello is the client.
        let a_tls = tls::probe(flow.stream_data(true));
        let b_tls = tls::probe(flow.stream_data(false));
        if a_tls || b_tls {
            self.tls_flow(key, flow, a_tls);
            return; // a flow is TLS or plaintext, not both
        }

        // HTTP: parse every message in each direction, pair them in order.
        let va = if http::probe(flow.stream_data(true)) {
            http::parse_all(flow.stream_data(true))
        } else {
            Vec::new()
        };
        let vb = if http::probe(flow.stream_data(false)) {
            http::parse_all(flow.stream_data(false))
        } else {
            Vec::new()
        };
        if !va.is_empty() || !vb.is_empty() {
            self.http_exchanges(key, flow, &va, &vb);
            self.carve_objects(key, flow, &va, &vb);
        }

        // Line-protocol credentials toward the well-known port.
        let server_port = key.service_port();
        if let Some(proto) = creds::line_proto(server_port) {
            let client_is_a = key.b_port == server_port;
            let head = if client_is_a {
                flow.stream_data(true)
            } else {
                flow.stream_data(false)
            };
            let (cip, dip) = if client_is_a {
                (key.a_ip, key.b_ip)
            } else {
                (key.b_ip, key.a_ip)
            };
            for c in creds::scan_lines(proto, head) {
                if self.creds.len() >= MAX_CREDS {
                    break;
                }
                self.creds.push(CredentialOut {
                    ts: flow.first_ts,
                    proto: c.proto,
                    src: cip,
                    dst: dip,
                    user: Self::intern(&mut self.intern, &c.user),
                    secret: Self::intern(&mut self.intern, &c.secret),
                });
            }
        }
    }

    fn dns_tcp(&mut self, key: &FlowKey, head: &[u8]) {
        let mut pos = 0;
        while pos + 2 <= head.len() {
            let mlen = u16::from_be_bytes([head[pos], head[pos + 1]]) as usize;
            pos += 2;
            if pos + mlen > head.len() {
                break;
            }
            if let Some(msg) = dns::parse(&head[pos..pos + mlen]) {
                for (name, qt) in msg.queries.into_iter() {
                    if self.dns.len() < self.limits.max_dns {
                        self.dns.push(DnsEvent {
                            ts: 0,
                            client: if msg.is_response { key.b_ip } else { key.a_ip },
                            server: if msg.is_response { key.a_ip } else { key.b_ip },
                            service: "dns",
                            name: Self::intern(&mut self.intern, &name),
                            qtype: dns::qtype_name(qt),
                            is_response: msg.is_response,
                            rcode: msg.is_response.then_some(msg.rcode),
                            answers: msg
                                .answers
                                .iter()
                                .map(|a| Self::intern(&mut self.intern, a))
                                .collect(),
                        });
                    } else {
                        self.dropped.dns += 1;
                    }
                }
            }
            pos += mlen;
        }
    }

    fn tls_flow(&mut self, key: &FlowKey, flow: &crate::flow::Flow, client_is_a: bool) {
        let (c_head, s_head) = if client_is_a {
            (flow.stream_data(true), flow.stream_data(false))
        } else {
            (flow.stream_data(false), flow.stream_data(true))
        };
        let (cip, cport, sip, sport) = if client_is_a {
            (key.a_ip, key.a_port, key.b_ip, key.b_port)
        } else {
            (key.b_ip, key.b_port, key.a_ip, key.a_port)
        };
        let mut info = tls::TlsInfo::default();
        tls::parse_records(c_head, &mut info);
        tls::parse_records(s_head, &mut info);
        if !info.saw_hello && info.certs.is_empty() && !info.heartbeat {
            return;
        }
        if self.tls.len() >= self.limits.max_tls {
            self.dropped.tls += 1;
            return;
        }
        if let Some(sni) = &info.sni {
            self.host_name(sip, sni);
        }
        self.tls.push(TlsEvent {
            first_ts: flow.first_ts,
            client: cip,
            server: sip,
            server_port: sport,
            sni: info.sni.map(|s| Self::intern(&mut self.intern, &s)),
            ja3: info.ja3.map(|s| Self::intern(&mut self.intern, &s)),
            ja3s: info.ja3s.map(|s| Self::intern(&mut self.intern, &s)),
            ja4: info.ja4.map(|s| Self::intern(&mut self.intern, &s)),
            ja4s: info.ja4s.map(|s| Self::intern(&mut self.intern, &s)),
            client_version: info.client_version,
            server_version: info.server_version,
            cipher: info.cipher,
            certs: info
                .certs
                .iter()
                .map(|c| CertOut {
                    subject_cn: c
                        .subject_cn
                        .as_deref()
                        .map(|s| Self::intern(&mut self.intern, s)),
                    issuer_cn: c
                        .issuer_cn
                        .as_deref()
                        .map(|s| Self::intern(&mut self.intern, s)),
                    not_before_ms: c.not_before_ms,
                    not_after_ms: c.not_after_ms,
                    self_signed: c.self_signed,
                })
                .collect(),
            heartbeat: info.heartbeat,
        });
        let _ = cport;
    }

    /// Pair the parsed messages of both directions into exchanges. The
    /// side whose messages are Requests is the client; responses pair
    /// with requests in order (keep-alive flows hold several).
    /// `va`/`vb` are `(stream_offset, msg)` pairs from `http::parse_all`.
    fn http_exchanges(
        &mut self,
        key: &FlowKey,
        flow: &crate::flow::Flow,
        va: &[(usize, http::HttpMsg)],
        vb: &[(usize, http::HttpMsg)],
    ) {
        let is_req = |m: &http::HttpMsg| matches!(m.kind, http::HttpKind::Request { .. });
        let is_resp = |m: &http::HttpMsg| matches!(m.kind, http::HttpKind::Response { .. });
        let client_is_a = va.iter().any(|(_, m)| is_req(m))
            || (!vb.iter().any(|(_, m)| is_req(m)) && va.len() <= vb.len());
        let (reqs, resps) = if client_is_a {
            (
                va.iter()
                    .filter(|(_, m)| is_req(m))
                    .map(|(_, m)| m)
                    .collect::<Vec<_>>(),
                vb.iter()
                    .filter(|(_, m)| is_resp(m))
                    .map(|(_, m)| m)
                    .collect::<Vec<_>>(),
            )
        } else {
            (
                vb.iter()
                    .filter(|(_, m)| is_req(m))
                    .map(|(_, m)| m)
                    .collect::<Vec<_>>(),
                va.iter()
                    .filter(|(_, m)| is_resp(m))
                    .map(|(_, m)| m)
                    .collect::<Vec<_>>(),
            )
        };
        let (client, server, sport) = if client_is_a {
            (key.a_ip, key.b_ip, key.b_port)
        } else {
            (key.b_ip, key.a_ip, key.a_port)
        };

        for i in 0..reqs.len().max(resps.len()) {
            let mut ex = HttpExchange {
                ts: flow.first_ts,
                client,
                server,
                server_port: sport,
                method: None,
                host: None,
                path: None,
                user_agent: None,
                status: None,
                content_type: None,
                location: None,
            };
            if let Some(r) = reqs.get(i) {
                if let http::HttpKind::Request { method, path } = &r.kind {
                    ex.method = Some(Self::intern(&mut self.intern, method));
                    ex.path = Some(Self::intern(&mut self.intern, path));
                }
                ex.host = r.host.as_deref().map(|h| Self::intern(&mut self.intern, h));
                ex.user_agent = r
                    .user_agent
                    .as_deref()
                    .map(|s| Self::intern(&mut self.intern, s));
                if self.creds.len() < MAX_CREDS
                    && let Some(basic) = &r.basic_auth
                    && let Some((u, p)) = creds::split_basic(basic)
                {
                    self.creds.push(CredentialOut {
                        ts: flow.first_ts,
                        proto: "http-basic",
                        src: client,
                        dst: server,
                        user: Self::intern(&mut self.intern, &u),
                        secret: Self::intern(&mut self.intern, &p),
                    });
                }
            }
            if let Some(r) = resps.get(i) {
                if let http::HttpKind::Response { status } = r.kind {
                    ex.status = Some(status);
                }
                ex.content_type = r
                    .content_type
                    .as_deref()
                    .map(|s| Self::intern(&mut self.intern, s));
                ex.location = r
                    .location
                    .as_deref()
                    .map(|s| Self::intern(&mut self.intern, s));
            }
            if self.http.len() < self.limits.max_http {
                self.http.push(ex);
            } else {
                self.dropped.http += 1;
            }
        }

        // Form-field credentials anywhere in the client's stream.
        let head = if client_is_a {
            flow.stream_data(true)
        } else {
            flow.stream_data(false)
        };
        if self.form_creds.len() < MAX_FORM_CREDS
            && reqs.iter().any(|r| r.complete)
            && creds::form_password_hit(head)
        {
            let host = reqs.first().and_then(|r| r.host.as_deref()).unwrap_or("?");
            self.form_creds.push(format!("{client} → {host}"));
        }
    }

    /// Recover response bodies as file-like objects — the download view.
    /// Bounded: 64 objects, 8 MB total; bodies beyond the reassembly cap
    /// are skipped rather than saved as broken prefixes.
    fn carve_objects(
        &mut self,
        key: &FlowKey,
        flow: &crate::flow::Flow,
        va: &[(usize, http::HttpMsg)],
        vb: &[(usize, http::HttpMsg)],
    ) {
        // Requests carry host/path; responses carry the bytes. The
        // response stream is the opposite direction from the request.
        let req_meta = |msgs: &[(usize, http::HttpMsg)], i: usize| {
            msgs.iter()
                .filter(|(_, m)| matches!(m.kind, http::HttpKind::Request { .. }))
                .nth(i)
                .map(|(_, m)| match &m.kind {
                    http::HttpKind::Request { path, .. } => (m.host.clone(), Some(path.clone())),
                    _ => (None, None),
                })
        };
        for (msgs, stream, client_is_a, req_side) in [
            (va, flow.stream_data(true), false, vb),
            (vb, flow.stream_data(false), true, va),
        ] {
            let mut ri = 0usize;
            for (off, m) in msgs {
                let http::HttpKind::Response { .. } = m.kind else {
                    continue;
                };
                // Content-Length → slice the body; chunked → decode it.
                let (body, truncated): (Vec<u8>, bool) =
                    if let Some(cl) = m.content_length.filter(|&n| n > 0) {
                        let Some(start) = off.checked_add(m.body_off) else {
                            continue;
                        };
                        let Some(end) = start.checked_add(cl) else {
                            continue;
                        };
                        if end > stream.len() {
                            continue; // body split past the reassembly cap
                        }
                        (stream[start..end].to_vec(), false)
                    } else if m.chunked {
                        let Some(start) = off.checked_add(m.body_off) else {
                            continue;
                        };
                        if start > stream.len() {
                            continue;
                        }
                        let (decoded, complete) = http::dechunk(&stream[start..]);
                        if decoded.is_empty() {
                            continue;
                        }
                        (decoded, !complete)
                    } else {
                        continue;
                    };
                if self.objects.len() >= 64 || self.objects_bytes + body.len() > 8 << 20 {
                    self.dropped.objects += 1;
                    continue;
                }
                let mime = magic::sniff(&body)
                    .map(str::to_string)
                    .or_else(|| m.content_type.clone())
                    .unwrap_or_else(|| "bin".into());
                let (host, path) = req_meta(req_side, ri).unwrap_or((None, None));
                let (client, server) = if client_is_a {
                    (key.a_ip, key.b_ip)
                } else {
                    (key.b_ip, key.a_ip)
                };
                self.objects_bytes += body.len();
                self.objects.push(CarvedOut {
                    id: None,
                    ts: flow.first_ts,
                    client,
                    server,
                    host,
                    path,
                    mime,
                    size: body.len(),
                    truncated,
                    data: body,
                });
                ri += 1;
            }
        }
    }

    fn assemble(mut self) -> Report {
        let mut findings = Vec::new();
        findings.extend(detect::port_scans(&self.scan));
        findings.extend(detect::dns_tunnels(&self.dns));
        findings.extend(detect::arp_spoof(&self.arp_claims));
        findings.extend(detect::tls_flags(&self.tls, self.last_ts));
        findings.extend(detect::beacons(&self.flows));
        findings.extend(detect::cleartext_sessions(&self.flows));
        if let Some(f) = detect::cleartext(&self.creds) {
            findings.push(f);
        }
        for hit in self.form_creds.iter().take(10) {
            findings.push(Finding {
                severity: Severity::Warn,
                kind: "form-creds",
                title: format!("Password field in HTTP request: {hit}"),
                detail: "A form credential crossed HTTP in cleartext.".into(),
                evidence: vec![hit.clone()],
            });
        }

        // Conversations: unordered host pairs ranked by bytes.
        let mut convos: FastMap<(IpAddr, IpAddr), ConvoAcc> = FastMap::default();
        for (k, f) in self.flows.iter() {
            let pair = (k.a_ip.min(k.b_ip), k.a_ip.max(k.b_ip));
            let c = convos.entry(pair).or_default();
            c.pkts += f.pkts;
            c.bytes += f.bytes;
            c.protos.insert(k.proto);
            *c.port_counts.entry(k.service_port()).or_default() += f.bytes;
        }
        let mut conversations: Vec<Conversation> = convos
            .into_iter()
            .map(|((a, b), c)| {
                let mut ports: Vec<(u16, u64)> = c.port_counts.into_iter().collect();
                ports.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
                Conversation {
                    a,
                    b,
                    pkts: c.pkts,
                    bytes: c.bytes,
                    protos: c.protos.iter().map(|&p| Proto::from_u8(p)).collect(),
                    top_ports: ports.into_iter().take(8).map(|(p, _)| p).collect(),
                }
            })
            .collect();
        conversations.sort_by_key(|c| std::cmp::Reverse(c.bytes));
        conversations.truncate(self.limits.top_conversations);

        // Listening ports: in a flow, the well-known endpoint is the one
        // being served. Multi-packet flows only — a lone SYN is a probe.
        let mut listen: FastMap<IpAddr, BTreeSet<u16>> = FastMap::default();
        for (k, f) in self.flows.iter() {
            if f.pkts < 2 {
                continue;
            }
            for (ip, port) in [(k.a_ip, k.a_port), (k.b_ip, k.b_port)] {
                if service_port_wellknown(port) && listen.get(&ip).is_none_or(|s| s.len() < 32) {
                    listen.entry(ip).or_default().insert(port);
                }
            }
        }

        // Host stats, ranked by bytes, with ARP-derived MACs attached.
        let mut hosts: Vec<HostStat> = self
            .hosts
            .into_iter()
            .map(|(ip, h)| {
                let mac = match ip {
                    IpAddr::V4(v4) => self.arp_macs.get(&v4).map(fmt_mac),
                    _ => None,
                };
                let vendor = mac
                    .as_deref()
                    .and_then(ntod_core::oui::vendor_of)
                    .map(str::to_string);
                let ports = listen.remove(&ip).unwrap_or_default();
                HostStat {
                    os: os_hint(h.ttl),
                    device: device_class(&ports, vendor.as_deref(), &h.names),
                    ports: ports.into_iter().collect(),
                    vendor,
                    mac,
                    ip,
                    pkts: h.pkts,
                    bytes: h.bytes,
                    first_ts: h.first_ts,
                    last_ts: h.last_ts,
                    names: h.names,
                }
            })
            .collect();
        hosts.sort_by_key(|h| std::cmp::Reverse(h.bytes));
        hosts.truncate(self.limits.top_hosts);

        findings.extend(detect::heavy_hitters(&hosts));

        self.dropped.flow_keys = self.flows.overflow_keys;
        Report {
            meta: Meta {
                packets: self.packets,
                bytes: self.bytes,
                first_ts: if self.first_ts == i64::MAX {
                    0
                } else {
                    self.first_ts
                },
                last_ts: self.last_ts,
                duration_ms: if self.first_ts == i64::MAX {
                    0
                } else {
                    self.last_ts - self.first_ts
                },
                linktypes: self.linktypes,
                capture_id: None,
                export_partial: false,
                dropped: self.dropped,
            },
            hosts,
            conversations,
            dns: self.dns,
            http: self.http,
            tls: self.tls,
            dhcp: self.dhcp_events,
            credentials: self.creds,
            objects: self.objects,
            findings,
        }
    }
}

#[derive(Default)]
struct ConvoAcc {
    pkts: u64,
    bytes: u64,
    protos: FastSet<u8>,
    port_counts: FastMap<u16, u64>,
}

/// TCP flag bits in the classic FIN|SYN|RST|PSH|ACK|URG|ECE|CWR layout.
fn tcp_flags(t: &TcpHeaderSlice<'_>) -> u8 {
    (t.fin() as u8)
        | (t.syn() as u8) << 1
        | (t.rst() as u8) << 2
        | (t.psh() as u8) << 3
        | (t.ack() as u8) << 4
        | (t.urg() as u8) << 5
        | (t.ece() as u8) << 6
        | (t.cwr() as u8) << 7
}

/// Strip link layer → (ethertype, L3 bytes). Unsupported → None.
fn strip_l2(linktype: u16, b: &[u8]) -> Option<(u16, &[u8])> {
    match linktype {
        // DLT_RAW — raw IP datagram.
        101 => match b.first()? >> 4 {
            4 => Some((0x0800, b)),
            6 => Some((0x86DD, b)),
            _ => None,
        },
        // DLT_EN10MB — Ethernet II (with 802.1Q tag skip).
        1 => {
            if b.len() < 14 {
                return None;
            }
            let mut et = u16::from_be_bytes([b[12], b[13]]);
            let mut off = 14;
            while et == 0x8100 || et == 0x88a8 {
                if b.len() < off + 4 {
                    return None;
                }
                et = u16::from_be_bytes([b[off + 2], b[off + 3]]);
                off += 4;
            }
            Some((et, &b[off..]))
        }
        // DLT_LINUX_SLL — 16B header, protocol at 14.
        113 => {
            if b.len() < 16 {
                return None;
            }
            Some((u16::from_be_bytes([b[14], b[15]]), &b[16..]))
        }
        // DLT_LINUX_SLL2 — 20B header, protocol at 0.
        276 => {
            if b.len() < 20 {
                return None;
            }
            Some((u16::from_be_bytes([b[0], b[1]]), &b[20..]))
        }
        // DLT_NULL — 4-byte address family.
        0 => {
            if b.len() < 4 {
                return None;
            }
            let fam = u32::from_le_bytes(b[0..4].try_into().ok()?);
            match fam {
                2 => Some((0x0800, &b[4..])),
                10 | 24 | 28 | 30 => Some((0x86DD, &b[4..])),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Strip IP layer → (src, dst, next_proto, L4 bytes).
/// Well-known + common LAN service ports worth listing on a host —
/// ephemeral ports above these are client-side noise.
fn service_port_wellknown(p: u16) -> bool {
    p < 1024
        || matches!(
            p,
            1433 | 1521
                | 1883
                | 3000
                | 3306
                | 3389
                | 5000
                | 5001
                | 5060
                | 5353
                | 5432
                | 5900
                | 6379
                | 8000
                | 8080
                | 8443
                | 8554
                | 8883
                | 9000
                | 9100
                | 9101
                | 9200
                | 11211
                | 27017
        )
}

/// OS family from the highest observed TTL — the standard initials are
/// 255 (network/embedded), 128 (Windows), 64 (Unix-likes), and hops
/// only ever subtract.
fn os_hint(ttl: u8) -> Option<&'static str> {
    match ttl {
        0 => None,
        1..=64 => Some("Unix-like"),
        65..=128 => Some("Windows"),
        _ => Some("network/IoT"),
    }
}

fn contains_ascii_ci(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    !n.is_empty() && h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Deterministic device class — Fing-style, but heuristic and honest
/// about it. Ordered by signal strength: names > distinctive ports >
/// vendor strings > service fingerprints.
fn device_class(
    ports: &BTreeSet<u16>,
    vendor: Option<&str>,
    names: &[Arc<str>],
) -> Option<&'static str> {
    let v = vendor.unwrap_or("");
    let v_has = |needle: &str| contains_ascii_ci(v, needle);
    let n_has = |needle: &str| names.iter().any(|s| contains_ascii_ci(s, needle));
    let has = |ps: &[u16]| ps.iter().any(|p| ports.contains(p));
    if n_has("iphone") || n_has("ipad") || n_has("android") || n_has("galaxy") {
        Some("mobile")
    } else if has(&[9100, 9101, 515, 631]) {
        Some("printer")
    } else if v_has("hikvision")
        || v_has("dahua")
        || v_has("axis")
        || v_has("reolink")
        || v_has("amcrest")
        || has(&[554, 8554])
    {
        Some("IP camera")
    } else if v_has("apple") || has(&[62078]) {
        Some("Apple device")
    } else if v_has("synology") || v_has("qnap") || has(&[5000, 5001]) {
        Some("NAS")
    } else if v_has("espressif") || v_has("tuya") || v_has("shelly") || has(&[1883]) {
        Some("IoT/embedded")
    } else if has(&[3389, 445, 139]) {
        Some("Windows host")
    } else if has(&[53, 67]) && ports.len() <= 4 {
        Some("router")
    } else if has(&[22, 23]) {
        Some("server/embedded")
    } else {
        (!v.is_empty() || !ports.is_empty()).then_some("generic host")
    }
}

fn strip_l3(etype: u16, b: &[u8]) -> Option<(IpAddr, IpAddr, u8, u8, &[u8])> {
    if etype == 0x0800 {
        let ip = Ipv4HeaderSlice::from_slice(b).ok()?;
        let l4 = &b[ip.slice().len()..];
        let (s, d) = (ip.source_addr(), ip.destination_addr());
        let p: u8 = ip.protocol().into();
        Some((s.into(), d.into(), p, ip.ttl(), l4))
    } else if etype == 0x86DD {
        let ip = Ipv6HeaderSlice::from_slice(b).ok()?;
        // shortcut: extension headers aren't walked — L4 is missed on those.
        let l4 = &b[ip.slice().len()..];
        let (s, d) = (ip.source_addr(), ip.destination_addr());
        Some((
            s.into(),
            d.into(),
            u8::from(ip.next_header()),
            ip.hop_limit(),
            l4,
        ))
    } else {
        None
    }
}
