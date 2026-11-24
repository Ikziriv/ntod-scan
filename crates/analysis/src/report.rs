//! Report model — what `analyze()` produces. Everything serializable,
//! everything capped: a report is a summary, never the whole capture.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

use ntod_core::Proto;
use serde::Serialize;

/// "aa:bb:cc:dd:ee:ff" — MACs stay as 6 octets on the wire side and
/// become strings only at the report boundary.
pub(crate) fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Hard bounds so one upload can't pin unbounded memory.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_dns: usize,
    pub max_http: usize,
    pub max_tls: usize,
    pub max_dhcp: usize,
    pub max_hosts: usize,
    /// Report-side caps: top-N lists.
    pub top_hosts: usize,
    pub top_conversations: usize,
    /// Global head-buffer budget across all flows.
    pub head_budget: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_dns: 4_000,
            max_http: 4_000,
            max_tls: 4_000,
            max_dhcp: 1_000,
            max_hosts: 100_000,
            top_hosts: 500,
            top_conversations: 1_000,
            head_budget: 64 << 20, // 64 MiB
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Meta {
    pub packets: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub duration_ms: i64,
    /// DLTs observed in the capture.
    pub linktypes: Vec<u16>,
    /// Counts of items dropped by report caps.
    pub dropped: Dropped,
    /// Retained-capture id for pcap export, set by the API layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<u64>,
    /// True when the retained frames were budget-truncated — exports
    /// only cover the earlier part of the capture.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub export_partial: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Dropped {
    pub dns: u64,
    pub http: u64,
    pub tls: u64,
    pub dhcp: u64,
    pub objects: u64,
    pub flow_keys: u64,
    pub unsupported_frames: u64,
    /// Distinct scan sources beyond the scan-map bound.
    pub scan_srcs: u64,
    /// ARP replies beyond the claim-map bound.
    pub arp_ips: u64,
}

#[derive(Debug, Serialize)]
pub struct HostStat {
    pub ip: IpAddr,
    pub pkts: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub mac: Option<String>,
    /// NIC vendor from the MAC OUI prefix, when known.
    pub vendor: Option<String>,
    /// Names seen for this host (DHCP, reverse answers, TLS SNI peer).
    pub names: Vec<Arc<str>>,
    /// OS family guess from observed TTL (Fing-style passive signal).
    pub os: Option<&'static str>,
    /// Well-known ports this host served on, inferred from flows.
    pub ports: Vec<u16>,
    /// Device-class label from ports + vendor + names heuristics.
    pub device: Option<&'static str>,
}

/// A file-like object recovered from an HTTP response body.
/// `data` is never serialized — the API/CLI move it out and set `id`.
#[derive(Debug, Serialize)]
pub struct CarvedOut {
    /// Store id, assigned by the API layer after extraction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub ts: i64,
    pub client: IpAddr,
    pub server: IpAddr,
    pub host: Option<String>,
    pub path: Option<String>,
    /// Magic-byte sniffed type (falls back to declared content-type).
    pub mime: String,
    pub size: usize,
    /// Truncated at the stream cap — the object is a prefix of the file.
    pub truncated: bool,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Conversation {
    pub a: IpAddr,
    pub b: IpAddr,
    pub pkts: u64,
    pub bytes: u64,
    pub protos: Vec<Proto>,
    /// Up to 8 busiest destination ports on the pair.
    pub top_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsEvent {
    pub ts: i64,
    pub client: IpAddr,
    pub server: IpAddr,
    /// "dns" | "mdns" | "llmnr" | "nbns"
    pub service: &'static str,
    /// Interned — repeated query names share one allocation.
    pub name: Arc<str>,
    pub qtype: Cow<'static, str>,
    pub is_response: bool,
    /// RCODE on responses (3 = NXDOMAIN).
    pub rcode: Option<u8>,
    pub answers: Vec<Arc<str>>,
}

/// One HTTP request paired with its response when the capture saw both —
/// the exchange view A-Packets calls "what did clients ask for, and what
/// came back". `status` is None when only the request was seen.
#[derive(Debug, Clone, Serialize)]
pub struct HttpExchange {
    pub ts: i64,
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub method: Option<Arc<str>>,
    pub host: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
    pub user_agent: Option<Arc<str>>,
    pub status: Option<u16>,
    pub content_type: Option<Arc<str>>,
    pub location: Option<Arc<str>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertOut {
    pub subject_cn: Option<Arc<str>>,
    pub issuer_cn: Option<Arc<str>>,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub self_signed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsEvent {
    pub first_ts: i64,
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub sni: Option<Arc<str>>,
    /// JA3 (client) / JA3S (server) fingerprints, md5 hex.
    pub ja3: Option<Arc<str>>,
    pub ja3s: Option<Arc<str>>,
    /// JA4 / JA4S fingerprints (FoxIO format) — survive clients that
    /// randomize extension order, which JA3 can't.
    pub ja4: Option<Arc<str>>,
    pub ja4s: Option<Arc<str>>,
    pub client_version: Option<u16>,
    pub server_version: Option<u16>,
    pub cipher: Option<u16>,
    pub certs: Vec<CertOut>,
    pub heartbeat: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpEvent {
    pub ts: i64,
    pub client_mac: Arc<str>,
    pub msg_type: &'static str,
    pub yiaddr: IpAddr,
    pub hostname: Option<Arc<str>>,
    pub requested: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialOut {
    pub ts: i64,
    pub proto: &'static str,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub user: Arc<str>,
    /// Masked secret — never the real value.
    pub secret: Arc<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Alert,
}

/// A triage finding — the "start with signal, not noise" layer.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine key, e.g. "port-scan", "dns-tunnel".
    pub kind: &'static str,
    pub title: String,
    pub detail: String,
    /// Up to a few concrete pointers (IPs, names, flows).
    pub evidence: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub meta: Meta,
    pub hosts: Vec<HostStat>,
    pub conversations: Vec<Conversation>,
    pub dns: Vec<DnsEvent>,
    pub http: Vec<HttpExchange>,
    pub tls: Vec<TlsEvent>,
    pub dhcp: Vec<DhcpEvent>,
    pub credentials: Vec<CredentialOut>,
    /// Files recovered from HTTP response bodies (bounded).
    pub objects: Vec<CarvedOut>,
    pub findings: Vec<Finding>,
}
