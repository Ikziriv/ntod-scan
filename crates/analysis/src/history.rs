//! Longitudinal context — the thing upload-only analyzers can't have:
//! a local memory of who's been on this network. Bounded JSON snapshot
//! in the data dir; updated only by *live* captures (uploaded files are
//! someone else's network, not history).

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::FastSet;
use crate::report::{Finding, Report, Severity};

/// Device memory cap — a LAN beyond this is an ISP, not a home/branch.
const MAX_DEVICES: usize = 512;
/// Baselines cap, same reasoning.
const MAX_BASELINES: usize = 512;
/// Re-alert cooldown per MAC — one "new device" ping a day max.
const REALERT_MS: i64 = 24 * 3600 * 1000;
/// EWMA weight for the per-host rate baseline.
const ALPHA: f64 = 0.3;
/// Baseline needs this many observations before it can accuse.
const MIN_SESSIONS: u32 = 3;
/// Contact bookkeeping caps.
const MAX_CONTACT_HOSTS: usize = 512;
const MAX_CONTACTS_PER_HOST: usize = 128;
/// Persisted alert-log depth.
const MAX_LOG: usize = 200;
/// Per-observe cap so one capture can't flood the feed.
const MAX_NEW_PEER: usize = 8;
/// External-name memory cap — a LAN resolves a lot of destinations.
const MAX_NAMES: usize = 4096;
/// Ordinary-egress ports — a new peer on these is just browsing, so the
/// finding only fires for relationships on anything else.
const WEB_PORTS: &[u16] = &[53, 80, 123, 443, 853, 8530];

#[derive(Debug, Serialize, Deserialize)]
struct DevRec {
    ips: Vec<String>,
    vendor: Option<String>,
    /// Heuristic device class (printer/camera/…) — serde(default) for
    /// files written before this field existed.
    #[serde(default)]
    device: Option<String>,
    first_seen: i64,
    last_seen: i64,
    /// Last time we emitted a new-device finding for it.
    last_alert: i64,
}

/// One remembered device, as returned by [`History::devices`].
#[derive(Debug, Serialize)]
pub struct DevInfo {
    pub mac: String,
    pub ips: Vec<String>,
    pub vendor: Option<String>,
    pub device: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Base {
    /// Bytes/sec EWMA across observed sessions.
    rate: f64,
    n: u32,
}

/// One line of the persisted alert log — findings that survive the
/// capture that produced them (Fing's notification timeline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRec {
    pub ts: i64,
    pub kind: String,
    pub severity: String,
    pub title: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Disk {
    devices: HashMap<String, DevRec>,
    baselines: HashMap<IpAddr, Base>,
    /// LAN IP → external IPs it has ever talked to (bounded sets).
    #[serde(default)]
    contacts: HashMap<IpAddr, BTreeSet<IpAddr>>,
    /// Recent findings across captures, newest last, capped.
    #[serde(default)]
    log: Vec<AlertRec>,
    /// External IP → name learned from observed DNS answers or TLS SNI.
    /// Powers named findings and the never-resolved check.
    #[serde(default)]
    names: HashMap<IpAddr, String>,
}

/// A loaded history store — open, [`observe`] reports, `save()`.
pub struct History {
    path: PathBuf,
    disk: Disk,
}

impl History {
    /// Load `<dir>/history.json` or start empty; the file is created on save.
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("history.json");
        let disk = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { path, disk }
    }

    /// Fold a finished live report into memory and return any findings it
    /// triggers (new devices, rate anomalies). Pure observations — nothing
    /// from `r` is mutated.
    pub fn observe(&mut self, r: &Report, now: i64) -> Vec<Finding> {
        let mut out = Vec::new();
        let dur_s = (r.meta.duration_ms.max(1) as f64) / 1000.0;

        for h in &r.hosts {
            // New-device detection is keyed on MAC — IPs roam, NICs don't.
            if let Some(mac) = &h.mac {
                match self.disk.devices.get_mut(mac) {
                    Some(rec) => {
                        // A known device silent for a day+ that reappears
                        // is worth a note — could also be a spoofed MAC.
                        let since_seen = now.saturating_sub(rec.last_seen);
                        if since_seen > REALERT_MS
                            && now.saturating_sub(rec.last_alert) > REALERT_MS
                        {
                            out.push(Finding {
                                severity: Severity::Info,
                                kind: "device-returned",
                                title: format!(
                                    "{} returned after {}h away",
                                    h.ip,
                                    since_seen / 3_600_000
                                ),
                                detail: format!(
                                    "MAC {mac} was last seen {}h ago — a long-silent \
                                     device (or something borrowing its identity).",
                                    since_seen / 3_600_000
                                ),
                                evidence: vec![mac.clone()],
                            });
                            rec.last_alert = now;
                        }
                        rec.last_seen = now;
                        if rec.device.is_none() {
                            rec.device = h.device.map(str::to_string);
                        }
                        let ip = h.ip.to_string();
                        if !rec.ips.contains(&ip) {
                            if rec.ips.len() >= 4 {
                                rec.ips.remove(0);
                            }
                            rec.ips.push(ip);
                        }
                    }
                    None => {
                        if self.disk.devices.len() >= MAX_DEVICES {
                            continue;
                        }
                        let rec = DevRec {
                            ips: vec![h.ip.to_string()],
                            vendor: h.vendor.clone(),
                            device: h.device.map(str::to_string),
                            first_seen: now,
                            last_seen: now,
                            last_alert: now,
                        };
                        self.disk.devices.insert(mac.clone(), rec);
                        out.push(Finding {
                            severity: Severity::Warn,
                            kind: "new-device",
                            title: format!(
                                "New device joined: {}{}{}",
                                h.ip,
                                h.vendor
                                    .as_deref()
                                    .map(|v| format!(" ({v})"))
                                    .unwrap_or_default(),
                                h.device.map(|d| format!(" — {d}")).unwrap_or_default(),
                            ),
                            detail: format!(
                                "MAC {mac} has never been observed on this network \
                                 before this capture — verify it belongs."
                            ),
                            evidence: vec![
                                mac.clone(),
                                h.names.first().map(|s| s.to_string()).unwrap_or_default(),
                            ]
                            .into_iter()
                            .filter(|s| !s.is_empty())
                            .collect(),
                        });
                    }
                }
            }

            // Rate baseline per IP — only meaningful on live captures
            // with a real duration.
            if dur_s >= 5.0 && h.bytes > 0 {
                let rate = h.bytes as f64 / dur_s;
                let ip = h.ip;
                if !self.disk.baselines.contains_key(&ip) {
                    if self.disk.baselines.len() >= MAX_BASELINES {
                        // Keep the trained ones; unproven entries go first.
                        self.disk.baselines.retain(|_, b| b.n >= MIN_SESSIONS);
                    }
                    if self.disk.baselines.len() >= MAX_BASELINES {
                        continue;
                    }
                }
                let base = self.disk.baselines.entry(ip).or_default();
                if base.n >= MIN_SESSIONS
                    && base.rate > 0.0
                    && rate > base.rate * 4.0
                    && h.bytes > 1_000_000
                {
                    out.push(Finding {
                        severity: Severity::Info,
                        kind: "rate-anomaly",
                        title: format!("{ip} is moving {:.0}× its baseline rate", rate / base.rate),
                        detail: format!(
                            "{ip} averaged {:.0} B/s over {} prior sessions; this \
                             one ran at {:.0} B/s — a burst worth a look.",
                            base.rate, base.n, rate
                        ),
                        evidence: vec![format!("{} bytes in {:.0}s", h.bytes, dur_s)],
                    });
                }
                base.rate = if base.n == 0 {
                    rate
                } else {
                    base.rate * (1.0 - ALPHA) + rate * ALPHA
                };
                base.n = base.n.saturating_add(1);
            }
        }

        // External-name memory: DNS answers and TLS SNI both tell us what
        // an outside IP is called — learned *before* the contact check so
        // this session's resolutions count.
        for d in &r.dns {
            if !d.is_response {
                continue;
            }
            for a in &d.answers {
                if let Ok(ip) = a.parse::<IpAddr>()
                    && self.disk.names.len() < MAX_NAMES
                {
                    self.disk
                        .names
                        .entry(ip)
                        .or_insert_with(|| d.name.to_string());
                }
            }
        }
        for t in &r.tls {
            if let Some(sni) = &t.sni
                && self.disk.names.len() < MAX_NAMES
            {
                self.disk
                    .names
                    .entry(t.server)
                    .or_insert_with(|| sni.to_string());
            }
        }

        // External-relationship memory: record every LAN↔outside contact
        // (bounded), and flag *new* non-web peers — but only for hosts
        // whose contact set predates this session, otherwise a first
        // capture is all new and all noise.
        if !r.conversations.is_empty() {
            let mut newly_added_lan: FastSet<IpAddr> = FastSet::default();
            let mut new_peer = 0usize;
            for c in &r.conversations {
                let Some((lan, ext)) = lan_peer(c.a, c.b) else {
                    continue;
                };
                let is_prior = if self.disk.contacts.contains_key(&lan) {
                    !newly_added_lan.contains(&lan)
                } else {
                    if self.disk.contacts.len() >= MAX_CONTACT_HOSTS {
                        continue;
                    }
                    self.disk.contacts.insert(lan, BTreeSet::new());
                    newly_added_lan.insert(lan);
                    false
                };
                let Some(set) = self.disk.contacts.get_mut(&lan) else {
                    continue;
                };
                let inserted = set.insert(ext);
                let fresh = is_prior && inserted;
                while set.len() > MAX_CONTACTS_PER_HOST {
                    set.pop_first();
                }
                if fresh
                    && new_peer < MAX_NEW_PEER
                    && !c.top_ports.iter().all(|p| WEB_PORTS.contains(p))
                {
                    new_peer += 1;
                    // Name enrichment turns "talked to an IP" into "talked
                    // to X"; never-resolved is the hardcoded-IP smell.
                    let name = self.disk.names.get(&ext).cloned();
                    out.push(Finding {
                        severity: Severity::Warn,
                        kind: "new-peer",
                        title: format!(
                            "{lan} first-ever contact with {ext}{}",
                            name.as_deref()
                                .map(|n| format!(" ({n})"))
                                .unwrap_or_default()
                        ),
                        detail: match &name {
                            Some(n) => format!(
                                "{lan} has talked outside before, but never to {ext} \
                                 ({n}) — on ports {}. New relationship; verify it.",
                                c.top_ports
                                    .iter()
                                    .map(u16::to_string)
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ),
                            None => format!(
                                "{lan} contacted {ext} on ports {} and no DNS answer \
                                 or TLS name has ever been seen for that IP — \
                                 hardcoded-address behavior, a classic C2 trait.",
                                c.top_ports
                                    .iter()
                                    .map(u16::to_string)
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ),
                        },
                        evidence: name
                            .into_iter()
                            .chain([lan.to_string(), ext.to_string()])
                            .collect(),
                    });
                }
            }
        }

        // Persist this observe's findings into the alert log.
        self.disk.log.extend(out.iter().map(|f| AlertRec {
            ts: now,
            kind: f.kind.into(),
            severity: format!("{:?}", f.severity).to_lowercase(),
            title: f.title.clone(),
        }));
        if self.disk.log.len() > MAX_LOG {
            let excess = self.disk.log.len() - MAX_LOG;
            self.disk.log.drain(..excess);
        }
        out
    }

    /// Recent findings across captures, newest first.
    pub fn alerts(&self) -> Vec<AlertRec> {
        self.disk.log.iter().rev().cloned().collect()
    }

    /// The remembered devices, most recently seen first.
    pub fn devices(&self) -> Vec<DevInfo> {
        let mut v: Vec<DevInfo> = self
            .disk
            .devices
            .iter()
            .map(|(mac, r)| DevInfo {
                mac: mac.clone(),
                ips: r.ips.clone(),
                vendor: r.vendor.clone(),
                device: r.device.clone(),
                first_seen: r.first_seen,
                last_seen: r.last_seen,
            })
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        v
    }

    /// Persist — unique temp file + `sync_all` + atomic rename so a crash
    /// or concurrent writer can never leave a torn or truncated store.
    pub fn save(&self) -> std::io::Result<()> {
        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let payload = serde_json::to_vec(&self.disk).map_err(std::io::Error::other)?;
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .path
            .with_extension(format!("{}.{}.tmp", std::process::id(), seq));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&payload)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
    }
}

/// LAN addresses: private/link-local/loopback — things that belong here.
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unicast_link_local() || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        }
    }
}

/// A real external endpoint — not multicast, broadcast, unspecified, or
/// documentation space that never answers.
fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

/// Split a conversation into (lan, external); None when it isn't one.
fn lan_peer(a: IpAddr, b: IpAddr) -> Option<(IpAddr, IpAddr)> {
    match (is_lan(a), is_lan(b)) {
        (true, false) if is_routable(b) => Some((a, b)),
        (false, true) if is_routable(a) => Some((b, a)),
        _ => None,
    }
}

/// The data dir: `$NTOD_DATA_DIR` or `~/.ntod-scan`.
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("NTOD_DATA_DIR") {
        return d.into();
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .unwrap_or_default();
    PathBuf::from(home).join(".ntod-scan")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{HostStat, Meta};

    fn host(ip: &str, mac: Option<&str>, bytes: u64) -> HostStat {
        HostStat {
            ip: ip.parse().unwrap(),
            pkts: 1,
            bytes,
            first_ts: 0,
            last_ts: 0,
            mac: mac.map(str::to_string),
            vendor: Some("TestNic".into()),
            names: vec![],
            os: None,
            ports: vec![],
            device: None,
        }
    }

    fn report(hosts: Vec<HostStat>) -> Report {
        Report {
            meta: Meta {
                duration_ms: 10_000,
                ..Default::default()
            },
            hosts,
            ..Default::default()
        }
    }

    #[test]
    fn new_device_alerts_once() {
        let dir = std::env::temp_dir().join("ntod-hist-test");
        let _ = std::fs::remove_file(dir.join("history.json"));
        let mut h = History::open(&dir);
        let r = report(vec![host("10.0.0.7", Some("aa:bb:cc:dd:ee:ff"), 100)]);
        let f = h.observe(&r, 1000);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "new-device");
        // Second observation of the same MAC — no alert.
        let r2 = report(vec![host("10.0.0.7", Some("aa:bb:cc:dd:ee:ff"), 100)]);
        assert!(h.observe(&r2, 2000).is_empty());
        // Round-trip through disk.
        h.save().unwrap();
        let mut h2 = History::open(&dir);
        assert!(h2.observe(&r2, 3000).is_empty());
        let _ = std::fs::remove_file(dir.join("history.json"));
    }

    #[test]
    fn rate_anomaly_after_baseline() {
        let dir = std::env::temp_dir().join("ntod-hist-test2");
        let _ = std::fs::remove_file(dir.join("history.json"));
        let mut h = History::open(&dir);
        // Three calm sessions establish the baseline (10s each).
        for i in 0..3 {
            let r = report(vec![host("10.0.0.8", None, 100_000)]);
            assert!(h.observe(&r, i * 10_000).is_empty());
        }
        // A 40× burst trips it.
        let r = report(vec![host("10.0.0.8", None, 40_000_000)]);
        let f = h.observe(&r, 40_000);
        assert!(f.iter().any(|x| x.kind == "rate-anomaly"));
        let _ = std::fs::remove_file(dir.join("history.json"));
    }

    fn conv(a: &str, b: &str, ports: &[u16]) -> crate::report::Conversation {
        crate::report::Conversation {
            a: a.parse().unwrap(),
            b: b.parse().unwrap(),
            pkts: 10,
            bytes: 1000,
            protos: vec![],
            top_ports: ports.to_vec(),
        }
    }

    #[test]
    fn new_peer_only_after_baseline_session() {
        let dir = std::env::temp_dir().join("ntod-hist-test3");
        let _ = std::fs::remove_file(dir.join("history.json"));
        let mut h = History::open(&dir);

        // First capture: every relationship is new — must stay quiet.
        let mut r = report(vec![]);
        r.conversations = vec![conv("10.0.0.9", "45.33.32.156", &[4444])];
        assert!(h.observe(&r, 1000).is_empty());

        // Second capture: the odd-port peer was already known — quiet;
        // a *new* odd-port peer flags, a new 443 peer doesn't. A DNS
        // answer in the same capture names the peer in the finding.
        let mut r2 = report(vec![]);
        r2.conversations = vec![
            conv("10.0.0.9", "45.33.32.156", &[4444]),
            conv("10.0.0.9", "104.21.5.19", &[8443]),
            conv("10.0.0.9", "93.184.216.34", &[443]),
        ];
        r2.dns = vec![crate::report::DnsEvent {
            ts: 0,
            client: "10.0.0.9".parse().unwrap(),
            server: "8.8.8.8".parse().unwrap(),
            service: "dns",
            name: "cdn.example.net".into(),
            qtype: "A".into(),
            is_response: true,
            rcode: Some(0),
            answers: vec!["104.21.5.19".into()],
        }];
        let f = h.observe(&r2, 2000);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "new-peer");
        assert!(f[0].title.contains("104.21.5.19 (cdn.example.net)"));

        // Third capture: another new odd-port peer, never DNS-resolved —
        // the detail calls out the hardcoded-IP smell.
        let mut r3 = report(vec![]);
        r3.conversations = vec![conv("10.0.0.9", "185.220.101.4", &[9001])];
        let f3 = h.observe(&r3, 3000);
        assert_eq!(f3.len(), 1);
        assert!(f3[0].detail.contains("hardcoded-address"));

        // Alert log persisted sessions' findings.
        assert!(h.alerts().iter().any(|a| a.kind == "new-peer"));
        let _ = std::fs::remove_file(dir.join("history.json"));
    }
}
