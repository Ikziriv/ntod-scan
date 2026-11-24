//! Host discovery: bounded parallel ping sweep over a subnet.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ipnetwork::Ipv4Network;

use crate::error::Error;
use crate::model::Host;

/// Hard upper bound on concurrent ping worker threads.
pub const MAX_WORKERS: usize = 256;
/// Hard upper bound on hosts probed in one sweep (/16).
pub const MAX_SCAN_HOSTS: u32 = 65_536;

/// The IPv4 of the primary interface, chosen by the routing table.
fn local_ip() -> Result<Ipv4Addr, Error> {
    // UDP "connect" just picks the route; nothing is sent.
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.connect((Ipv4Addr::new(203, 0, 113, 1), 80))?; // TEST-NET-3
    let IpAddr::V4(ip) = sock.local_addr()?.ip() else {
        return Err(Error::NoLocalAddr);
    };
    Ok(ip)
}

/// The /24 the primary interface is on.
///
/// shortcut: assumes /24; pass `--subnet` explicitly for other masks.
pub fn local_subnet() -> Result<Ipv4Network, Error> {
    Ok(Ipv4Network::new(local_ip()?, 24)?)
}

/// Start a host sweep; hosts arrive on the returned channel as found.
/// With `workers` concurrent probes (clamped to `1..=MAX_WORKERS`).
/// Channel closes when the sweep ends.
pub fn scan_stream(subnet: Ipv4Network, timeout: Duration, workers: usize) -> mpsc::Receiver<Host> {
    scan_stream_cancellable(subnet, timeout, workers, true, None)
}

/// Like [`scan_stream`], but workers exit early when `cancel` becomes `true`
/// or when the returned receiver is dropped. `arp` toggles the
/// ARP-first probe on on-link subnets (SendARP costs ~1-3s per dead IP —
/// pass `false` when sweep speed matters more than ICMP-hidden hosts).
pub fn scan_stream_cancellable(
    subnet: Ipv4Network,
    timeout: Duration,
    workers: usize,
    arp: bool,
    cancel: Option<Arc<AtomicBool>>,
) -> mpsc::Receiver<Host> {
    let (tx, rx) = mpsc::channel();
    let (start, count) = target_range(subnet);
    if count == 0 {
        return rx;
    }
    let next = Arc::new(AtomicU32::new(0));
    let n_workers = workers.clamp(1, MAX_WORKERS).min(count as usize);
    // ARP probes only make sense on-link — off-link they would resolve
    // the gateway and phantom-report every IP as up.
    let on_link = arp && local_ip().is_ok_and(|ip| subnet.contains(ip));
    for _ in 0..n_workers {
        let tx = tx.clone();
        let next = next.clone();
        let cancel = cancel.clone();
        thread::spawn(move || {
            loop {
                if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= count {
                    return;
                }
                let ip = Ipv4Addr::from(start.wrapping_add(i));
                let found = probe_host(ip, timeout, on_link);
                if let Some(h) = found
                    && tx.send(h).is_err()
                {
                    return;
                }
            }
        });
    }
    rx
}

/// Sweep `subnet` and collect the results, sorted by IP.
/// `arp` toggles ARP-first probing — see [`scan_stream_cancellable`].
pub fn scan(subnet: Ipv4Network, timeout: Duration, workers: usize, arp: bool) -> Vec<Host> {
    let mut found: Vec<Host> = scan_stream_cancellable(subnet, timeout, workers, arp, None)
        .iter()
        .collect();
    found.sort_unstable();
    found
}

/// Zero-allocation `(first_host_u32, host_count)` for `subnet`, skipping
/// network & broadcast on subnets larger than `/31` and capping at `MAX_SCAN_HOSTS`.
fn target_range(subnet: Ipv4Network) -> (u32, u32) {
    let base = u32::from(subnet.network());
    let size = subnet.size();
    if size > 2 {
        (base.wrapping_add(1), (size - 2).min(MAX_SCAN_HOSTS))
    } else {
        (base, size)
    }
}

fn ping_one(ip: Ipv4Addr, timeout: Duration) -> Result<(), Error> {
    ping::new(ip.into())
        .timeout(timeout)
        .ttl(128)
        .send()
        .map_err(|_| Error::Probe)
        .map(|_| ())
}

/// Up-detection: ARP answers what ICMP hides — every live LAN host must
/// reply to ARP, and the reply carries its MAC for free. On Windows the
/// probe is SendARP; on Unix it's a heavier UDP+`arp -a` round-trip, so
/// ARP-first only runs there when the sweep targets the on-link subnet.
fn probe_host(ip: Ipv4Addr, timeout: Duration, on_link: bool) -> Option<Host> {
    if on_link && let Some(mac) = crate::arp::probe(ip) {
        let mut h = Host::new(ip);
        h.mac = Some(mac);
        return Some(h);
    }
    ping_one(ip, timeout).ok().map(|_| Host::new(ip))
}
