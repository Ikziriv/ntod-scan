//! Fing-tier enrichment: hostname, vendor, open ports per host.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::{arp, model::Host};

/// Upper bound on concurrent enrichment workers so large subnets never exhaust OS threads.
const MAX_ENRICH_WORKERS: usize = 64;

/// Common ports probed per host — service fingerprint, not full scan.
pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9100, 554,
];

/// Reverse-DNS name for `ip`, if one exists.
pub fn hostname(ip: Ipv4Addr) -> Option<String> {
    dns_lookup::lookup_addr(&ip.into())
        .ok()
        .map(|n| n.trim_end_matches('.').to_string())
}

/// Open TCP ports from `TOP_PORTS`, sequential connect with `timeout` each.
pub fn open_ports(ip: Ipv4Addr, timeout: Duration) -> Vec<u16> {
    TOP_PORTS
        .iter()
        .copied()
        .filter(|&p| TcpStream::connect_timeout(&SocketAddr::new(ip.into(), p), timeout).is_ok())
        .collect()
}

/// Fill MAC (ARP cache → active probe), vendor, hostname, and open
/// ports using a bounded worker pool. Port connects run first — their
/// SYNs seed the ARP cache, so the table read afterwards sees nearly
/// every live host even before per-host probing.
pub fn enrich(hosts: &mut Vec<Host>) {
    if hosts.is_empty() {
        return;
    }
    let arp_map = arp::arp_table().unwrap_or_default();
    let queue = Mutex::new(std::mem::take(hosts));
    let done = Mutex::new(Vec::with_capacity(
        queue.lock().map(|q| q.len()).unwrap_or(0),
    ));
    let n_workers = queue
        .lock()
        .map(|q| q.len().min(MAX_ENRICH_WORKERS))
        .unwrap_or(1)
        .max(1);

    let arp_map = &arp_map;
    thread::scope(|s| {
        for _ in 0..n_workers {
            let (queue, done) = (&queue, &done);
            s.spawn(move || {
                loop {
                    let mut h = match queue.lock().ok().and_then(|mut q| q.pop()) {
                        Some(h) => h,
                        None => return,
                    };
                    h.open_ports = open_ports(h.ip, Duration::from_millis(150));
                    if h.mac.is_none() {
                        h.mac = arp_map.get(&h.ip).cloned().or_else(|| arp::probe(h.ip));
                    }
                    h.vendor = h
                        .mac
                        .as_deref()
                        .and_then(crate::oui::vendor_of)
                        .map(str::to_string);
                    h.hostname = hostname(h.ip)
                        .or_else(|| crate::names::nbns_name(h.ip))
                        .or_else(|| crate::names::mdns_name(h.ip));
                    if let Ok(mut out) = done.lock() {
                        out.push(h);
                    }
                }
            });
        }
    });

    if let Ok(mut out) = done.into_inner() {
        out.sort_unstable();
        *hosts = out;
    }
}
