//! OS ARP cache lookup — fills in MAC addresses after a scan.
//!
//! shortcut: parses `arp -a` output instead of a proper ARP resolver;
//! replace with a raw-ARP scan once the pcap engine lands.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use crate::model::Host;

/// Read the OS ARP cache as ip -> mac. Handles both
/// `aa-bb-cc-dd-ee-ff` (Windows) and `aa:bb:...` (Unix) formats.
pub fn arp_table() -> std::io::Result<HashMap<Ipv4Addr, String>> {
    let out = Command::new("arp").arg("-a").output()?;
    Ok(parse_arp_output(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_arp_output(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = HashMap::new();
    for line in text.lines() {
        let mut ip_addr = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let clean = tok.trim_matches(['(', ')']);
            if ip_addr.is_none()
                && let Ok(ip) = clean.parse::<Ipv4Addr>()
            {
                ip_addr = Some(ip);
                continue;
            }
            if is_mac(clean) {
                mac = Some(clean.to_string());
            }
        }
        if let (Some(ip), Some(mac)) = (ip_addr, mac) {
            table.insert(ip, mac);
        }
    }
    table
}

fn is_mac(t: &str) -> bool {
    let mut count = 0usize;
    for p in t.split(['-', ':']) {
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        count += 1;
    }
    count == 6
}

/// Fill `Host::mac` for every host found in the ARP cache.
pub fn enrich(hosts: &mut [Host]) {
    if let Ok(table) = arp_table() {
        for h in hosts.iter_mut() {
            h.mac = table.get(&h.ip).cloned();
        }
    }
}

/// Actively resolve `ip`'s MAC via ARP — sends real ARP traffic, so it
/// finds hosts the OS cache hasn't heard from yet, including ones that
/// drop ICMP. On-link targets only: for off-link IPs the resolver
/// returns the next-hop gateway's MAC, which would masquerade as a host.
pub fn probe(ip: Ipv4Addr) -> Option<String> {
    platform::probe(ip)
}

#[cfg(windows)]
mod platform {
    use std::net::Ipv4Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

    /// SendARP — the OS resolver's own primitive; no admin, no Npcap.
    pub(super) fn probe(ip: Ipv4Addr) -> Option<String> {
        let mut mac = [0u8; 8];
        let mut len = mac.len() as u32;
        // SendARP takes DestIP as in_addr.s_addr — network byte order,
        // i.e. memory layout [a,b,c,d].
        let dest = u32::from_ne_bytes(ip.octets());
        let rc = unsafe { SendARP(dest, 0, mac.as_mut_ptr().cast(), &mut len) };
        if rc != 0 || len < 6 {
            return None;
        }
        Some(
            mac[..6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}

#[cfg(not(windows))]
mod platform {
    use super::arp_table;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    /// One UDP datagram forces the kernel to ARP-resolve `ip`, then the
    /// neighbor table holds the answer. shortcut: shells out per probe —
    /// replace with a raw-ARP responder if sweep latency matters.
    pub(super) fn probe(ip: Ipv4Addr) -> Option<String> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        // Port 9 (discard): any destination works — only the ARP
        // resolution matters, not the delivery.
        let _ = sock.send_to(&[0], SocketAddr::new(ip.into(), 9));
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(60));
            if let Some(mac) = arp_table().ok().and_then(|t| t.get(&ip).cloned()) {
                return Some(mac);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_and_windows_arp_lines() {
        let sample = "\
? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
  192.168.1.10          11-22-33-44-55-66     dynamic
";
        let t = parse_arp_output(sample);
        assert_eq!(
            t.get(&Ipv4Addr::new(192, 168, 1, 1)).map(String::as_str),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            t.get(&Ipv4Addr::new(192, 168, 1, 10)).map(String::as_str),
            Some("11-22-33-44-55-66")
        );
    }
}
