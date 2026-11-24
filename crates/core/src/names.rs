//! Hostname lookups beyond PTR records: NetBIOS node status (Windows
//! machines) and unicast mDNS PTR (Apple, IoT, printers). Both answer
//! the common case — a live host with no PTR — that `lookup_addr` misses.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Per-probe ceiling; unanswered UDP just means "no such name service".
const TIMEOUT: Duration = Duration::from_millis(400);

/// NBNS (UDP/137) node-status query — the name a Windows box announces
/// even when DNS knows nothing about it.
pub fn nbns_name(ip: Ipv4Addr) -> Option<String> {
    // Header + one NBSTAT question for the wildcard name "*".
    let mut q = Vec::with_capacity(50);
    q.extend_from_slice(&[0xAB, 0xCD]); // transaction id
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // rd=0, qdcount=1
    q.push(32); // encoded label len
    q.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // "*" padded
    q.push(0);
    q.extend_from_slice(&[0, 0x21, 0, 1]); // QTYPE=NBSTAT, QCLASS=IN
    let buf = query(ip, 137, &q, false)?;
    nbns_first_name(&buf)
}

/// First unique workstation name out of an NBSTAT answer.
/// Layout: header(12) + question(38) + RR header(12) + num-names(1) +
/// n * 18-byte name records.
fn nbns_first_name(buf: &[u8]) -> Option<String> {
    let count = *buf.get(62)? as usize;
    for i in 0..count.min(20) {
        let e = 63 + i * 18;
        let entry = buf.get(e..e + 18)?;
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        // Unique (not group) record, suffix 0x00 = workstation name.
        if suffix == 0 && flags & 0x8000 == 0 {
            let name: String = entry[..15]
                .iter()
                .take_while(|&&b| b != 0 && b != b' ')
                .filter(|b| b.is_ascii_graphic())
                .map(|&b| b as char)
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// mDNS PTR for `ip` — sent unicast to the host and to the 224.0.0.251
/// group from the same socket, so responders honouring the QU bit reply
/// straight back to us. Covers devices that ignore direct queries.
pub fn mdns_name(ip: Ipv4Addr) -> Option<String> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&[0x12, 0x34]); // id
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // qdcount=1
    for octet in ip.octets().iter().rev() {
        let s = octet.to_string();
        q.push(s.len() as u8);
        q.extend_from_slice(s.as_bytes());
    }
    for label in [b"in-addr".as_slice(), b"arpa".as_slice()] {
        q.push(label.len() as u8);
        q.extend_from_slice(label);
    }
    q.push(0);
    q.extend_from_slice(&[0, 0x0C]); // QTYPE=PTR
    q.extend_from_slice(&[0x80, 0x01]); // QCLASS=IN | QU (unicast-response)
    let buf = query(ip, 5353, &q, true)?;

    let qd = be16(&buf, 4)?;
    let an = be16(&buf, 6)?;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(&buf, off)?.checked_add(4)?;
    }
    for _ in 0..an.min(32) {
        off = skip_name(&buf, off)?;
        let rtype = be16(&buf, off)?;
        let rdlen = be16(&buf, off + 8)?;
        let rdata = off.checked_add(10)?;
        if rtype == 0x000C {
            return decode_name(&buf, rdata);
        }
        off = rdata.checked_add(rdlen)?;
    }
    None
}

/// UDP packets out, first reply back — `None` on timeout or error.
/// With `multicast` the same packet also goes to the mDNS group so
/// multicast-only responders see it (the QU bit makes them reply
/// unicast to our ephemeral port).
fn query(ip: Ipv4Addr, port: u16, packet: &[u8], multicast: bool) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.send_to(packet, SocketAddr::new(ip.into(), port))
        .ok()?;
    if multicast {
        const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
        let _ = sock.send_to(packet, SocketAddr::new(MDNS_GROUP.into(), 5353));
    }
    let mut buf = vec![0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn be16(buf: &[u8], off: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]) as usize)
}

/// Offset past a DNS name at `off`, following no pointers.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        off = off.checked_add(len + 1)?;
    }
}

/// Decode a DNS name at `off` into dotted text, following compression
/// pointers. Bounds-checked; malformed input yields `None`.
fn decode_name(buf: &[u8], mut off: usize) -> Option<String> {
    let mut out = String::new();
    for _ in 0..32 {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return (!out.is_empty()).then_some(out);
        }
        if len & 0xC0 == 0xC0 {
            off = ((len & 0x3F) << 8) | *buf.get(off + 1)? as usize;
            continue;
        }
        let label = buf.get(off + 1..off + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.extend(
            label
                .iter()
                .filter(|b| b.is_ascii_graphic())
                .map(|&b| b as char),
        );
        off += len + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nbns_first_unique_name() {
        // 62B prefix, then 2 name records: a group (flags 0x8000) we
        // skip, then unique "DESKTOP-ABC".
        let mut buf = vec![0u8; 63];
        buf[62] = 2; // num names
        let mut grp = [b' '; 18];
        grp[..7].copy_from_slice(b"WORKGRP");
        grp[15] = 0;
        grp[16] = 0x80;
        grp[17] = 0x00;
        let mut uniq = [b' '; 18];
        uniq[..11].copy_from_slice(b"DESKTOP-ABC");
        uniq[15] = 0;
        buf.extend_from_slice(&grp);
        buf.extend_from_slice(&uniq);
        assert_eq!(nbns_first_name(&buf).as_deref(), Some("DESKTOP-ABC"));
    }

    #[test]
    fn decodes_names_and_pointers() {
        // Literal "host.local" at offset 12.
        let mut buf = vec![0u8; 12];
        for part in ["host", "local"] {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0);
        assert_eq!(decode_name(&buf, 12).as_deref(), Some("host.local"));
        // A compression pointer skips in 2 bytes, and decoding follows
        // it to the literal "host.local" at offset 12.
        let mut buf2 = vec![0xC0, 0x0C];
        buf2.resize(12, 0);
        buf2.extend_from_slice(&buf[12..]);
        assert_eq!(skip_name(&buf2, 0), Some(2));
        assert_eq!(decode_name(&buf2, 0).as_deref(), Some("host.local"));
    }
}
