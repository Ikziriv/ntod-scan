//! Raw frame -> PacketEvent via etherparse (zero-copy, no unsafe).

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use ntod_core::Proto;

use crate::PacketEvent;

/// Decode a link-layer frame (by libpcap linktype) to a PacketEvent.
pub fn decode_frame(linktype: u16, b: &[u8], ts: i64) -> Option<PacketEvent> {
    match linktype {
        // DLT_RAW — raw IP datagram.
        101 => decode_ip(b, ts),
        // DLT_EN10MB — Ethernet II (skip 802.1Q tags).
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
            if et != 0x0800 && et != 0x86DD {
                return None;
            }
            decode_ip(&b[off..], ts)
        }
        // DLT_LINUX_SLL — 16B header, protocol at 14.
        113 => {
            if b.len() < 16 {
                return None;
            }
            let et = u16::from_be_bytes([b[14], b[15]]);
            (et == 0x0800 || et == 0x86DD).then(|| decode_ip(&b[16..], ts))?
        }
        // DLT_LINUX_SLL2 — 20B header, protocol at 0.
        276 => {
            if b.len() < 20 {
                return None;
            }
            let et = u16::from_be_bytes([b[0], b[1]]);
            (et == 0x0800 || et == 0x86DD).then(|| decode_ip(&b[20..], ts))?
        }
        _ => None,
    }
}

/// Decode an IPv4 or IPv6 datagram (first nibble decides).
pub fn decode_ip(raw: &[u8], ts: i64) -> Option<PacketEvent> {
    match raw.first()? >> 4 {
        4 => decode_v4(raw, ts),
        6 => decode_v6(raw, ts),
        _ => None,
    }
}

/// Decode one IPv4 datagram (bytes starting at the IP header).
pub fn decode_v4(raw: &[u8], ts: i64) -> Option<PacketEvent> {
    let ip = Ipv4HeaderSlice::from_slice(raw).ok()?;
    let proto = Proto::from_u8(u8::from(ip.protocol()));
    let payload = &raw[ip.slice().len()..];

    let (sport, dport) = match proto {
        Proto::Tcp => TcpHeaderSlice::from_slice(payload)
            .ok()
            .map(|t| (Some(t.source_port()), Some(t.destination_port())))
            .unwrap_or((None, None)),
        Proto::Udp => UdpHeaderSlice::from_slice(payload)
            .ok()
            .map(|u| (Some(u.source_port()), Some(u.destination_port())))
            .unwrap_or((None, None)),
        _ => (None, None),
    };

    Some(PacketEvent {
        ts,
        src: ip.source_addr().into(),
        dst: ip.destination_addr().into(),
        proto,
        sport,
        dport,
        len: ip.total_len(),
    })
}

/// Decode one IPv6 datagram (bytes starting at the IPv6 header).
/// Extension headers are not walked — L4 fields are missed on those.
pub fn decode_v6(raw: &[u8], ts: i64) -> Option<PacketEvent> {
    let ip = Ipv6HeaderSlice::from_slice(raw).ok()?;
    let proto = Proto::from_u8(u8::from(ip.next_header()));
    let payload = &raw[ip.slice().len()..];

    let (sport, dport) = match proto {
        Proto::Tcp => TcpHeaderSlice::from_slice(payload)
            .ok()
            .map(|t| (Some(t.source_port()), Some(t.destination_port())))
            .unwrap_or((None, None)),
        Proto::Udp => UdpHeaderSlice::from_slice(payload)
            .ok()
            .map(|u| (Some(u.source_port()), Some(u.destination_port())))
            .unwrap_or((None, None)),
        _ => (None, None),
    };

    Some(PacketEvent {
        ts,
        src: ip.source_addr().into(),
        dst: ip.destination_addr().into(),
        proto,
        sport,
        dport,
        len: ip.payload_length().saturating_add(40),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntod_core::Proto;
    use std::net::{IpAddr, Ipv4Addr};

    // IPv4 (ihl 5, total 40, ttl 64, proto 6) + TCP sport 1234 dport 443
    const TCP_PKT: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8,
        0x04, 0xd2, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0,
    ];

    #[test]
    fn decodes_tcp_packet() {
        let ev = decode_v4(TCP_PKT, 1000).expect("decodes");
        assert_eq!(ev.proto, Proto::Tcp);
        assert_eq!(ev.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ev.dst, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(ev.sport, Some(1234));
        assert_eq!(ev.dport, Some(443));
        assert_eq!(ev.len, 40);
        assert_eq!(ev.ts, 1000);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_v4(&[0u8; 10], 0).is_none());
    }

    #[test]
    fn filter_matches() {
        let ev = decode_v4(TCP_PKT, 0).unwrap();
        let f = ntod_core::Filter {
            proto: Some(Proto::Tcp),
            port: Some(443),
            ..Default::default()
        };
        assert!(ev.matches(&f));
        let f2 = ntod_core::Filter {
            proto: Some(Proto::Udp),
            ..Default::default()
        };
        assert!(!ev.matches(&f2));
    }
}
