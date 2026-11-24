//! BOOTP/DHCP parser — hostnames, requested IPs, message types.
//! Passive device identification feed (Fing-tier fingerprint input).

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpMsg {
    /// DHCP message type (1=Discover … 5=Ack), 0 when absent.
    pub msg_type: u8,
    /// Client hardware address (chaddr) rendered as MAC.
    pub client_mac: String,
    /// Your IP address (yiaddr) — the address the server is offering.
    pub yiaddr: Ipv4Addr,
    /// Option 12 hostname.
    pub hostname: Option<String>,
    /// Option 60 vendor-class identifier ("android-dhcp-15", "MSFT 5.0",
    /// "dhcpcd-9.4.1") — a strong passive device fingerprint.
    pub vendor_class: Option<String>,
    /// Option 50 requested IP.
    pub requested: Option<Ipv4Addr>,
}

pub fn msg_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "Ack",
        6 => "Nak",
        7 => "Release",
        8 => "Inform",
        _ => "Other",
    }
}

/// Parse a BOOTP datagram (UDP 67/68 payload).
pub fn parse(b: &[u8]) -> Option<DhcpMsg> {
    // BOOTP fixed part is 236 bytes, then the 0x63825363 cookie + options.
    if b.len() < 244 || b[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let hlen = b[2].min(16) as usize;
    let mac = if hlen == 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&b[28..34]);
        crate::report::fmt_mac(&m)
    } else {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(hlen * 3);
        for (i, &o) in b[28..28 + hlen].iter().enumerate() {
            if i > 0 {
                s.push(':');
            }
            let _ = write!(s, "{o:02x}");
        }
        s
    };
    let mut msg = DhcpMsg {
        msg_type: 0,
        client_mac: mac,
        yiaddr: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        hostname: None,
        vendor_class: None,
        requested: None,
    };
    let mut pos = 240;
    while pos + 2 <= b.len() {
        let code = b[pos];
        if code == 255 {
            break;
        }
        if code == 0 {
            pos += 1;
            continue;
        }
        let len = b[pos + 1] as usize;
        pos += 2;
        if pos + len > b.len() {
            break;
        }
        let v = &b[pos..pos + len];
        match code {
            53 if len >= 1 => msg.msg_type = v[0],
            12 => msg.hostname = Some(String::from_utf8_lossy(v).into_owned()),
            50 if len == 4 => msg.requested = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            60 => msg.vendor_class = Some(String::from_utf8_lossy(v).into_owned()),
            _ => {}
        }
        pos += len;
    }
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dhcp_request() {
        let mut b = vec![0u8; 240];
        b[0] = 1; // request
        b[1] = 1; // ethernet
        b[2] = 6; // hlen
        b[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        b[16..20].copy_from_slice(&[192, 168, 1, 50]);
        b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        // opt 53 msg type 3, opt 12 hostname "laptop", opt 50 req ip, 255
        b.extend_from_slice(&[53, 1, 3]);
        b.extend_from_slice(&[12, 6]);
        b.extend_from_slice(b"laptop");
        b.extend_from_slice(&[60, 15]);
        b.extend_from_slice(b"android-dhcp-15");
        b.extend_from_slice(&[50, 4, 192, 168, 1, 50, 255]);
        let m = parse(&b).unwrap();
        assert_eq!(m.msg_type, 3);
        assert_eq!(m.client_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(m.hostname.as_deref(), Some("laptop"));
        assert_eq!(m.vendor_class.as_deref(), Some("android-dhcp-15"));
        assert_eq!(m.requested, Some(Ipv4Addr::new(192, 168, 1, 50)));
    }
}
