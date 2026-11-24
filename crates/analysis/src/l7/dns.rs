//! DNS message parser — also covers mDNS/LLMNR/NBNS (same wire format).
//!
//! Zero-panic: every read is bounds-checked; name decompression follows
//! pointers with a jump cap to defeat loops.

use std::borrow::Cow;
use std::net::Ipv6Addr;

#[derive(Debug, Clone)]
pub struct DnsMsg {
    /// QR bit — true when this is a response.
    pub is_response: bool,
    /// RCODE (low 4 bits of flags); meaningful on responses.
    pub rcode: u8,
    /// (name, qtype) per question.
    pub queries: Vec<(String, u16)>,
    /// First answers as display strings ("1.2.3.4", "alias.example").
    pub answers: Vec<String>,
}

/// Parse one DNS message (UDP payload, or one TCP frame without the
/// 2-byte length prefix — strip it before calling).
pub fn parse(b: &[u8]) -> Option<DnsMsg> {
    if b.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([b[2], b[3]]);
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut msg = DnsMsg {
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x0f) as u8,
        queries: Vec::with_capacity(qd.min(16)),
        answers: Vec::new(),
    };
    let mut pos = 12;
    for _ in 0..qd.min(64) {
        let (name, next) = read_name(b, pos)?;
        if next + 4 > b.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([b[next], b[next + 1]]);
        msg.queries.push((name, qtype));
        pos = next + 4;
    }
    // Answers: skip if question section exceeded our 64-question cap (offset misaligned).
    if qd <= 64 {
        for _ in 0..an.min(64) {
            let Some(next) = skip_name(b, pos) else {
                break;
            };
            if next + 10 > b.len() {
                break;
            }
            let rtype = u16::from_be_bytes([b[next], b[next + 1]]);
            let rdlen = u16::from_be_bytes([b[next + 8], b[next + 9]]) as usize;
            let rd = &b[next + 10..(next + 10 + rdlen).min(b.len())];
            if rd.len() == rdlen && msg.answers.len() < 8 {
                match rtype {
                    1 if rdlen == 4 => {
                        msg.answers
                            .push(format!("{}.{}.{}.{}", rd[0], rd[1], rd[2], rd[3]));
                    }
                    28 if rdlen == 16 => {
                        if let Ok(octets) = <[u8; 16]>::try_from(rd) {
                            msg.answers.push(Ipv6Addr::from(octets).to_string());
                        }
                    }
                    5 | 12 | 2 => {
                        if let Some((n, _)) = read_name(b, next + 10) {
                            msg.answers.push(n);
                        }
                    }
                    _ => {}
                }
            }
            pos = next + 10 + rdlen;
            if pos > b.len() {
                break;
            }
        }
    }
    Some(msg)
}

/// Advance past a DNS name in the stream without allocating a `String`.
fn skip_name(b: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for _ in 0..128 {
        let &len = b.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            let _ = b.get(pos + 1)?;
            return Some(pos + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > b.len() {
            return None;
        }
    }
    None
}

/// Read a possibly-compressed domain name. Returns (name, offset after
/// the name in the original stream — pointer targets don't advance it).
fn read_name(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut next = None;
    let mut out = String::with_capacity(32);
    for _jumps in 0..32 {
        let &len = b.get(pos)?;
        if len == 0 {
            return Some((out, next.unwrap_or(pos + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *b.get(pos + 1)? as usize;
            let ptr = (((len & 0x3F) as usize) << 8) | lo;
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // 0x40/0x80 label types are not DNS names
        }
        let end = pos + 1 + len as usize;
        if end > b.len() {
            return None;
        }
        let extra = usize::from(!out.is_empty()) + len as usize;
        if out.len() + extra > 255 {
            return None; // RFC 1035 max domain name length
        }
        if !out.is_empty() {
            out.push('.');
        }
        let label = &b[pos + 1..end];
        match std::str::from_utf8(label) {
            Ok(s) => out.push_str(s),
            Err(_) => out.push_str(&String::from_utf8_lossy(label)),
        }
        pos = end;
    }
    None // pointer loop
}

/// Short qtype name for reports.
pub fn qtype_name(t: u16) -> Cow<'static, str> {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        10 => "NULL".into(),
        _ => format!("TYPE{t}").into(),
    }
}

/// Registered-domain guess: last two labels.
/// shortcut: no public-suffix list — "co.uk" splits wrong; upgrade when
/// that matters for tunnel grouping.
pub fn base_domain(name: &str) -> &str {
    name.rmatch_indices('.')
        .nth(1)
        .map_or(name, |(i, _)| &name[i + 1..])
}

/// Shannon entropy (bits/byte) of a string — high values flag encoded data.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &c in s.as_bytes() {
        freq[c as usize] += 1;
    }
    let n = s.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        // id=0x1234, qr=0, qd=1: "www.example.com" A IN
        let mut b = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    #[test]
    fn parses_query_name() {
        let m = parse(&query()).unwrap();
        assert!(!m.is_response);
        assert_eq!(m.queries, vec![("www.example.com".to_string(), 1)]);
    }

    #[test]
    fn parses_compressed_answer() {
        let mut b = query();
        b[2] = 0x81;
        b[3] = 0x80;
        b[6] = 0;
        b[7] = 1; // ancount 1
        // answer: name pointer to offset 12, A, IN, ttl 60, rdlen 4, 1.2.3.4
        b.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let m = parse(&b).unwrap();
        assert!(m.is_response);
        assert_eq!(m.rcode, 0);
        assert_eq!(m.answers, vec!["1.2.3.4"]);
    }

    #[test]
    fn base_domain_last_two_labels() {
        assert_eq!(base_domain("a.b.c.example.com"), "example.com");
        assert_eq!(base_domain("example.com"), "example.com");
        assert_eq!(base_domain("localhost"), "localhost");
    }

    #[test]
    fn entropy_flags_encoded_names() {
        let low = shannon("www.example.com");
        let high = shannon("a9f3kx7q2m8zb4v1n6y5j0d");
        assert!(low < 4.0 && high > 4.0, "low={low} high={high}");
    }
}
