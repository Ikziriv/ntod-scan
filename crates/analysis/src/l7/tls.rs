//! TLS record + handshake parser: SNI, JA3/JA3S fingerprints, cert chain
//! info, heartbeat frames (Heartbleed indicator).
//!
//! Works on the buffered start of a TCP stream — no reassembly, so a
//! certificate chain past the head cap is simply not seen.

use std::fmt::Write as _;

use super::x509::{self, CertInfo};

#[derive(Debug, Default)]
pub struct TlsInfo {
    /// ClientHello SNI.
    pub sni: Option<String>,
    /// JA3 hash of the ClientHello (md5 hex of the JA3 string).
    pub ja3: Option<String>,
    /// JA3S hash of the ServerHello.
    pub ja3s: Option<String>,
    /// JA4 of the ClientHello (FoxIO format: `t13d1516h2_…_…`).
    pub ja4: Option<String>,
    /// JA4S of the ServerHello.
    pub ja4s: Option<String>,
    /// TLS version offered by the client (0x0303 = TLS 1.2).
    pub client_version: Option<u16>,
    /// Version/cipher chosen by the server.
    pub server_version: Option<u16>,
    pub cipher: Option<u16>,
    /// Parsed certificates (first few of the chain).
    pub certs: Vec<CertInfo>,
    /// Heartbeat records present — possible Heartbleed probe.
    pub heartbeat: bool,
    /// True once a ClientHello was decoded.
    pub saw_hello: bool,
}

/// Cheap pre-check: TLS handshake record.
pub fn probe(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

/// GREASE values (RFC 8701): 0x?a?a pattern — excluded from fingerprints.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v & 0xff == v >> 8
}

/// Parse all complete TLS records in `buf`.
pub fn parse_records(buf: &[u8], out: &mut TlsInfo) {
    let mut pos = 0;
    while pos + 5 <= buf.len() {
        let ct = buf[pos];
        let rlen = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if pos + 5 + rlen > buf.len() {
            break; // incomplete record
        }
        let body = &buf[pos + 5..pos + 5 + rlen];
        match ct {
            22 => parse_handshakes(body, out),
            24 => out.heartbeat = true,
            _ => {}
        }
        pos += 5 + rlen;
    }
}

fn parse_handshakes(mut b: &[u8], out: &mut TlsInfo) {
    while b.len() >= 4 {
        let htype = b[0];
        let hlen = ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
        if 4 + hlen > b.len() {
            break;
        }
        let body = &b[4..4 + hlen];
        match htype {
            1 => client_hello(body, out),
            2 => server_hello(body, out),
            11 => certificates(body, out),
            _ => {}
        }
        b = &b[4 + hlen..];
    }
}

fn client_hello(b: &[u8], out: &mut TlsInfo) {
    // version(2) random(32) sid_len(1) sid cs_len(2) ciphers comp_len(1) comp
    if b.len() < 34 {
        return;
    }
    let ver = u16::from_be_bytes([b[0], b[1]]);
    out.client_version = Some(ver);
    let mut pos = 34;
    let sid_len = b.get(pos).copied().unwrap_or(0) as usize;
    pos += 1 + sid_len;
    if pos + 2 > b.len() {
        return;
    }
    let cs_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > b.len() {
        return;
    }
    let mut ciphers: Vec<u16> = b[pos..pos + cs_len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .filter(|&v| !grease(v))
        .collect();
    pos += cs_len;
    if pos >= b.len() {
        return;
    }
    let comp_len = b[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > b.len() {
        // hello without extensions — still fingerprintable
        out.ja3 = Some(ja3_hash(ver, &ciphers, &[], &[], &[]));
        out.ja4 = Some(ja4(ver, false, &mut ciphers, &[], &[], None));
        out.saw_hello = true;
        return;
    }
    let ext_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_len).min(b.len());

    let mut exts = Vec::new();
    let mut groups = Vec::new();
    let mut points = Vec::new();
    let mut sig_algos = Vec::new();
    let mut alpn: Option<&[u8]> = None;
    let mut max_ver = ver;
    let mut e = pos;
    while e + 4 <= end {
        let etype = u16::from_be_bytes([b[e], b[e + 1]]);
        let elen = u16::from_be_bytes([b[e + 2], b[e + 3]]) as usize;
        e += 4;
        if e + elen > end {
            break;
        }
        let edata = &b[e..e + elen];
        if !grease(etype) {
            exts.push(etype);
        }
        match etype {
            0 => out.sni = parse_sni(edata),
            10 => groups = u16_list(edata, 2),
            11 => {
                points = edata
                    .get(1..)
                    .map(|s| s.iter().map(|&v| v as u16).collect())
                    .unwrap_or_default()
            }
            13 => sig_algos = u16_list(edata, 2),
            16 => alpn = alpn_first(edata),
            43 => {
                // supported_versions: list_len(1) + u16* — take the max.
                if let Some(&top) = u16_list(edata, 1).iter().max() {
                    max_ver = top;
                }
            }
            _ => {}
        }
        e += elen;
    }
    out.ja3 = Some(ja3_hash(ver, &ciphers, &exts, &groups, &points));
    out.ja4 = Some(ja4(
        max_ver,
        out.sni.is_some(),
        &mut ciphers,
        &exts,
        &sig_algos,
        alpn,
    ));
    out.saw_hello = true;
}

fn server_hello(b: &[u8], out: &mut TlsInfo) {
    if b.len() < 38 {
        return;
    }
    let ver = u16::from_be_bytes([b[0], b[1]]);
    let mut pos = 34;
    let sid_len = b[pos] as usize;
    pos += 1 + sid_len;
    if pos + 3 > b.len() {
        out.server_version = Some(ver);
        return;
    }
    let cipher = u16::from_be_bytes([b[pos], b[pos + 1]]);
    out.cipher = Some(cipher);
    pos += 3; // cipher + compression
    let mut exts = Vec::new();
    let mut alpn: Option<&[u8]> = None;
    let mut neg_ver = ver;
    if pos + 2 <= b.len() {
        let ext_len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2;
        let end = (pos + ext_len).min(b.len());
        let mut e = pos;
        while e + 4 <= end {
            let et = u16::from_be_bytes([b[e], b[e + 1]]);
            let el = u16::from_be_bytes([b[e + 2], b[e + 3]]) as usize;
            if e + 4 + el > end {
                break;
            }
            if !grease(et) {
                exts.push(et);
            }
            match et {
                16 => alpn = alpn_first(&b[e + 4..e + 4 + el]),
                43 => {
                    // Server's supported_versions is a single u16 — no list.
                    if el == 2 {
                        neg_ver = u16::from_be_bytes([b[e + 4], b[e + 5]]);
                    }
                }
                _ => {}
            }
            e += 4 + el;
        }
    }
    out.server_version = Some(neg_ver);
    let mut ja3s = String::with_capacity(32 + exts.len() * 6);
    let _ = write!(ja3s, "{ver},{cipher},");
    write_dec_list(&mut ja3s, &exts);
    out.ja3s = Some(format!("{:x}", md5::compute(ja3s.as_bytes())));
    out.ja4s = Some(ja4s(neg_ver, cipher, &exts, alpn));
}

fn certificates(b: &[u8], out: &mut TlsInfo) {
    // Certificate message: list_len(3) + [cert_len(3) + DER]*
    if b.len() < 3 {
        return;
    }
    let total = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize;
    let mut pos = 3;
    let end = (3 + total).min(b.len());
    while pos + 3 <= end && out.certs.len() < 4 {
        let clen = ((b[pos] as usize) << 16) | ((b[pos + 1] as usize) << 8) | b[pos + 2] as usize;
        pos += 3;
        if pos + clen > end {
            break;
        }
        if let Some(c) = x509::parse(&b[pos..pos + clen]) {
            out.certs.push(c);
        }
        pos += clen;
    }
}

fn parse_sni(b: &[u8]) -> Option<String> {
    // server_name_list: len(2) + [type(1) name_len(2) name]
    if b.len() < 5 {
        return None;
    }
    let nlen = u16::from_be_bytes([b[3], b[4]]) as usize;
    if b[2] != 0 || 5 + nlen > b.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&b[5..5 + nlen]).into_owned())
}

/// u16 list preceded by a length field of `len_bytes` (1 or 2).
fn u16_list(b: &[u8], len_bytes: usize) -> Vec<u16> {
    if b.len() < len_bytes {
        return Vec::new();
    }
    let llen = if len_bytes == 2 {
        u16::from_be_bytes([b[0], b[1]]) as usize
    } else {
        b[0] as usize
    };
    let data = &b[len_bytes..(len_bytes + llen).min(b.len())];
    data.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .filter(|&v| !grease(v))
        .collect()
}

/// ALPN ext data: list_len(2) + [len(1) + proto]* — first protocol name.
fn alpn_first(b: &[u8]) -> Option<&[u8]> {
    if b.len() < 3 {
        return None;
    }
    let n = b[2] as usize;
    if 3 + n > b.len() || n == 0 {
        return None;
    }
    Some(&b[3..3 + n])
}

fn write_dec_list(buf: &mut String, v: &[u16]) {
    for (i, &x) in v.iter().enumerate() {
        if i > 0 {
            buf.push('-');
        }
        let _ = write!(buf, "{x}");
    }
}

fn write_hex_list(buf: &mut String, v: &[u16]) {
    for (i, &x) in v.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        let _ = write!(buf, "{x:04x}");
    }
}

/// First 12 hex chars of sha256 — the JA4 hash sections.
fn sha12(s: &str) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(12);
    for &b in &d[..6] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// 2-char JA4 version code from a negotiated/offered TLS version.
fn ver_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// 2-char ALPN code: first+last char of the chosen value, "00" if none,
/// "99" for non-ASCII values.
fn alpn_code(a: Option<&[u8]>) -> [char; 2] {
    let Some(p) = a else { return ['0', '0'] };
    let (f, l) = (*p.first().unwrap_or(&0), *p.last().unwrap_or(&0));
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        [f as char, l as char]
    } else {
        ['9', '9']
    }
}

/// JA4 client fingerprint (FoxIO spec): `t{ver}{d|i}{cc}{ec}{alpn}_b_c`.
/// b = sha256 of sorted cipher hex; c = sha256 of sorted ext hex (SNI and
/// ALPN removed) + ("_" + signature algorithms in wire order, when non-empty).
fn ja4(
    ver: u16,
    has_sni: bool,
    ciphers: &mut [u16],
    exts: &[u16],
    sig_algos: &[u16],
    alpn: Option<&[u8]>,
) -> String {
    ciphers.sort_unstable();
    let mut buf = String::with_capacity(ciphers.len().max(exts.len() + sig_algos.len()) * 5 + 1);
    let b = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        write_hex_list(&mut buf, ciphers);
        sha12(&buf)
    };
    let mut es: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    es.sort_unstable();
    let c = if es.is_empty() && sig_algos.is_empty() {
        "000000000000".to_string()
    } else {
        buf.clear();
        write_hex_list(&mut buf, &es);
        if !sig_algos.is_empty() {
            buf.push('_');
            write_hex_list(&mut buf, sig_algos);
        }
        sha12(&buf)
    };
    let [a0, a1] = alpn_code(alpn);
    format!(
        "t{}{}{:02}{:02}{a0}{a1}_{b}_{c}",
        ver_code(ver),
        if has_sni { "d" } else { "i" },
        ciphers.len().min(99),
        exts.len().min(99),
    )
}

/// JA4S server fingerprint: `t{ver}{ec}{alpn}_{cipher}_{ext_hash}` —
/// extensions stay in WIRE order (servers don't shuffle, order is signal).
fn ja4s(ver: u16, cipher: u16, exts: &[u16], alpn: Option<&[u8]>) -> String {
    let c = if exts.is_empty() {
        "000000000000".to_string()
    } else {
        let mut buf = String::with_capacity(exts.len() * 5);
        write_hex_list(&mut buf, exts);
        sha12(&buf)
    };
    let [a0, a1] = alpn_code(alpn);
    format!(
        "t{}{:02}{a0}{a1}_{cipher:04x}_{c}",
        ver_code(ver),
        exts.len().min(99),
    )
}

fn ja3_hash(ver: u16, ciphers: &[u16], exts: &[u16], groups: &[u16], points: &[u16]) -> String {
    let cap = 16 + (ciphers.len() + exts.len() + groups.len() + points.len()) * 6;
    let mut ja3 = String::with_capacity(cap);
    let _ = write!(ja3, "{ver},");
    write_dec_list(&mut ja3, ciphers);
    ja3.push(',');
    write_dec_list(&mut ja3, exts);
    ja3.push(',');
    write_dec_list(&mut ja3, groups);
    ja3.push(',');
    write_dec_list(&mut ja3, points);
    format!("{:x}", md5::compute(ja3.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ClientHello with SNI "example.com", one cipher, exts 0/10/11.
    fn client_hello() -> Vec<u8> {
        let mut body = vec![0x03, 0x03]; // TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // sid len
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // ciphers: TLS_AES_128_GCM
        body.extend_from_slice(&[1, 0]); // comp: null
        // extensions: SNI(0) + groups(10) + points(11)
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0, 0, 0, 16]); // type 0, len 16
        exts.extend_from_slice(&[0, 14]); // list len 14
        exts.extend_from_slice(&[0, 0, 11]); // host_name, len 11
        exts.extend_from_slice(b"example.com");
        exts.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 29]); // groups: x25519
        exts.extend_from_slice(&[0, 11, 0, 2, 1, 0]); // points: uncompressed
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        // wrap: handshake(1) + len3 + record(0x16 0301 len)
        let mut hs = vec![1u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_and_ja3() {
        let mut t = TlsInfo::default();
        parse_records(&client_hello(), &mut t);
        assert_eq!(t.sni.as_deref(), Some("example.com"));
        assert!(t.ja3.is_some());
        assert_eq!(t.client_version, Some(0x0303));
        assert!(t.saw_hello);
        // JA4_a is human-readable by design — pin it: TLS/TCP, 1.2,
        // SNI present, 1 cipher, 3 exts, no ALPN.
        let ja4 = t.ja4.expect("ja4 computed");
        assert_eq!(&ja4[..10], "t12d010300", "ja4_a was {ja4}");
        // No supported_versions ext → falls back to legacy version.
        assert_eq!(ja4.len(), 10 + 1 + 12 + 1 + 12);
    }

    #[test]
    fn ja4s_wire_order_and_empty_sentinel() {
        // No extensions → zero sentinel, not a hash.
        assert_eq!(ja4s(0x0303, 0xc02f, &[], None), "t120000_c02f_000000000000");
        // Wire order is preserved — [16(alpn absent), 43] vs [43] differ.
        let a = ja4s(0x0304, 0x1301, &[0x002b, 0x0010], Some(b"h2"));
        assert!(a.starts_with("t1302h2_1301_"));
        assert_ne!(a, ja4s(0x0304, 0x1301, &[0x0010, 0x002b], Some(b"h2")));
    }

    #[test]
    fn flags_heartbeat() {
        let rec = [0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x40, 0x00];
        let mut t = TlsInfo::default();
        parse_records(&rec, &mut t);
        assert!(t.heartbeat);
    }
}
