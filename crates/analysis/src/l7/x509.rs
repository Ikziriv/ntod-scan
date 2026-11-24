//! Minimal X.509 DER reader — just enough to flag expired and self-signed
//! certificates: subject/issuer CN, validity window.
//!
//! Walks one certificate's TBSCertificate. Not a validator; signature
//! verification is out of scope (payloads are observations, not trust).

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    /// Validity window as Unix epoch milliseconds (0 when unparseable).
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub self_signed: bool,
}

/// TLV: returns (tag, content_start, tlv_end).
fn tlv(b: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    if pos + 2 > b.len() {
        return None;
    }
    let tag = b[pos];
    let mut len = b[pos + 1] as usize;
    let mut p = pos + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || p + n > b.len() {
            return None;
        }
        len = 0;
        for i in 0..n {
            len = (len << 8) | b[p + i] as usize;
        }
        p += n;
    }
    if b.len().checked_sub(p).is_none_or(|rem| len > rem) {
        return None;
    }
    Some((tag, p, p + len))
}

/// Parse a DER certificate blob.
pub fn parse(b: &[u8]) -> Option<CertInfo> {
    // Certificate := SEQUENCE { tbs, sigAlg, sigValue }
    let (_, start, end) = tlv(b, 0)?;
    let cert = &b[start..end];
    // tbsCertificate := SEQUENCE
    let (_, tstart, tend) = tlv(cert, 0)?;
    let tbs = &cert[tstart..tend];
    let mut pos = 0;
    // optional [0] explicit version
    let (tag, _, tend0) = tlv(tbs, pos)?;
    if tag == 0xa0 {
        pos = tend0;
    }
    // serial INTEGER, signature SEQUENCE
    for _ in 0..2 {
        let (_, _, e) = tlv(tbs, pos)?;
        pos = e;
    }
    // issuer Name
    let (_, istart, iend) = tlv(tbs, pos)?;
    let issuer = &tbs[istart..iend];
    let issuer_cn = name_cn(issuer);
    pos = iend;
    // validity SEQUENCE { notBefore, notAfter }
    let (_, vstart, vend) = tlv(tbs, pos)?;
    let validity = &tbs[vstart..vend];
    let (tag1, ns, ne) = tlv(validity, 0)?;
    let (tag2, as_, ae) = tlv(validity, ne)?;
    let not_before_ms = parse_time(tag1, &validity[ns..ne]);
    let not_after_ms = parse_time(tag2, &validity[as_..ae]);
    pos = vend;
    // subject Name
    let (_, sstart, send) = tlv(tbs, pos)?;
    let subject = &tbs[sstart..send];
    let subject_cn = name_cn(subject);
    Some(CertInfo {
        self_signed: issuer == subject,
        subject_cn,
        issuer_cn,
        not_before_ms,
        not_after_ms,
    })
}

/// First commonName (OID 2.5.4.3 → bytes 55 04 03) in a Name sequence.
fn name_cn(name: &[u8]) -> Option<String> {
    let mut pos = 0;
    while let Some((tag, s, e)) = tlv(name, pos) {
        if tag != 0x31 {
            break; // SET
        }
        let set_body = &name[s..e];
        // SET { SEQUENCE { OID, value } }
        if let Some((_, ss, se)) = tlv(set_body, 0) {
            let seq = &set_body[ss..se];
            if let Some((_, oid_s, oid_e)) = tlv(seq, 0)
                && seq[oid_s..oid_e] == [0x55, 0x04, 0x03]
                && let Some((_, vs, ve)) = tlv(seq, oid_e)
            {
                return Some(String::from_utf8_lossy(&seq[vs..ve]).into_owned());
            }
        }
        pos = e;
    }
    None
}

/// UTCTime (0x17, YYMMDDhhmmssZ) or GeneralizedTime (0x18, YYYY…Z) to epoch ms.
/// Returns 0 when the tag or date fields are malformed.
fn parse_time(tag: u8, s: &[u8]) -> i64 {
    let Ok(t) = core::str::from_utf8(s) else {
        return 0;
    };
    let (y, off) = match tag {
        0x17 => {
            let Some(yy) = t.get(..2).and_then(|v| v.parse::<i64>().ok()) else {
                return 0;
            };
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        0x18 => {
            let Some(yyyy) = t.get(..4).and_then(|v| v.parse::<i64>().ok()) else {
                return 0;
            };
            (yyyy, 4)
        }
        _ => return 0,
    };
    let num = |r: std::ops::Range<usize>| -> Option<i64> { t.get(r)?.parse().ok() };
    let (Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (
        num(off..off + 2),
        num(off + 2..off + 4),
        num(off + 4..off + 6),
        num(off + 6..off + 8),
        num(off + 8..off + 10),
    ) else {
        return 0;
    };
    if !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&mi)
        || !(0..=60).contains(&se)
    {
        return 0;
    }
    civil_to_epoch(y, mo, d, h, mi, se)
}

/// Days-from-civil → Unix epoch milliseconds (Howard Hinnant's algorithm).
fn civil_to_epoch(y: i64, m: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (((days * 24 + h) * 60 + mi) * 60 + s) * 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny self-signed cert: SEQ { TBS { issuer, validity, subject } , ...}
    fn cert(subject_cn: &str, issuer_cn: &str, not_after: &str) -> Vec<u8> {
        let name = |cn: &str| {
            let mut rdn = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x13];
            rdn.push(cn.len() as u8);
            rdn.extend_from_slice(cn.as_bytes());
            let mut set = vec![0x31, (rdn.len() + 2) as u8, 0x30, rdn.len() as u8];
            set.extend_from_slice(&rdn);
            let mut n = vec![0x30, set.len() as u8];
            n.extend_from_slice(&set);
            n
        };
        let time = |t: &str| {
            let mut v = vec![0x17, t.len() as u8];
            v.extend_from_slice(t.as_bytes());
            v
        };
        let mut validity = vec![];
        validity.extend_from_slice(&time("230101000000Z"));
        validity.extend_from_slice(&time(not_after));
        let mut val = vec![0x30, validity.len() as u8];
        val.extend_from_slice(&validity);

        let mut tbs_body = vec![
            0xa0, 0x03, 0x02, 0x01, 0x02, // version v3
            0x02, 0x01, 0x01, // serial
            0x30, 0x02, 0x30, 0x00, // sig alg (dummy)
        ];
        tbs_body.extend_from_slice(&name(issuer_cn));
        tbs_body.extend_from_slice(&val);
        tbs_body.extend_from_slice(&name(subject_cn));
        let mut tbs = vec![0x30, tbs_body.len() as u8];
        tbs.extend_from_slice(&tbs_body);

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&[0x30, 0x02, 0x30, 0x00]); // sigAlg
        cert_body.extend_from_slice(&[0x03, 0x02, 0x00, 0x00]); // sigValue
        let mut c = vec![0x30, cert_body.len() as u8];
        c.extend_from_slice(&cert_body);
        c
    }

    #[test]
    fn parses_self_signed_cert() {
        let c = cert("example.com", "example.com", "300101000000Z");
        let i = parse(&c).unwrap();
        assert_eq!(i.subject_cn.as_deref(), Some("example.com"));
        assert!(i.self_signed);
        // 2030-01-01 = 1_893_456_000_000 ms
        assert_eq!(i.not_after_ms, 1_893_456_000_000);
    }

    #[test]
    fn detects_ca_signed() {
        let c = cert("example.com", "Let's Encrypt", "300101000000Z");
        let i = parse(&c).unwrap();
        assert!(!i.self_signed);
        assert_eq!(i.issuer_cn.as_deref(), Some("Let's Encrypt"));
    }
}
