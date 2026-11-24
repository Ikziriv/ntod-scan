//! Cleartext credential extraction — line protocols (FTP/POP3/IMAP/SMTP)
//! plus helpers shared with the HTTP dissector.
//!
//! Secrets are never stored in the clear: reports carry the username and a
//! masked hint, matching A-Packets' preview behaviour.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

#[derive(Debug, Clone)]
pub struct Cred {
    /// e.g. "ftp", "pop3", "imap", "smtp", "http-basic", "http-form"
    pub proto: &'static str,
    pub user: String,
    /// Masked: first char + bullet run + length. Never the full secret.
    pub secret: String,
}

/// Mask a password for display.
pub fn mask(s: &str) -> String {
    let mut it = s.chars();
    match it.next() {
        Some(c) => format!("{c}••• ({} chars)", s.chars().count()),
        None => "•••".into(),
    }
}

/// Decode a base64 token to UTF-8 (Authorization headers, SMTP AUTH).
pub fn decode_b64_utf8(tok: &str) -> Option<String> {
    B64.decode(tok.trim())
        .ok()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Scan client→server bytes for cleartext logins on line-oriented auth
/// protocols. `port` is the server-side port.
pub fn scan_lines(proto: &'static str, b: &[u8]) -> Vec<Cred> {
    let text = String::from_utf8_lossy(b);
    let mut out = Vec::new();
    let mut pending_user: Option<String> = None;
    let mut smtp_b64_stage = 0u8;
    for line in text.split(['\r', '\n']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match proto {
            "ftp" | "pop3" => {
                if let Some(u) = strip_prefix_ci(line, "USER ") {
                    pending_user = Some(u.to_string());
                } else if let Some(p) = strip_prefix_ci(line, "PASS ")
                    && let Some(u) = pending_user.take()
                {
                    out.push(Cred {
                        proto,
                        user: u,
                        secret: mask(p),
                    });
                }
            }
            "imap" => {
                // "<tag> LOGIN user pass"
                let mut it = line.split_whitespace();
                let (_tag, cmd, user, pass) = (it.next(), it.next(), it.next(), it.next());
                if let (Some(cmd), Some(u), Some(p)) = (cmd, user, pass)
                    && cmd.eq_ignore_ascii_case("login")
                {
                    out.push(Cred {
                        proto,
                        user: u.trim_matches('"').into(),
                        secret: mask(p.trim_matches('"')),
                    });
                }
            }
            "smtp" => {
                if let Some(rest) = strip_prefix_ci(line, "AUTH PLAIN ") {
                    if let Some(dec) = decode_b64_utf8(rest) {
                        // \0 authzid \0 user \0 pass
                        let mut it = dec.split('\0').filter(|s| !s.is_empty());
                        let u = it.next().unwrap_or_default().to_string();
                        let p = it.next().unwrap_or_default();
                        out.push(Cred {
                            proto,
                            user: u,
                            secret: mask(p),
                        });
                    }
                } else if strip_prefix_ci(line, "AUTH LOGIN").is_some() {
                    smtp_b64_stage = 1;
                } else if smtp_b64_stage == 1 {
                    if let Some(u) = decode_b64_utf8(line) {
                        pending_user = Some(u);
                        smtp_b64_stage = 2;
                    } else {
                        smtp_b64_stage = 0;
                    }
                } else if smtp_b64_stage == 2 {
                    if let Some(p) = decode_b64_utf8(line)
                        && let Some(u) = pending_user.take()
                    {
                        out.push(Cred {
                            proto,
                            user: u,
                            secret: mask(&p),
                        });
                    }
                    smtp_b64_stage = 0;
                }
            }
            _ => {}
        }
    }
    out
}

/// Split a decoded Basic credential "user:pass" into display form.
pub fn split_basic(decoded: &str) -> Option<(String, String)> {
    let (u, p) = decoded.split_once(':')?;
    Some((u.to_string(), mask(p)))
}

/// Which ports get line-scanned, and the proto label for each.
pub fn line_proto(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        110 => Some("pop3"),
        143 => Some("imap"),
        25 | 587 => Some("smtp"),
        _ => None,
    }
}

/// SNMP v1/v2c community string — minimal BER walk:
/// SEQUENCE → INTEGER(version) → OCTET STRING(community).
/// The community is a shared secret sent in cleartext; mask on output.
pub fn snmp_community(b: &[u8]) -> Option<String> {
    if b.len() < 4 || b[0] != 0x30 {
        return None;
    }
    // Skip the SEQUENCE header (short or long form length).
    let (mut i, len_len) = match b[1] {
        n if n < 0x80 => (2usize, 0usize),
        n => (2, (n & 0x7f) as usize),
    };
    i += len_len;
    // Version INTEGER.
    if b.get(i) != Some(&0x02) {
        return None;
    }
    let vlen = *b.get(i + 1)? as usize;
    i += 2 + vlen;
    // Community OCTET STRING.
    if b.get(i) != Some(&0x04) {
        return None;
    }
    let clen = *b.get(i + 1)? as usize;
    let s = b.get(i + 2..i + 2 + clen)?;
    let s = std::str::from_utf8(s).ok()?;
    (!s.is_empty() && s.len() < 64 && s.chars().all(|c| c.is_ascii_graphic())).then(|| s.into())
}

/// Form-encoded password fields in a request head buffer — coarse, flags
/// rather than extracts (full key never leaves the capture context).
/// Zero-allocation byte scan around `=`.
pub fn form_password_hit(b: &[u8]) -> bool {
    const KEYS: &[&[u8]] = &[b"password", b"passwd", b"pwd", b"pass"];
    for (i, &ch) in b.iter().enumerate() {
        if ch != b'=' {
            continue;
        }
        for &k in KEYS {
            if i >= k.len() && b[i - k.len()..i].eq_ignore_ascii_case(k) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftp_user_pass_pair() {
        let c = scan_lines("ftp", b"USER alice\r\nPASS s3cret\r\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].user, "alice");
        assert!(!c[0].secret.contains("s3cret"));
    }

    #[test]
    fn smtp_auth_login_flow() {
        // "alice" / "hunter2" base64
        let c = scan_lines("smtp", b"AUTH LOGIN\r\nYWxpY2U=\r\naHVudGVyMg==\r\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].user, "alice");
    }

    #[test]
    fn imap_login() {
        let c = scan_lines("imap", b"a1 LOGIN bob pw123\r\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].user, "bob");
    }
}
