//! HTTP/1.x header parser — request or response, from a flow head buffer.
//!
//! Single-buffer view only: headers split past the head cap or body bytes
//! beyond it are not seen. Enough for triage views.

#[derive(Debug, Clone)]
pub enum HttpKind {
    Request { method: String, path: String },
    Response { status: u16 },
}

#[derive(Debug, Clone)]
pub struct HttpMsg {
    pub kind: HttpKind,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub location: Option<String>,
    /// `Authorization: Basic …` decoded to "user:pass" — mask before display.
    pub basic_auth: Option<String>,
    /// `Content-Length` when declared — lets `parse_all` skip bodies.
    pub content_length: Option<usize>,
    /// `Transfer-Encoding: chunked` — body needs dechunking to carve.
    pub chunked: bool,
    /// Body start offset, when the header terminator was seen.
    pub body_off: usize,
    /// True when the header block was complete within the buffer.
    pub complete: bool,
}

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

fn is_request_prefix(b: &[u8]) -> bool {
    METHODS
        .iter()
        .any(|m| b.len() > m.len() && &b[..m.len()] == m.as_bytes() && b[m.len()] == b' ')
}

/// Parse a flow head buffer as HTTP/1.x. `None` when it isn't HTTP.
pub fn parse(b: &[u8]) -> Option<HttpMsg> {
    let is_resp = b.starts_with(b"HTTP/");
    let is_req = !is_resp && is_request_prefix(b);
    if !is_resp && !is_req {
        return None;
    }
    let head_end = find(b, b"\r\n\r\n").map(|i| i + 4);
    let region = &b[..head_end.unwrap_or(b.len()).min(b.len())];
    let text = String::from_utf8_lossy(region);
    let mut lines = text.split("\r\n");
    let first = lines.next()?;

    let kind = if is_resp {
        let status = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        HttpKind::Response { status }
    } else {
        let mut it = first.split_whitespace();
        HttpKind::Request {
            method: it.next().unwrap_or_default().to_string(),
            path: it.next().unwrap_or_default().to_string(),
        }
    };

    let mut msg = HttpMsg {
        kind,
        host: None,
        user_agent: None,
        content_type: None,
        location: None,
        basic_auth: None,
        content_length: None,
        chunked: false,
        body_off: head_end.unwrap_or(b.len()),
        complete: head_end.is_some(),
    };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("host") {
            msg.host = Some(v.into());
        } else if k.eq_ignore_ascii_case("user-agent") {
            msg.user_agent = Some(v.into());
        } else if k.eq_ignore_ascii_case("content-type") {
            msg.content_type = Some(v.into());
        } else if k.eq_ignore_ascii_case("location") {
            msg.location = Some(v.into());
        } else if k.eq_ignore_ascii_case("content-length") {
            msg.content_length = v.parse().ok();
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            msg.chunked = v
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"));
        } else if k.eq_ignore_ascii_case("authorization")
            && v.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("basic "))
        {
            msg.basic_auth = super::creds::decode_b64_utf8(v[6..].trim());
        }
    }
    Some(msg)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse every message in a reassembled stream — pipelined requests and
/// keep-alive connections hold several. Returns `(stream_offset, msg)`
/// pairs so callers can locate bodies for carving. Stops at the first
/// unparsable byte or after 8 messages; bodies are skipped via
/// Content-Length (chunked or incomplete bodies end the parse).
pub fn parse_all(b: &[u8]) -> Vec<(usize, HttpMsg)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < b.len() && out.len() < 8 {
        let Some(m) = parse(&b[pos..]) else { break };
        let stop = m.chunked || !m.complete;
        let next = m.body_off.saturating_add(m.content_length.unwrap_or(0));
        out.push((pos, m));
        if stop || next == 0 {
            break;
        }
        pos = pos.saturating_add(next);
    }
    out
}

/// Decode a chunked body starting at `b`. Returns `(body, complete)` —
/// `complete=false` means the terminator chunk wasn't in the buffer, so
/// `body` is a prefix. Output is capped at 256 KB.
pub fn dechunk(b: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // "SIZE\r\n" — chunk header line (may carry ;extensions).
        let Some(eol) = find(&b[pos..], b"\r\n") else {
            return (out, false);
        };
        let size_str = std::str::from_utf8(&b[pos..pos + eol])
            .ok()
            .and_then(|s| s.split(';').next());
        let Some(size) = size_str.and_then(|s| usize::from_str_radix(s.trim(), 16).ok()) else {
            return (out, false);
        };
        pos += eol + 2;
        if size == 0 {
            // Terminator — trailers may follow, but the body is done.
            return (out, true);
        }
        if size > b.len() - pos {
            let take = (b.len() - pos).min((256usize << 10).saturating_sub(out.len()));
            out.extend_from_slice(&b[pos..pos + take]);
            return (out, false);
        }
        let room = (256usize << 10).saturating_sub(out.len());
        let take = size.min(room);
        out.extend_from_slice(&b[pos..pos + take]);
        // Skip data + trailing CRLF, staying in bounds if it's missing.
        pos = (pos + size + 2).min(b.len());
        if out.len() >= 256 << 10 {
            return (out, false);
        }
    }
}

/// Looks like the start of an HTTP message (cheap check before parsing).
pub fn probe(b: &[u8]) -> bool {
    b.starts_with(b"HTTP/") || is_request_prefix(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request() {
        let b = b"GET /x?a=1 HTTP/1.1\r\nHost: ex.com\r\nUser-Agent: curl/8\r\n\r\nBODY";
        let m = parse(b).unwrap();
        let HttpKind::Request { method, path } = &m.kind else {
            panic!("expected request");
        };
        assert_eq!(method, "GET");
        assert_eq!(path, "/x?a=1");
        assert_eq!(m.host.as_deref(), Some("ex.com"));
        assert!(m.complete);
        assert_eq!(&b[m.body_off..], b"BODY");
    }

    #[test]
    fn parses_basic_auth() {
        // "user:pass" = dXNlcjpwYXNz
        let b = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let m = parse(b).unwrap();
        assert_eq!(m.basic_auth.as_deref(), Some("user:pass"));
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse(b"\x16\x03\x01\x00\x05").is_none());
        assert!(!probe(b"\x16\x03\x01"));
    }

    #[test]
    fn parse_all_pipelined() {
        let b = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
                  POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc\
                  GET /c HTTP/1.1\r\nHost: y\r\n\r\n";
        let v = parse_all(b);
        assert_eq!(v.len(), 3);
        let paths: Vec<&str> = v
            .iter()
            .filter_map(|(_, m)| match &m.kind {
                HttpKind::Request { path, .. } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, ["/a", "/b", "/c"]);
        assert_eq!(v[2].1.host.as_deref(), Some("y"));
    }

    #[test]
    fn dechunks_body() {
        let (body, done) = dechunk(b"4\r\nMZ\x90\x00\r\n5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(body, b"MZ\x90\x00hello");
        assert!(done);
        let (partial, done) = dechunk(b"a\r\n0123456789\r\nf\r\nshort");
        assert!(partial.starts_with(b"0123456789"));
        assert!(!done);
        // Hostile inputs: huge size, missing CRLF after data, junk size.
        let (b1, done1) = dechunk(b"ffffffffffffffff\r\nMZ\r\n");
        assert_eq!(b1, b"MZ\r\n");
        assert!(!done1);
        let (_, done2) = dechunk(b"2\r\nAB");
        assert!(!done2);
        let (b3, done3) = dechunk(b"zzz\r\n");
        assert!(b3.is_empty());
        assert!(!done3);
    }

    #[test]
    fn huge_content_length_does_not_overflow() {
        let b = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
                  POST /b HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n";
        let v = parse_all(b);
        assert_eq!(v.len(), 2);
    }
}
