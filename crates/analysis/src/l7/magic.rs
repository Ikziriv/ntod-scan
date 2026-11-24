//! Magic-byte MIME sniffing for carved objects — the declared
//! Content-Type is attacker-controlled; the first bytes are not.

/// MIME-ish label from leading bytes, `None` when unrecognized.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.len() < 4 {
        return None;
    }
    Some(match &b[..4] {
        [0x4D, 0x5A, ..] => "exe",
        [b'%', b'P', b'D', b'F'] => "pdf",
        [b'P', b'K', 0x03, 0x04] => "zip",
        [0x89, b'P', b'N', b'G'] => "png",
        [0xFF, 0xD8, 0xFF, ..] => "jpeg",
        [b'G', b'I', b'F', b'8'] => "gif",
        [0x1F, 0x8B, ..] => "gzip",
        [0x7F, b'E', b'L', b'F'] => "elf",
        [0xCA, 0xFE, 0xBA, 0xBE] => "class",
        [b'R', b'I', b'F', b'F'] => "riff",
        [b'I', b'D', b'3', ..] => "mp3",
        [b'd', b'e', b'x', 0x0A] => "dex",
        _ => {
            if b.starts_with(b"SQLite format 3") {
                "sqlite"
            } else if b.len() > 8 && &b[4..8] == b"ftyp" {
                "mp4"
            } else if b.starts_with(b"<?xml") || b.starts_with(b"<xml") {
                "xml"
            } else if b.starts_with(b"{\\rtf") {
                "rtf"
            } else if looks_text(b) {
                "text"
            } else {
                return None;
            }
        }
    })
}

fn looks_text(b: &[u8]) -> bool {
    b.iter()
        .take(64)
        .all(|&c| c.is_ascii_graphic() || c == b' ' || c == b'\n' || c == b'\r' || c == b'\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common() {
        assert_eq!(sniff(b"MZ\x90\x00").unwrap(), "exe");
        assert_eq!(sniff(b"%PDF-1.7").unwrap(), "pdf");
        assert_eq!(sniff(b"PK\x03\x04rest").unwrap(), "zip");
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n").unwrap(), "png");
        assert_eq!(sniff(b"\xFF\xD8\xFF\xE0").unwrap(), "jpeg");
        assert_eq!(sniff(b"\x1F\x8B\x08\x00").unwrap(), "gzip");
        assert_eq!(sniff(b"\x7FELF\x02").unwrap(), "elf");
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n").unwrap(), "text");
        assert!(sniff(b"\x00\x01\x02\x03").is_none());
    }
}
