//! Minimal classic .pcap writer — pure Rust, no libpcap.
//! Writes DLT_RAW (linktype 101): IPv4 datagrams, matching our captures.
//! Output opens in Wireshark directly.

use std::io::{BufWriter, Write};

/// Streaming pcap writer over any `Write` sink.
pub struct PcapWriter<W: Write> {
    w: BufWriter<W>,
    snaplen: u32,
}

impl<W: Write> PcapWriter<W> {
    /// Write the global pcap header (little-endian, DLT_RAW).
    pub fn new(sink: W) -> std::io::Result<Self> {
        Self::with_linktype(sink, 101)
    }

    /// Same, with an explicit linktype — needed to re-export frames that
    /// arrived as Ethernet (1) or any other DLT the capture carried.
    pub fn with_linktype(sink: W, linktype: u16) -> std::io::Result<Self> {
        let mut w = BufWriter::new(sink);
        // magic, ver 2.4, thiszone, sigfigs, snaplen, linktype
        w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&65535u32.to_le_bytes())?;
        w.write_all(&(linktype as u32).to_le_bytes())?;
        Ok(Self { w, snaplen: 65535 })
    }

    /// One packet record: ts (secs, µs) + raw IPv4 bytes.
    pub fn write_packet(&mut self, ts_ms: i64, pkt: &[u8]) -> std::io::Result<()> {
        let ts_ms = ts_ms.max(0);
        let secs = (ts_ms / 1000) as u32;
        let usecs = ((ts_ms % 1000) * 1000) as u32;
        let len = pkt.len().min(self.snaplen as usize) as u32;
        self.w.write_all(&secs.to_le_bytes())?;
        self.w.write_all(&usecs.to_le_bytes())?;
        self.w.write_all(&len.to_le_bytes())?; // incl_len
        self.w.write_all(&(pkt.len() as u32).to_le_bytes())?; // orig_len
        self.w.write_all(&pkt[..len as usize])?;
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }

    /// Flush and return the underlying sink.
    pub fn into_inner(self) -> std::io::Result<W> {
        self.w
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_le_header_and_record() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1500, &[0x45, 0x00, 0x00, 0x28]).unwrap();
        let bytes = w.w.into_inner().unwrap();
        assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]); // LE magic
        assert_eq!(&bytes[20..24], &101u32.to_le_bytes()); // DLT_RAW
        let rec = &bytes[24..];
        assert_eq!(u32::from_le_bytes(rec[0..4].try_into().unwrap()), 1); // secs
        assert_eq!(u32::from_le_bytes(rec[8..12].try_into().unwrap()), 4); // incl_len
        assert_eq!(&rec[16..20], &[0x45, 0x00, 0x00, 0x28]);
    }
}
