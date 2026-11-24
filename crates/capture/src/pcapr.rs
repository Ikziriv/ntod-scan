//! Read classic .pcap and .pcapng captures — the input half of [`pcapw`].
//!
//! Pure Rust, no libpcap. Yields link-layer frames with timestamps; which
//! dissectors apply depends on the linktype (DLT): 1 = Ethernet,
//! 101 = raw IP, 113 = Linux SLL, 276 = SLL2.

/// One captured frame, borrowed from the input buffer.
#[derive(Debug)]
pub struct Pkt<'a> {
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// libpcap linktype (DLT) of the frame.
    pub linktype: u16,
    pub data: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a .pcap or .pcapng file (bad magic)")]
    BadMagic,
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("pcapng: bad byte-order magic")]
    BadEndian,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Iterate every packet in a .pcap/.pcapng buffer. `f` returns false to stop
/// early. Returns the number of packets yielded.
pub fn for_each<F>(bytes: &[u8], f: F) -> Result<usize, Error>
where
    F: FnMut(&Pkt<'_>) -> bool,
{
    match bytes {
        [0xd4, 0xc3, 0xb2, 0xa1, ..] => classic(bytes, true, false, f),
        [0xa1, 0xb2, 0xc3, 0xd4, ..] => classic(bytes, false, false, f),
        [0x4d, 0x3c, 0xb2, 0xa1, ..] => classic(bytes, true, true, f),
        [0xa1, 0xb2, 0x3c, 0x4d, ..] => classic(bytes, false, true, f),
        [0x0a, 0x0d, 0x0d, 0x0a, ..] => pcapng(bytes, f),
        _ => Err(Error::BadMagic),
    }
}

/// Largest single record accepted from a stream — corrupt headers can't
/// make the reader allocate unbounded buffers.
const MAX_REC: usize = 16 << 20;

/// Read a classic .pcap stream incrementally — the shape `tcpdump -w -`
/// produces on a pipe. `f` gets each frame and returns false to stop early.
/// Clean EOF and a truncated tail both end the stream without error.
pub fn read_stream<R: std::io::Read, F>(mut r: R, mut f: F) -> Result<usize, Error>
where
    F: FnMut(&Pkt<'_>) -> bool,
{
    let mut hdr = [0u8; 24];
    let (le, nano) = match r.read_exact(&mut hdr) {
        Ok(()) => match &hdr[..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
            _ => return Err(Error::BadMagic),
        },
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(Error::Truncated("pcap global header"));
        }
        Err(e) => return Err(e.into()),
    };
    let linktype = u16_at(&hdr, 20, le);

    let mut rec = [0u8; 16];
    let mut buf: Vec<u8> = Vec::new();
    let mut n = 0;
    loop {
        match r.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(n),
            Err(e) => return Err(e.into()),
        }
        let sec = u32_at(&rec, 0, le) as i64;
        let frac = u32_at(&rec, 4, le) as i64;
        let incl = u32_at(&rec, 8, le) as usize;
        if incl > MAX_REC {
            return Err(Error::Truncated("pcap record"));
        }
        buf.resize(incl, 0);
        match r.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(n),
            Err(e) => return Err(e.into()),
        }
        let ts_ms = sec * 1000 + if nano { frac / 1_000_000 } else { frac / 1_000 };
        n += 1;
        if !f(&Pkt {
            ts_ms,
            linktype,
            data: &buf,
        }) {
            return Ok(n);
        }
    }
}

fn u16_at(b: &[u8], i: usize, le: bool) -> u16 {
    let a: [u8; 2] = b[i..i + 2].try_into().unwrap();
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}

fn u32_at(b: &[u8], i: usize, le: bool) -> u32 {
    let a: [u8; 4] = b[i..i + 4].try_into().unwrap();
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

/// Classic libpcap file: 24-byte global header, 16-byte record headers.
fn classic<F>(bytes: &[u8], le: bool, nano: bool, mut f: F) -> Result<usize, Error>
where
    F: FnMut(&Pkt<'_>) -> bool,
{
    if bytes.len() < 24 {
        return Err(Error::Truncated("pcap global header"));
    }
    let linktype = u16_at(bytes, 20, le);
    let mut cur = 24usize;
    let mut n = 0;
    while bytes.len().saturating_sub(cur) >= 16 {
        let sec = u32_at(bytes, cur, le) as i64;
        let frac = u32_at(bytes, cur + 4, le) as i64;
        let incl = u32_at(bytes, cur + 8, le) as usize;
        cur += 16;
        let end = cur
            .checked_add(incl)
            .filter(|&e| e <= bytes.len())
            .ok_or(Error::Truncated("pcap record"))?;
        let ts_ms = sec * 1000 + if nano { frac / 1_000_000 } else { frac / 1_000 };
        let pkt = Pkt {
            ts_ms,
            linktype,
            data: &bytes[cur..end],
        };
        n += 1;
        if !f(&pkt) {
            return Ok(n);
        }
        cur = end;
    }
    Ok(n)
}

/// Per-interface timestamp resolution for pcapng EPBs.
enum TsRes {
    /// Value is 10^-x seconds: ts_ms = ts * 1000 / divisor.
    Pow10(u64),
    /// Value is 2^-x seconds: ts_ms = (ts * 1000) >> x.
    Pow2(u8),
}

impl TsRes {
    fn to_ms(&self, ts: u64) -> i64 {
        let ms = match self {
            Self::Pow10(div) => (ts as u128).saturating_mul(1000) / (*div as u128).max(1),
            Self::Pow2(x) => (ts as u128).saturating_mul(1000) >> (*x).min(63),
        };
        ms.min(i64::MAX as u128) as i64
    }
}

struct Iface {
    linktype: u16,
    snaplen: usize,
    tsres: TsRes,
}

/// PCAP Next Generation: SHB / IDB / EPB / SPB block walk.
/// Handles per-interface linktypes, snaplens, and timestamp resolutions.
fn pcapng<F>(bytes: &[u8], mut f: F) -> Result<usize, Error>
where
    F: FnMut(&Pkt<'_>) -> bool,
{
    let mut le = true;
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut cur = 0usize;
    let mut n = 0;

    while bytes.len().saturating_sub(cur) >= 12 {
        let btype = u32_at(bytes, cur, le);
        let mut blen = u32_at(bytes, cur + 4, le) as usize;

        // Section Header Block — the byte-order magic inside decides endianness.
        if btype == 0x0a0d0d0a {
            le = match &bytes[cur + 8..cur + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err(Error::BadEndian),
            };
            blen = u32_at(bytes, cur + 4, le) as usize;
            ifaces.clear();
        }

        let block_end = cur
            .checked_add(blen)
            .filter(|&e| blen >= 12 && e <= bytes.len())
            .ok_or(Error::Truncated("pcapng block"))?;
        let body = &bytes[cur + 8..block_end - 4];

        match btype {
            // Interface Description Block.
            0x0000_0001 => {
                if body.len() < 8 {
                    return Err(Error::Truncated("pcapng IDB"));
                }
                let linktype = u16_at(body, 0, le);
                let snaplen = u32_at(body, 4, le) as usize;
                // if_tsresol option (code 9): default is 10^-6 s.
                let mut r = TsRes::Pow10(1_000_000);
                let mut o = 8usize;
                while body.len().saturating_sub(o) >= 4 {
                    let code = u16_at(body, o, le);
                    let olen = u16_at(body, o + 2, le) as usize;
                    o += 4;
                    if code == 0 {
                        break;
                    }
                    if olen > body.len().saturating_sub(o) {
                        break;
                    }
                    if code == 9 && olen >= 1 {
                        let v = body[o];
                        if v & 0x80 != 0 {
                            let shift = v & 0x7f;
                            if shift < 64 {
                                r = TsRes::Pow2(shift);
                            }
                        } else if v <= 19 {
                            r = TsRes::Pow10(10u64.pow(v as u32));
                        }
                    }
                    let padded = olen.div_ceil(4).saturating_mul(4);
                    o = o.saturating_add(padded);
                }
                ifaces.push(Iface {
                    linktype,
                    snaplen,
                    tsres: r,
                });
            }
            // Enhanced Packet Block.
            0x0000_0006 => {
                if body.len() < 20 {
                    return Err(Error::Truncated("pcapng EPB"));
                }
                let iface_idx = u32_at(body, 0, le) as usize;
                let ts = ((u32_at(body, 4, le) as u64) << 32) | u32_at(body, 8, le) as u64;
                let caplen = u32_at(body, 12, le) as usize;
                let data_end = 20usize
                    .checked_add(caplen)
                    .filter(|&e| e <= body.len())
                    .ok_or(Error::Truncated("pcapng EPB data"))?;
                let (ts_ms, lt) = match ifaces.get(iface_idx) {
                    Some(i) => (i.tsres.to_ms(ts), i.linktype),
                    None => (TsRes::Pow10(1_000_000).to_ms(ts), u16::MAX),
                };
                n += 1;
                if !f(&Pkt {
                    ts_ms,
                    linktype: lt,
                    data: &body[20..data_end],
                }) {
                    return Ok(n);
                }
            }
            // Simple Packet Block — no timestamp, interface 0.
            0x0000_0003 => {
                if body.len() < 4 {
                    return Err(Error::Truncated("pcapng SPB"));
                }
                let orig = u32_at(body, 0, le) as usize;
                let (lt, snaplen) = ifaces
                    .first()
                    .map_or((u16::MAX, 262_144), |i| (i.linktype, i.snaplen));
                let cap = orig.min(snaplen).min(body.len() - 4);
                n += 1;
                if !f(&Pkt {
                    ts_ms: 0,
                    linktype: lt,
                    data: &body[4..4 + cap],
                }) {
                    return Ok(n);
                }
            }
            _ => {}
        }
        cur = block_end;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapw::PcapWriter;

    #[test]
    fn roundtrip_classic_pcap() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1500, &[0x45, 0, 0, 0x28]).unwrap();
        w.write_packet(2500, &[0x46, 0, 0, 0x30]).unwrap();
        let file = w.into_inner().unwrap();

        let mut seen = Vec::new();
        let n = for_each(&file, |p| {
            seen.push((p.ts_ms, p.linktype, p.data.to_vec()));
            true
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(seen[0], (1500, 101, vec![0x45, 0, 0, 0x28]));
        assert_eq!(seen[1], (2500, 101, vec![0x46, 0, 0, 0x30]));
    }

    #[test]
    fn read_stream_yields_each_record_and_tolerates_short_tail() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1500, &[0x45, 0, 0, 0x28]).unwrap();
        w.write_packet(2500, &[0x46, 0, 0, 0x30]).unwrap();
        let file = w.into_inner().unwrap();

        let mut seen = Vec::new();
        let n = read_stream(&file[..], |p| {
            seen.push((p.ts_ms, p.linktype, p.data.to_vec()));
            true
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(seen[0], (1500, 101, vec![0x45, 0, 0, 0x28]));

        // Cut mid-record: the partial tail is dropped, not an error.
        let mut seen = Vec::new();
        let n = read_stream(&file[..file.len() - 3], |p| {
            seen.push(p.ts_ms);
            true
        })
        .unwrap();
        assert_eq!((n, seen.len()), (1, 1));

        assert!(matches!(
            read_stream(&[0u8; 24][..], |_| true),
            Err(Error::BadMagic)
        ));
        assert!(matches!(
            read_stream(&b"tiny"[..], |_| true),
            Err(Error::Truncated(_))
        ));
    }

    #[test]
    fn reads_pcapng() {
        // SHB (LE) + IDB(linktype 101) + EPB(ts=1500ms in µs units).
        let mut f = Vec::new();
        f.extend_from_slice(&0x0a0d0d0au32.to_le_bytes()); // SHB type
        f.extend_from_slice(&28u32.to_le_bytes()); // block len
        f.extend_from_slice(&0x1a2b3c4du32.to_le_bytes()); // BOM (LE)
        f.extend_from_slice(&1u16.to_le_bytes()); // ver major
        f.extend_from_slice(&0u16.to_le_bytes()); // ver minor
        f.extend_from_slice(&(-1i64).to_le_bytes()); // section len
        f.extend_from_slice(&28u32.to_le_bytes());
        f.extend_from_slice(&1u32.to_le_bytes()); // IDB
        f.extend_from_slice(&20u32.to_le_bytes());
        f.extend_from_slice(&101u16.to_le_bytes()); // DLT_RAW
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        f.extend_from_slice(&20u32.to_le_bytes());
        f.extend_from_slice(&6u32.to_le_bytes()); // EPB
        f.extend_from_slice(&36u32.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes()); // iface 0
        f.extend_from_slice(&0u32.to_le_bytes()); // ts hi
        f.extend_from_slice(&1_500_000u32.to_le_bytes()); // ts lo (µs)
        f.extend_from_slice(&4u32.to_le_bytes()); // caplen
        f.extend_from_slice(&4u32.to_le_bytes()); // len
        f.extend_from_slice(&[0x45, 0, 0, 0x28]);
        f.extend_from_slice(&36u32.to_le_bytes());

        let mut seen = Vec::new();
        for_each(&f, |p| {
            seen.push((p.ts_ms, p.linktype));
            true
        })
        .unwrap();
        assert_eq!(seen, vec![(1500, 101)]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            for_each(b"not a pcap", |_| true),
            Err(Error::BadMagic)
        ));
    }

    #[test]
    fn nanosecond_ts_and_extreme_tsresol_do_not_overflow() {
        // Real-world 2024 epoch timestamp in nanoseconds (~1.7e18) would overflow u64 * 1000.
        let ns_res = TsRes::Pow10(1_000_000_000);
        let ts_ns: u64 = 1_700_000_000_123_000_000;
        assert_eq!(ns_res.to_ms(ts_ns), 1_700_000_000_123);

        // Extreme Pow2 shift does not panic.
        let bin_res = TsRes::Pow2(63);
        let _ = bin_res.to_ms(u64::MAX);
    }
}
