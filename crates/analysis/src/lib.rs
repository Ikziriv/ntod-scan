//! ntod-analysis: pcap triage engine.
//!
//! Feed it a .pcap/.pcapng buffer and get a report: conversations, DNS,
//! HTTP, TLS fingerprints, credentials, and detector findings — the same
//! layer WebPCAP / A-Packets / ScanSuite sell as a cloud service, except
//! this one runs entirely on your own machine.

mod engine;

pub mod detect;
pub mod flow;
pub mod history;
pub mod l7;
pub mod report;

pub use report::Report;

/// Hash builder for all engine/detector maps: foldhash's *quality*
/// variant — fast like hashbrown's default, but seeded per map so a
/// hostile capture can't precompute colliding keys (SipHash-class
/// DoS resistance without SipHash cost).
pub(crate) type FastMap<K, V> = hashbrown::HashMap<K, V, foldhash::quality::RandomState>;
pub(crate) type FastSet<T> = hashbrown::HashSet<T, foldhash::quality::RandomState>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pcap(#[from] ntod_capture::pcapr::Error),
    #[error(transparent)]
    Capture(#[from] ntod_capture::Error),
    #[error("{0}")]
    Unavailable(&'static str),
}

/// Analyze a capture buffer into a [`Report`].
///
/// Live capture can reuse the same pipeline later — `engine` is the seam;
/// today the supported input is a capture file (`.pcap` or `.pcapng`).
pub fn analyze(bytes: &[u8]) -> Result<Report, Error> {
    let mut a = Analyzer::new();
    ntod_capture::pcapr::for_each(bytes, |p| {
        a.feed(p.ts_ms, p.linktype, p.data);
        true
    })?;
    Ok(a.finish())
}

/// [`analyze`], but also retain the raw frames (up to `keep_budget`
/// bytes) so the caller can re-export filtered subsets as pcap later.
/// `complete=false` means the budget ran out and later frames are missing.
pub fn analyze_retain(
    bytes: &[u8],
    keep_budget: usize,
) -> Result<(Report, Vec<ntod_capture::RawFrame>, bool), Error> {
    let mut a = Analyzer::new();
    let mut frames = Vec::new();
    let mut kept = 0usize;
    let mut complete = true;
    ntod_capture::pcapr::for_each(bytes, |p| {
        a.feed(p.ts_ms, p.linktype, p.data);
        if complete && p.data.len() <= keep_budget.saturating_sub(kept) {
            kept += p.data.len();
            frames.push(ntod_capture::RawFrame {
                ts_ms: p.ts_ms,
                linktype: p.linktype,
                data: p.data.to_vec(),
            });
        } else {
            complete = false;
        }
        true
    })?;
    Ok((a.finish(), frames, complete))
}

/// Incremental analysis driver — feed frames from any source (pcap,
/// live capture, replay), then [`Analyzer::finish`] into a [`Report`].
/// This is the seam the WS live-triage command uses.
pub struct Analyzer {
    eng: engine::Engine,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            eng: engine::Engine::new(report::Limits::default()),
        }
    }

    /// Ingest one captured frame (libpcap linktype + raw bytes).
    pub fn feed(&mut self, ts_ms: i64, linktype: u16, data: &[u8]) {
        self.eng.ingest(&ntod_capture::pcapr::Pkt {
            ts_ms,
            linktype,
            data,
        });
    }

    /// Packets ingested so far — for live progress messages.
    pub fn packets(&self) -> u64 {
        self.eng.packets()
    }

    /// Close out the flow table, dissect heads, run detectors → report.
    pub fn finish(self) -> Report {
        self.eng.finish()
    }
}

/// Drive a live frame channel into `a` until `dur` elapses,
/// `max_packets` is reached, `halt` returns true, or the channel
/// disconnects. `progress` fires about once a second with packets
/// ingested so far — return false from it to stop early. This is the one
/// pump loop the CLI, WS, and SSE capture drivers all share.
pub fn feed_channel(
    rx: &std::sync::mpsc::Receiver<ntod_capture::RawFrame>,
    a: &mut Analyzer,
    dur: std::time::Duration,
    max_packets: u64,
    halt: impl Fn() -> bool,
    mut progress: impl FnMut(u64) -> bool,
) {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + dur;
    let mut last = Instant::now();
    while a.packets() < max_packets
        && let Some(rem) = deadline.checked_duration_since(Instant::now())
    {
        if halt() {
            break;
        }
        match rx.recv_timeout(rem.min(Duration::from_millis(200))) {
            Ok(f) => a.feed(f.ts_ms, f.linktype, &f.data),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last.elapsed() >= Duration::from_secs(1) {
            last = Instant::now();
            if !progress(a.packets()) {
                break;
            }
        }
    }
}

/// Run the same engine over a *live* capture for `dur`, capped at
/// `max_packets`. This is the difference from the upload-only analyzers:
/// identical report, produced from the wire in real time.
///
/// Needs the same privileges as [`ntod_capture::start`].
pub fn analyze_live(
    bind_ip: std::net::Ipv4Addr,
    dur: std::time::Duration,
    max_packets: u64,
) -> Result<Report, Error> {
    let mut cap = ntod_capture::start(bind_ip)?;
    let Some(rx) = cap.take_rx() else {
        return Err(Error::Unavailable("capture channel missing"));
    };
    let mut a = Analyzer::new();
    feed_channel(&rx, &mut a, dur, max_packets, || false, |_| true);
    cap.stop();
    Ok(a.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntod_capture::pcapw::PcapWriter;

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let mut b = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        b.extend_from_slice(&src);
        b.extend_from_slice(&dst);
        let total = (20 + l4.len()) as u16;
        b[2..4].copy_from_slice(&total.to_be_bytes());
        b.extend_from_slice(l4);
        b
    }

    fn udp_dns_query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut u = vec![0x13, 0x88, 0, 53, 0, 0, 0, 0];
        let ulen = (8 + q.len()) as u16;
        u[4..6].copy_from_slice(&ulen.to_be_bytes());
        u.extend_from_slice(&q);
        ipv4(17, [10, 0, 0, 5], [8, 8, 8, 8], &u)
    }

    fn tcp_http_get() -> Vec<u8> {
        let payload = b"GET /login HTTP/1.1\r\nHost: test.local\r\nUser-Agent: curl/8\r\n\r\n";
        let mut t = vec![0xC0, 0xDE, 0, 80];
        t.extend_from_slice(&[0; 8]); // seq + ack
        t.extend_from_slice(&[0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0]);
        t.extend_from_slice(payload);
        ipv4(6, [10, 0, 0, 5], [93, 184, 216, 34], &t)
    }

    fn tcp_syn_sweep() -> Vec<Vec<u8>> {
        (1..40u16)
            .map(|p| {
                let mut t = vec![0xC0, 0xDF, (p >> 8) as u8, p as u8];
                t.extend_from_slice(&[0; 8]);
                t.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0]);
                ipv4(6, [10, 0, 0, 9], [10, 0, 0, 1], &t)
            })
            .collect()
    }

    #[test]
    fn end_to_end_report() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1000, &udp_dns_query()).unwrap();
        w.write_packet(1500, &tcp_http_get()).unwrap();
        for (i, pkt) in tcp_syn_sweep().iter().enumerate() {
            w.write_packet(2000 + i as i64, pkt).unwrap();
        }
        let file = w.into_inner().unwrap();

        let r = analyze(&file).unwrap();
        assert_eq!(r.meta.packets, 41);
        assert_eq!(r.dns.len(), 1);
        assert_eq!(&*r.dns[0].name, "www.example.com");
        assert_eq!(r.http.len(), 1);
        assert_eq!(r.http[0].host.as_deref(), Some("test.local"));
        assert!(
            r.findings.iter().any(|f| f.kind == "port-scan"),
            "expected port-scan finding, got {:?}",
            r.findings.iter().map(|f| f.kind).collect::<Vec<_>>()
        );
        assert!(!r.conversations.is_empty());
        assert!(r.hosts.iter().any(|h| h.ip.to_string() == "10.0.0.9"));
    }

    fn tcp_http_response() -> Vec<u8> {
        // "executable" download body — magic-sniffed as exe.
        let body = b"MZ\x90\x00body!!";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut t = vec![0, 80, 0xC0, 0xDE];
        t.extend_from_slice(&[0; 8]);
        t.extend_from_slice(&[0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0]);
        t.extend_from_slice(head.as_bytes());
        t.extend_from_slice(body);
        ipv4(6, [93, 184, 216, 34], [10, 0, 0, 5], &t)
    }

    fn udp_snmp_get() -> Vec<u8> {
        // 30 0b SEQ{ 02 01 00 INTEGER v1, 04 06 "s3cr3t" community }
        let mut pdu = vec![0x30, 0x0b, 0x02, 0x01, 0x00, 0x04, 0x06];
        pdu.extend_from_slice(b"s3cr3t");
        let mut u = vec![0x10, 0x00, 0, 161, 0, 0, 0, 0];
        let ulen = (8 + pdu.len()) as u16;
        u[4..6].copy_from_slice(&ulen.to_be_bytes());
        u.extend_from_slice(&pdu);
        ipv4(17, [10, 0, 0, 9], [10, 0, 0, 1], &u)
    }

    #[test]
    fn carving_snmp_and_host_hints() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1000, &tcp_http_get()).unwrap();
        w.write_packet(1100, &tcp_http_response()).unwrap();
        w.write_packet(1200, &udp_snmp_get()).unwrap();
        let file = w.into_inner().unwrap();

        let r = analyze(&file).unwrap();
        // Exchange pairs the request with the response.
        assert_eq!(r.http.len(), 1);
        assert_eq!(r.http[0].status, Some(200));
        assert_eq!(r.http[0].method.as_deref(), Some("GET"));
        // Carved object: magic-sniffed, host/path from the request.
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].mime, "exe");
        assert_eq!(&r.objects[0].data[..4], b"MZ\x90\x00");
        assert_eq!(r.objects[0].path.as_deref(), Some("/login"));
        // SNMP community extracted.
        assert!(
            r.credentials.iter().any(|c| c.proto == "snmp-community"),
            "expected snmp cred, got {:?}",
            r.credentials.iter().map(|c| c.proto).collect::<Vec<_>>()
        );
        // TTL=64 fixture → Unix-like hint.
        let h = r
            .hosts
            .iter()
            .find(|h| h.ip.to_string() == "10.0.0.5")
            .unwrap();
        assert_eq!(h.os, Some("Unix-like"));
        // Port 80 served by the remote endpoint.
        let srv = r
            .hosts
            .iter()
            .find(|h| h.ip.to_string() == "93.184.216.34")
            .unwrap();
        assert!(srv.ports.contains(&80));
    }

    fn tcp_http_chunked_response() -> Vec<u8> {
        // Chunked-encoded body: "4\r\nMZ\x90\x00\r\n5\r\nchunk\r\n0\r\n\r\n"
        let body = b"4\r\nMZ\x90\x00\r\n5\r\nchunk\r\n0\r\n\r\n";
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut t = vec![0, 80, 0xC0, 0xDE];
        t.extend_from_slice(&[0; 8]);
        t.extend_from_slice(&[0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0]);
        t.extend_from_slice(head);
        t.extend_from_slice(body);
        ipv4(6, [93, 184, 216, 34], [10, 0, 0, 5], &t)
    }

    #[test]
    fn retain_keeps_frames_within_budget() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1000, &tcp_http_get()).unwrap();
        w.write_packet(1100, &tcp_http_response()).unwrap();
        w.write_packet(1200, &udp_snmp_get()).unwrap();
        let file = w.into_inner().unwrap();

        let (r, frames, complete) = analyze_retain(&file, 1 << 20).unwrap();
        assert_eq!(r.meta.packets, 3);
        assert_eq!(frames.len(), 3);
        assert!(complete);
        // A tiny budget truncates retention but not the report.
        let (r2, frames2, complete2) = analyze_retain(&file, 1).unwrap();
        assert_eq!(r2.meta.packets, 3);
        assert!(frames2.len() < 3);
        assert!(!complete2);
    }

    #[test]
    fn carves_chunked_body() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_packet(1000, &tcp_http_get()).unwrap();
        w.write_packet(1100, &tcp_http_chunked_response()).unwrap();
        let file = w.into_inner().unwrap();

        let r = analyze(&file).unwrap();
        assert_eq!(r.objects.len(), 1);
        assert_eq!(r.objects[0].mime, "exe");
        assert_eq!(r.objects[0].data, b"MZ\x90\x00chunk");
        assert!(!r.objects[0].truncated);
    }
}
