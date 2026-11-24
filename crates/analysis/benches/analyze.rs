//! `analyze()` throughput on a synthetic mixed-traffic pcap.
//!
//! The workload exercises the per-packet hot path end to end: flow-table
//! churn (many TCP flows), stream reassembly + L7 dissection (HTTP),
//! DNS events, scan fan-out aggregation, and ARP bookkeeping.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ntod_capture::pcapw::PcapWriter;

/// Deterministic PRNG — bench input must be identical run to run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let mut b = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    let total = (20 + l4.len()) as u16;
    b[2..4].copy_from_slice(&total.to_be_bytes());
    b.extend_from_slice(l4);
    b
}

fn eth(payload: &[u8], etype: u16) -> Vec<u8> {
    let mut f = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ];
    f.extend_from_slice(&etype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    u.extend_from_slice(&ulen.to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

fn arp_reply(spa: [u8; 4], sha: [u8; 6]) -> Vec<u8> {
    let mut a = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02];
    a.extend_from_slice(&sha);
    a.extend_from_slice(&spa);
    a.extend_from_slice(&[0; 10]); // tha + tpa
    eth(&a, 0x0806)
}

/// ~36k Ethernet frames: HTTP-ish TCP flows, DNS queries, a port sweep,
/// ARP replies. Returns the serialized pcap and the packet count.
fn build_pcap() -> (Vec<u8>, u64) {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut w = PcapWriter::with_linktype(Vec::new(), 1).unwrap();
    let mut n = 0u64;
    let mut put = |w: &mut PcapWriter<Vec<u8>>, ts: i64, f: &[u8]| {
        w.write_packet(ts, f).unwrap();
        n += 1;
    };
    let mut ts = 0i64;
    let mut next_ts = |rng: &mut Rng| {
        ts += 1 + (rng.next() % 40) as i64;
        ts
    };

    // 240 TCP flows x ~30 packets with payload — flow table + streams.
    for flow in 0..240u16 {
        let cli = [10, 0, (flow / 100) as u8, (flow % 100 + 2) as u8];
        let srv = [93, 184, 216, (flow % 200 + 1) as u8];
        let sport = 49152 + flow;
        let mut seq = 1u32;
        for seg in 0..15u32 {
            let body = format!(
                "GET /f{flow}/{seg} HTTP/1.1\r\nHost: h{}.local\r\n\r\n",
                flow % 40
            );
            let p = tcp(sport, 80, seq, 1, 0x18, body.as_bytes());
            seq += body.len() as u32;
            put(
                &mut w,
                next_ts(&mut rng),
                &eth(&ipv4(6, cli, srv, &p), 0x0800),
            );
            let r = tcp(
                80,
                sport,
                1,
                seq,
                0x18,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            );
            put(
                &mut w,
                next_ts(&mut rng),
                &eth(&ipv4(6, srv, cli, &r), 0x0800),
            );
        }
    }

    // ~2500 UDP DNS queries to varying names.
    for i in 0..2500u32 {
        let name = format!("h{}.dyn{}.example.com", i % 700, i % 40);
        let q = udp(53000 + (i % 1000) as u16, 53, &dns_query(&name));
        put(
            &mut w,
            next_ts(&mut rng),
            &eth(&ipv4(17, [10, 0, 1, 5], [8, 8, 8, 8], &q), 0x0800),
        );
    }

    // Port sweep: one source, 25 dsts x 200 ports.
    for d in 0..25u8 {
        for p in 0..200u16 {
            let s = tcp(40000, 1024 + p, 1, 0, 0x02, &[]);
            put(
                &mut w,
                next_ts(&mut rng),
                &eth(&ipv4(6, [10, 0, 0, 9], [10, 0, 0, d + 1], &s), 0x0800),
            );
        }
    }

    // ARP replies, a few conflicting is-at claims.
    for i in 0..60u8 {
        let sha = [0x02, 0, 0, 0, 0, i % 7];
        put(
            &mut w,
            next_ts(&mut rng),
            &arp_reply([192, 168, 1, i % 9], sha),
        );
    }

    (w.into_inner().unwrap(), n)
}

fn bench_analyze(c: &mut Criterion) {
    let (pcap, packets) = build_pcap();
    let mut g = c.benchmark_group("analyze");
    g.throughput(Throughput::Elements(packets));
    g.bench_function(BenchmarkId::new("mixed_pcap", packets), |b| {
        b.iter(|| ntod_analysis::analyze(std::hint::black_box(&pcap)).unwrap())
    });
    g.finish();
}

/// Per-frame decode — the WS sniff path's unit cost before batching.
fn bench_decode(c: &mut Criterion) {
    let p = tcp(40000, 80, 1, 1, 0x18, b"GET /x HTTP/1.1\r\n\r\n");
    let frame = eth(&ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &p), 0x0800);
    let mut g = c.benchmark_group("decode");
    g.throughput(Throughput::Bytes(frame.len() as u64));
    g.bench_function("eth_tcp", |b| {
        b.iter(|| ntod_capture::decode::decode_frame(1, std::hint::black_box(&frame), 0))
    });
    g.finish();
}

criterion_group!(benches, bench_analyze, bench_decode);
criterion_main!(benches);
