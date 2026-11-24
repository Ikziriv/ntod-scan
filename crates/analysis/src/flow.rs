//! Bidirectional 5-tuple flow table with bounded state.
//!
//! Keys are canonicalized (lower endpoint first) so both directions land in
//! one flow — that is what lets HTTP requests pair with responses and TLS
//! ClientHellos pair with certificates. Beacon detection keeps per-direction
//! inter-arrival stats online via Welford's algorithm, O(1) per direction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::FastMap;

/// Max simultaneous flows tracked; new keys beyond this are counted only.
pub const MAX_FLOWS: usize = 200_000;
/// Reassembled payload kept per direction for L7 dissection.
pub const STREAM_CAP: usize = 32 * 1024;

/// IPv4 endpoint pair packed to 16 bytes — the LAN common case keeps
/// the flow table dense.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key4 {
    a_ip: u32,
    a_port: u16,
    b_ip: u32,
    b_port: u16,
    proto: u8,
}

/// IPv6 pair — 40 bytes; rare on LAN captures, pays full width only
/// where it actually occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key6 {
    a_ip: u128,
    a_port: u16,
    b_ip: u128,
    b_port: u16,
    proto: u8,
}

/// Packed v4 form of a canonical key, when it is one.
fn key4(key: &FlowKey) -> Option<Key4> {
    let (IpAddr::V4(a), IpAddr::V4(b)) = (key.a_ip, key.b_ip) else {
        return None;
    };
    Some(Key4 {
        a_ip: a.into(),
        a_port: key.a_port,
        b_ip: b.into(),
        b_port: key.b_port,
        proto: key.proto,
    })
}

/// Packed v6 form of a canonical key, when it is one.
fn key6(key: &FlowKey) -> Option<Key6> {
    let (IpAddr::V6(a), IpAddr::V6(b)) = (key.a_ip, key.b_ip) else {
        return None;
    };
    Some(Key6 {
        a_ip: a.into(),
        a_port: key.a_port,
        b_ip: b.into(),
        b_port: key.b_port,
        proto: key.proto,
    })
}

/// Canonical bidirectional flow key — the *materialized* view: produced
/// at ingest, handed to the report pass, but never stored in the table
/// (which keeps the packed per-family repr above). `a` is the
/// lexicographically lower `(ip, port)` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub a_port: u16,
    pub b_ip: IpAddr,
    pub b_port: u16,
    /// Raw IP protocol number (6 = TCP, 17 = UDP, …).
    pub proto: u8,
}

impl From<&Key4> for FlowKey {
    fn from(k: &Key4) -> Self {
        Self {
            a_ip: Ipv4Addr::from(k.a_ip).into(),
            a_port: k.a_port,
            b_ip: Ipv4Addr::from(k.b_ip).into(),
            b_port: k.b_port,
            proto: k.proto,
        }
    }
}

impl From<&Key6> for FlowKey {
    fn from(k: &Key6) -> Self {
        Self {
            a_ip: Ipv6Addr::from(k.a_ip).into(),
            a_port: k.a_port,
            b_ip: Ipv6Addr::from(k.b_ip).into(),
            b_port: k.b_port,
            proto: k.proto,
        }
    }
}

impl FlowKey {
    /// Canonical key + whether this packet travels a→b.
    pub fn new(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, proto: u8) -> (Self, bool) {
        let fwd = (src, sport) <= (dst, dport);
        let (a_ip, a_port, b_ip, b_port) = if fwd {
            (src, sport, dst, dport)
        } else {
            (dst, dport, src, sport)
        };
        (
            Self {
                a_ip,
                a_port,
                b_ip,
                b_port,
                proto,
            },
            fwd,
        )
    }

    /// The server-ish endpoint's port, if either is well-known.
    pub fn service_port(&self) -> u16 {
        if self.a_port < 1024 {
            self.a_port
        } else {
            self.b_port
        }
    }
}

/// Welford running stats for packet inter-arrival times.
/// `last_ts` uses i64::MIN as the unset sentinel — Option<i64> has no
/// niche and would cost 16 bytes per direction.
#[derive(Debug)]
struct Iar {
    n: u64,
    mean: f64,
    m2: f64,
    last_ts: i64,
}

impl Default for Iar {
    fn default() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
            last_ts: i64::MIN,
        }
    }
}

impl Iar {
    fn push(&mut self, ts: i64) {
        if self.last_ts != i64::MIN {
            let d = (ts - self.last_ts) as f64;
            if d >= 0.0 {
                self.n += 1;
                let delta = d - self.mean;
                self.mean += delta / self.n as f64;
                self.m2 += delta * (d - self.mean);
            }
        }
        self.last_ts = ts;
    }

    /// (sample_count, mean_ms, coefficient_of_variation).
    fn cadence(&self) -> Option<(u64, f64, f64)> {
        if self.n < 4 || self.mean <= 0.0 {
            return None;
        }
        let std = (self.m2 / self.n as f64).sqrt();
        Some((self.n + 1, self.mean, std / self.mean))
    }
}

/// Reassembled byte stream for one direction of a TCP flow — a
/// sequence-ordered contiguous prefix, bounded at `STREAM_CAP`.
/// Out-of-order segments are parked until the gap fills.
/// shortcut: keeps the contiguous prefix only — bytes past the cap are
/// dropped; upgrade to a windowed reassembler for file carving.
#[derive(Debug, Default)]
pub struct Stream {
    /// Contiguous bytes, anchored at the first payload seq seen
    /// (mid-stream captures anchor wherever observation started).
    data: Vec<u8>,
    /// Segments ahead of the prefix, keyed by absolute seq. A plain Vec —
    /// parked segments are rare and few, so linear scans beat tree nodes.
    pending: Vec<(u32, Vec<u8>)>,
    pending_len: usize,
    /// Seq number that `data[0]` corresponds to.
    base: Option<u32>,
    /// Payload bytes dropped at the cap.
    pub truncated: u64,
}

impl Stream {
    /// Contiguous reassembled prefix.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Feed one payload segment; `seq` is the TCP sequence number, `None`
    /// for datagram transports (appended verbatim). Returns bytes stored
    /// so the table can debit the global budget.
    fn feed(&mut self, seq: Option<u32>, payload: &[u8], budget: usize) -> usize {
        let Some(seq) = seq else {
            return self.append(payload, budget);
        };
        let base = *self.base.get_or_insert(seq);
        let rel = seq.wrapping_sub(base); // forward distance (wraps when behind)
        let stored = if rel as usize <= self.data.len() {
            // Overlaps or continues the prefix — append the new tail bytes.
            let off = (self.data.len() - rel as usize).min(payload.len());
            self.append(&payload[off..], budget)
        } else if seq != base && rel < STREAM_CAP as u32 {
            // Ahead of the prefix with a gap — park until the gap fills.
            self.park(seq, payload, budget)
        } else {
            let lrel = base.wrapping_sub(seq) as usize; // distance below anchor
            if lrel > 0 && lrel <= payload.len() {
                // Connects on the left — prepend the new head bytes.
                let n = lrel
                    .min(STREAM_CAP.saturating_sub(self.data.len()))
                    .min(budget);
                if n > 0 {
                    self.data.splice(0..0, payload[..n].iter().copied());
                    self.base = Some(base.wrapping_sub(n as u32));
                    n
                } else {
                    0
                }
            } else if lrel > payload.len() {
                // Gap below the anchor — park for the missing link.
                self.park(seq, payload, budget)
            } else {
                self.truncated += payload.len() as u64;
                0
            }
        };
        self.drain_pending();
        stored
    }

    fn park(&mut self, seq: u32, payload: &[u8], budget: usize) -> usize {
        let room = STREAM_CAP.saturating_sub(self.data.len() + self.pending_len);
        let n = payload.len().min(room).min(budget);
        if n == 0 {
            self.truncated += payload.len() as u64;
            return 0;
        }
        if let Some(slot) = self.pending.iter_mut().find(|(s, _)| *s == seq) {
            self.pending_len = self.pending_len - slot.1.len() + n;
            slot.1 = payload[..n].to_vec();
        } else {
            self.pending.push((seq, payload[..n].to_vec()));
            self.pending_len += n;
        }
        n
    }

    fn append(&mut self, bytes: &[u8], budget: usize) -> usize {
        let n = bytes
            .len()
            .min(STREAM_CAP.saturating_sub(self.data.len()))
            .min(budget);
        if n == 0 {
            self.truncated += bytes.len() as u64;
            return 0;
        }
        self.data.extend_from_slice(&bytes[..n]);
        n
    }

    /// Attach any pending segments that now connect to the prefix —
    /// forward (append) and backward (re-anchor) until stable.
    /// Uses wrapping TCP sequence-space comparisons.
    fn drain_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let Some(mut base) = self.base else { return };
        let seq_le = |a: u32, b: u32| (a.wrapping_sub(b) as i32) <= 0;
        let seq_lt = |a: u32, b: u32| (a.wrapping_sub(b) as i32) < 0;
        let seq_gt = |a: u32, b: u32| (a.wrapping_sub(b) as i32) > 0;
        let seq_ge = |a: u32, b: u32| (a.wrapping_sub(b) as i32) >= 0;
        loop {
            let end = base.wrapping_add(self.data.len() as u32);
            // Drop segments fully covered by the prefix.
            let plen = &mut self.pending_len;
            self.pending.retain(|(s, v)| {
                let covered = seq_ge(*s, base)
                    && seq_le(*s, end)
                    && seq_le(s.wrapping_add(v.len() as u32), end);
                if covered {
                    *plen -= v.len();
                }
                !covered
            });
            // Forward connect: the segment with seq <= end reaching past it.
            let fwd = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, (s, v))| {
                    seq_le(*s, end) && seq_gt(s.wrapping_add(v.len() as u32), end)
                })
                .max_by_key(|(_, (s, _))| s.wrapping_sub(base))
                .map(|(i, _)| i);
            if let Some(i) = fwd {
                let (seq, seg) = self.pending.remove(i);
                self.pending_len -= seg.len();
                let off = end.wrapping_sub(seq) as usize;
                if off < seg.len() {
                    self.append(&seg[off..], usize::MAX); // budget paid when parked
                }
                continue;
            }
            // Backward connect: the segment with seq < base reaching the anchor.
            let bwd = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, (s, v))| {
                    seq_lt(*s, base) && seq_ge(s.wrapping_add(v.len() as u32), base)
                })
                .min_by_key(|(_, (s, _))| base.wrapping_sub(*s))
                .map(|(i, _)| i);
            if let Some(i) = bwd {
                let (seq, seg) = self.pending.remove(i);
                self.pending_len -= seg.len();
                let take = (base.wrapping_sub(seq) as usize).min(seg.len());
                self.data.splice(0..0, seg[..take].iter().copied());
                base = base.wrapping_sub(take as u32);
                self.base = Some(base);
                continue;
            }
            break;
        }
    }
}

/// Welford running stats over payload sizes — the beacon discriminator:
/// real C2 check-ins are near-identical lengths; keepalive channels mix
/// in app data and show high size variance.
#[derive(Debug, Default)]
struct Svar {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Svar {
    fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    /// Coefficient of variation, or `None` with too little evidence.
    fn cv(&self) -> Option<f64> {
        if self.n < 8 || self.mean <= 0.0 {
            return None;
        }
        Some((self.m2 / self.n as f64).sqrt() / self.mean)
    }
}

#[derive(Debug, Default)]
pub struct Flow {
    pub first_ts: i64,
    pub last_ts: i64,
    pub pkts: u64,
    pub bytes: u64,
    /// Reassembly state per direction, allocated on first TCP payload —
    /// datagram-only flows (DNS, scans) don't carry ~150 B of dead
    /// stream fields each.
    stream_a: Option<Box<Stream>>,
    stream_b: Option<Box<Stream>>,
    /// TCP flags seen (bitmask: FIN SYN RST PSH ACK URG ECE CWR).
    pub tcp_flags: u8,
    iar_a: Iar,
    iar_b: Iar,
    /// Payload-size stats per direction (payload-bearing packets only).
    svar_a: Svar,
    svar_b: Svar,
}

impl Flow {
    pub fn observe(&mut self, ts: i64, len: u64, a_to_b: bool) {
        if self.pkts == 0 {
            self.first_ts = ts;
        }
        self.pkts += 1;
        self.bytes += len;
        self.last_ts = ts;
        if a_to_b {
            &mut self.iar_a
        } else {
            &mut self.iar_b
        }
        .push(ts);
    }

    /// Inter-arrival cadence per direction: `a_to_b=true` is a→b.
    pub fn cadence(&self, a_to_b: bool) -> Option<(u64, f64, f64)> {
        if a_to_b {
            self.iar_a.cadence()
        } else {
            self.iar_b.cadence()
        }
    }

    /// Note a payload-bearing packet's size for the size-variance signal.
    pub fn size_sample(&mut self, a_to_b: bool, len: usize) {
        if a_to_b {
            &mut self.svar_a
        } else {
            &mut self.svar_b
        }
        .push(len as f64);
    }

    /// Payload-size CV per direction — near-zero means fixed-size
    /// transfers (a beacon/keepalive shape).
    pub fn size_cv(&self, a_to_b: bool) -> Option<f64> {
        if a_to_b { &self.svar_a } else { &self.svar_b }.cv()
    }

    /// Reassembled bytes for direction `a_to_b` (`true` = a→b); empty
    /// when that direction never carried payload.
    pub fn stream_data(&self, a_to_b: bool) -> &[u8] {
        if a_to_b {
            &self.stream_a
        } else {
            &self.stream_b
        }
        .as_deref()
        .map_or(&[], |s| s.data())
    }

    /// Feed one payload segment into this packet's direction stream.
    /// Returns bytes stored so the table can debit its head budget.
    fn feed_dir(&mut self, a_to_b: bool, seq: Option<u32>, payload: &[u8], budget: usize) -> usize {
        self.size_sample(a_to_b, payload.len());
        let stream = if a_to_b {
            self.stream_a.get_or_insert_default()
        } else {
            self.stream_b.get_or_insert_default()
        };
        stream.feed(seq, payload, budget)
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    /// Two flat tables keyed by the packed per-family reprs — v4 keys
    /// are 16 B; v6 keys stay 48 B where they occur. Canonical
    /// `FlowKey`s are materialized on demand by [`FlowTable::iter`].
    map4: FastMap<Key4, Flow>,
    map6: FastMap<Key6, Flow>,
    /// Remaining global head-buffer budget.
    pub head_budget: usize,
    /// Flow keys dropped because the table hit MAX_FLOWS.
    pub overflow_keys: u64,
}

impl FlowTable {
    pub fn new(head_budget: usize) -> Self {
        Self {
            map4: FastMap::default(),
            map6: FastMap::default(),
            head_budget,
            overflow_keys: 0,
        }
    }

    /// Flows tracked across both tables.
    pub fn len(&self) -> usize {
        self.map4.len() + self.map6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map4.is_empty() && self.map6.is_empty()
    }

    /// All flows as canonical keys — materialized on demand; the packed
    /// storage repr is never exposed.
    pub fn iter(&self) -> impl Iterator<Item = (FlowKey, &Flow)> {
        self.map4
            .iter()
            .map(|(k, f)| (FlowKey::from(k), f))
            .chain(self.map6.iter().map(|(k, f)| (FlowKey::from(k), f)))
    }

    /// Look up a flow by canonical key — report/test path.
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        if let Some(k) = key4(key) {
            self.map4.get(&k)
        } else {
            key6(key).and_then(|k| self.map6.get(&k))
        }
    }

    /// Observe one packet on `key` (from [`FlowKey::new`]). Returns the
    /// flow, or `None` when the table is full and this is a new key.
    pub fn update(&mut self, key: FlowKey, fwd: bool, ts: i64, len: u64) -> Option<&mut Flow> {
        let full = self.len() >= MAX_FLOWS;
        let f = if let Some(k) = key4(&key) {
            if full && !self.map4.contains_key(&k) {
                self.overflow_keys += 1;
                return None;
            }
            self.map4.entry(k).or_default()
        } else {
            let k = key6(&key)?; // None only for a mixed-family key
            if full && !self.map6.contains_key(&k) {
                self.overflow_keys += 1;
                return None;
            }
            self.map6.entry(k).or_default()
        };
        f.observe(ts, len, fwd);
        Some(f)
    }

    /// TCP fast path: observe + flags + stream feed in one map lookup.
    /// Returns false when the table is full and this is a new key.
    #[allow(clippy::too_many_arguments)] // every arg is one packet field
    pub fn update_tcp(
        &mut self,
        key: FlowKey,
        fwd: bool,
        ts: i64,
        len: u64,
        flags: u8,
        seq: u32,
        payload: &[u8],
    ) -> bool {
        let full = self.len() >= MAX_FLOWS;
        let f = if let Some(k) = key4(&key) {
            if full && !self.map4.contains_key(&k) {
                self.overflow_keys += 1;
                return false;
            }
            self.map4.entry(k).or_default()
        } else if let Some(k) = key6(&key) {
            if full && !self.map6.contains_key(&k) {
                self.overflow_keys += 1;
                return false;
            }
            self.map6.entry(k).or_default()
        } else {
            return false;
        };
        f.observe(ts, len, fwd);
        f.tcp_flags |= flags;
        if !payload.is_empty() {
            let stored = f.feed_dir(fwd, Some(seq), payload, self.head_budget);
            self.head_budget -= stored;
        }
        true
    }

    /// Feed one payload segment into the sender's stream for `key`.
    /// `a_to_b` must match the direction used in `update`; `seq` is the
    /// TCP sequence number (`None` for datagrams).
    pub fn feed_stream(&mut self, key: &FlowKey, a_to_b: bool, seq: Option<u32>, payload: &[u8]) {
        let f = if let Some(k) = key4(key) {
            self.map4.get_mut(&k)
        } else {
            key6(key).and_then(|k| self.map6.get_mut(&k))
        };
        let Some(f) = f else {
            return;
        };
        let stored = f.feed_dir(a_to_b, seq, payload, self.head_budget);
        self.head_budget -= stored;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn both_directions_share_one_flow() {
        let mut t = FlowTable::new(1024);
        let (k1, f1) = FlowKey::new(A, 1000, B, 443, 6);
        t.update(k1, f1, 0, 100);
        let (k2, b_fwd) = FlowKey::new(B, 443, A, 1000, 6);
        assert_eq!(k1, k2);
        t.update(k2, b_fwd, 1000, 50);
        assert!(!b_fwd);
        assert_eq!(t.len(), 1);
        let f = t.iter().next().unwrap().1;
        assert_eq!(f.pkts, 2);
        // direction a→b cadence has 1 sample only
        assert!(f.cadence(true).is_none());
    }

    #[test]
    fn cadence_detects_regular_timing() {
        let mut t = FlowTable::new(1024);
        let (key, fwd) = FlowKey::new(A, 1000, B, 443, 6);
        for i in 0..10 {
            t.update(key, fwd, i * 1000, 100);
        }
        let f = t.iter().next().unwrap().1;
        let (n, mean, cv) = f.cadence(true).unwrap();
        assert_eq!(n, 10);
        assert_eq!(mean, 1000.0);
        assert!(cv < 0.01, "cv={cv}");
    }

    #[test]
    fn head_buffer_respects_budget() {
        let mut t = FlowTable::new(10);
        let (key, fwd) = FlowKey::new(A, 1000, B, 443, 6);
        t.update(key, fwd, 0, 0);
        t.feed_stream(&key, true, None, &[1u8; 8]);
        t.feed_stream(&key, true, None, &[2u8; 8]); // only 2 fit the budget
        t.feed_stream(&key, false, None, &[3u8; 8]); // budget spent
        let f = t.get(&key).unwrap();
        assert_eq!(f.stream_data(true).len(), 10);
        assert!(f.stream_data(false).is_empty());
    }

    #[test]
    fn stream_reassembles_out_of_order() {
        let mut s = Stream::default();
        // "hello world" arriving as two out-of-order segments — the
        // anchor re-bases left when earlier bytes arrive late.
        s.feed(Some(101), b"world", 1024);
        s.feed(Some(95), b"hello ", 1024);
        assert_eq!(s.data(), b"hello world");
        // Retransmit is a no-op.
        s.feed(Some(95), b"hello ", 1024);
        assert_eq!(s.data(), b"hello world");
    }

    #[test]
    fn stream_patches_gaps() {
        let mut s = Stream::default();
        s.feed(Some(0), b"GET /a", 1024);
        s.feed(Some(10), b"GET /b", 1024); // gap at 6..10
        assert_eq!(s.data(), b"GET /a");
        s.feed(Some(6), b"XXXX", 1024); // fills the gap
        assert_eq!(s.data(), b"GET /aXXXXGET /b");
    }
}
