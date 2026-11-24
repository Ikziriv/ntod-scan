//! Packet capture engine: Wireshark/tcpdump tier.
//!
//! Backends:
//! - Windows `SIO_RCVALL` raw socket (built-in, needs Administrator, IP-level)
//! - libpcap (feature `pcap-backend`, cross-platform, link-level)

pub mod decode;
pub mod pcapr;
pub mod pcapw;

#[cfg(windows)]
mod rcvall;

#[cfg(feature = "pcap-backend")]
pub mod pcapdev;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use ntod_core::{Filter, Proto};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("capture requires Administrator/root privileges")]
    NeedsAdmin,
    #[error("capture backend unavailable: {0}")]
    Unavailable(&'static str),
}

/// One captured link-layer frame as read off the wire.
/// Consumers decode to [`PacketEvent`] via [`decode::decode_frame`] or feed
/// it to the analysis engine — the backend keeps the raw bytes either way.
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    /// libpcap linktype (101 = raw IP on the Windows backend, usually 1).
    pub linktype: u16,
    pub data: Vec<u8>,
}

/// One decoded packet summary emitted to the stream.
#[derive(Debug, Clone, Serialize)]
pub struct PacketEvent {
    /// Unix epoch milliseconds.
    pub ts: i64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: Proto,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// Total packet length in bytes.
    pub len: u16,
}

impl PacketEvent {
    pub fn matches(&self, f: &Filter) -> bool {
        if let Some(p) = f.proto
            && p != self.proto
        {
            return false;
        }
        if let Some(s) = f.src
            && s != self.src
        {
            return false;
        }
        if let Some(d) = f.dst
            && d != self.dst
        {
            return false;
        }
        if let Some(port) = f.port
            && self.sport != Some(port)
            && self.dport != Some(port)
        {
            return false;
        }
        true
    }
}

/// A running capture; `stop()` or drop to end it.
pub struct Capture {
    stop: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<RawFrame>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Capture {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Take the frame channel (once — subsequent calls return `None`).
    pub fn take_rx(&mut self) -> Option<mpsc::Receiver<RawFrame>> {
        self.rx.take()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
        // Drop the receiver first so a blocked/disconnected sender exits promptly.
        drop(self.rx.take());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Capture all IP traffic on the interface owning `bind_ip`.
///
/// Backend order with `pcap-backend` built: libpcap first — Ethernet
/// frames, real MACs, and on Windows Npcap captures without elevation —
/// then the OS-native fallback (Windows `SIO_RCVALL`, needs
/// Administrator). Without `pcap-backend`, Windows goes straight to
/// `SIO_RCVALL`.
pub fn start(bind_ip: Ipv4Addr) -> Result<Capture, Error> {
    #[cfg(feature = "pcap-backend")]
    match pcapdev::start(bind_ip) {
        Ok(c) => return Ok(c),
        Err(e) => {
            // Windows falls through to the raw socket — an unprivileged
            // user without Npcap gets the honest NeedsAdmin error.
            if !cfg!(windows) {
                return Err(e);
            }
        }
    }
    #[cfg(windows)]
    {
        return rcvall::start(bind_ip);
    }
    #[allow(unreachable_code)]
    Err(Error::Unavailable(
        "rebuild with feature `pcap-backend` on this platform",
    ))
}

#[doc(hidden)]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
