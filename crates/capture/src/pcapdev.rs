//! libpcap backend — feature `pcap-backend`. Needs libpcap/Npcap SDK to
//! build. Gives link-level capture (Ethernet frames, real MACs) on every
//! OS, unlike the Windows rcvall path.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

use crate::{Capture, Error, RawFrame, now_ms};

/// All capture-capable interfaces.
pub fn devices() -> Result<Vec<String>, Error> {
    pcap::Device::list()
        .map(|ds| ds.into_iter().map(|d| d.name).collect())
        .map_err(|e| Error::Unavailable(pcstr(e)))
}

fn pcstr(e: pcap::Error) -> &'static str {
    match e {
        pcap::Error::TimeoutExpired => "capture timeout",
        pcap::Error::IoError(_) => "pcap io error",
        pcap::Error::PcapError(_) => "pcap error",
        _ => "libpcap error",
    }
}

/// Capture on the interface whose IPv4 matches `bind_ip` (or default).
pub fn start(bind_ip: Ipv4Addr) -> Result<Capture, Error> {
    let dev = pcap::Device::list()
        .map_err(|e| Error::Unavailable(pcstr(e)))?
        .into_iter()
        .find(|d| {
            d.addresses
                .iter()
                .any(|a| a.addr == std::net::IpAddr::V4(bind_ip))
        })
        .or_else(|| pcap::Device::lookup().ok().flatten())
        .ok_or(Error::Unavailable("no capture device found"))?;

    let mut cap = pcap::Capture::from_device(dev)
        .map_err(|e| Error::Unavailable(pcstr(e)))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
        .map_err(|e| Error::Unavailable(pcstr(e)))?;

    let linktype = cap.get_datalink().0 as u16;
    let (tx, rx) = mpsc::sync_channel::<RawFrame>(4096);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    let handle = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(pkt) => match tx.try_send(RawFrame {
                    ts_ms: now_ms(),
                    linktype,
                    data: pkt.data.to_vec(),
                }) {
                    Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                },
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }
    });

    Ok(Capture {
        stop,
        rx: Some(rx),
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_devices() {
        println!("{:?}", super::devices());
    }
}
