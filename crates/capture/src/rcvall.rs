//! Windows raw-socket capture via SIO_RCVALL — no Npcap needed, IP-level
//! packets only (no Ethernet header/MACs), requires Administrator.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::{Capture, Error, RawFrame, now_ms};

const SIO_RCVALL: u32 = 0x9800_0001;
const WSAEACCES: i32 = 10013;
const WSAETIMEDOUT: i32 = 10060;

/// WsaGuard cleans up WSAStartup on drop.
struct WsaGuard;

impl Drop for WsaGuard {
    fn drop(&mut self) {
        unsafe { WSACleanup() };
    }
}

struct SockGuard(SOCKET);

impl Drop for SockGuard {
    fn drop(&mut self) {
        unsafe { closesocket(self.0) };
    }
}

fn last_err() -> std::io::Error {
    unsafe { std::io::Error::from_raw_os_error(WSAGetLastError()) }
}

fn io_or_admin(e: std::io::Error) -> Error {
    if e.raw_os_error() == Some(WSAEACCES) {
        Error::NeedsAdmin
    } else {
        Error::Io(e)
    }
}

/// # Safety
/// All pointer args reference valid stack/heap memory for the call duration;
/// socket lifetime is owned by SockGuard.
pub fn start(bind_ip: Ipv4Addr) -> Result<Capture, Error> {
    unsafe {
        let mut wsa: WSADATA = std::mem::zeroed();
        let wsa_rc = WSAStartup(0x0202, &mut wsa);
        if wsa_rc != 0 {
            return Err(Error::Io(std::io::Error::from_raw_os_error(wsa_rc)));
        }
        let wsa_guard = WsaGuard;

        let sock = socket(AF_INET as i32, SOCK_RAW, IPPROTO_IP);
        if sock == INVALID_SOCKET {
            return Err(io_or_admin(last_err()));
        }
        let sock = SockGuard(sock);

        let mut addr: SOCKADDR_IN = std::mem::zeroed();
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(bind_ip.octets());
        if bind(
            sock.0,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        ) != 0
        {
            return Err(io_or_admin(last_err()));
        }

        // WinSock2 SO_RCVTIMEO takes a DWORD (u32) in milliseconds, not TIMEVAL.
        let timeout_ms: u32 = 100;
        if setsockopt(
            sock.0,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout_ms as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        ) != 0
        {
            return Err(Error::Io(last_err()));
        }

        let on: u32 = 1;
        let mut ret: u32 = 0;
        if WSAIoctl(
            sock.0,
            SIO_RCVALL,
            &on as *const u32 as *const _,
            4,
            std::ptr::null_mut(),
            0,
            &mut ret,
            std::ptr::null_mut::<OVERLAPPED>(),
            None,
        ) != 0
        {
            return Err(io_or_admin(last_err()));
        }

        // 4096-frame bound — a stalled consumer drops packets via try_send
        // instead of blocking the capture loop or growing memory without limit.
        let (tx, rx) = mpsc::sync_channel(4096);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();

        let handle = thread::spawn(move || {
            // Keep `_wsa` declared before `sock` so `closesocket` runs before `WSACleanup`.
            let _wsa = wsa_guard;
            let sock = sock;
            let mut buf = vec![0u8; 65535];
            loop {
                if stop_thread.load(Ordering::Relaxed) {
                    break;
                }
                let n = recv(sock.0, buf.as_mut_ptr(), buf.len() as i32, 0);
                if n <= 0 {
                    let e = WSAGetLastError();
                    if e == WSAETIMEDOUT || e == WSAEWOULDBLOCK {
                        continue;
                    }
                    break; // real socket error
                }
                match tx.try_send(RawFrame {
                    ts_ms: now_ms(),
                    linktype: 101, // DLT_RAW — IP datagrams, no L2
                    data: buf[..n as usize].to_vec(),
                }) {
                    Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                }
            }
        });

        Ok(Capture {
            stop,
            rx: Some(rx),
            handle: Some(handle),
        })
    }
}
