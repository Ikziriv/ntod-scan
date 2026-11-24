//! Remote sniffing: `tcpdump -w -` streams a real pcap to stdout — over
//! SSH that means a Kali box's adapter lands in the local analyzer with
//! no file transfer step. Caller feeds the bytes to `ntod-analysis`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use ntod_capture::{RawFrame, pcapr};

use crate::error::Error;
use crate::runner::{Backend, read_cap};

/// Grace after `seconds` for ssh teardown and the last write.
const GRACE: Duration = Duration::from_secs(10);

/// Session bound for live `stream` captures — same 1h as monitor.
const SESSION: Duration = Duration::from_secs(3600);

/// `tcpdump -U -s0 -i <iface> -w - -- [bpf]` for `seconds`, stdout bounded
/// at `max_bytes` of pcap data. `-U` flushes per packet so the kill at
/// deadline only ever truncates the final record — pcap readers
/// tolerate a short tail. Grace covers ssh teardown; the deadline kill
/// is the normal end of this tool.
pub fn capture(
    backend: &Backend,
    iface: &str,
    seconds: u64,
    bpf: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    capture_cancellable(backend, iface, seconds, bpf, max_bytes, None)
}

/// Like [`capture`], but terminates early when `cancel` becomes `true`.
pub fn capture_cancellable(
    backend: &Backend,
    iface: &str,
    seconds: u64,
    bpf: Option<&str>,
    max_bytes: usize,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>, Error> {
    let argv = argv(iface, bpf)?;
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    backend.run_capture_cancellable(&refs, seconds + GRACE.as_secs(), max_bytes, cancel)
}

/// Live sniffing: spawn `tcpdump -U -s0 -i <iface> -w -` and push each
/// frame to `tx` as it lands — unlike [`capture`], nothing waits for a
/// deadline. Ends when `cancel` fires, the pipe closes, or the 1h
/// session bound hits; the child's stderr surfaces on failure.
pub fn stream(
    backend: &Backend,
    iface: &str,
    bpf: Option<&str>,
    cancel: Arc<AtomicBool>,
    tx: mpsc::SyncSender<RawFrame>,
) -> Result<(), Error> {
    let argv = argv(iface, bpf)?;
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut child = backend.spawn(&refs)?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let err_h = thread::spawn(move || read_cap(stderr, 64 << 10));

    // The watchdog owns the child: exit, cancel, or the session bound
    // all end the capture, and the verdict travels back on `end_rx`.
    let (end_tx, end_rx) = mpsc::channel();
    let cancel_w = cancel.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + SESSION;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {
                    if cancel_w.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        let _ = child.kill();
                        match child.wait() {
                            Ok(s) => break s,
                            Err(e) => {
                                let _ = end_tx.send(Err(Error::Io(e)));
                                return;
                            }
                        };
                    }
                }
                Err(e) => {
                    let _ = end_tx.send(Err(Error::Io(e)));
                    return;
                }
            }
            thread::sleep(Duration::from_millis(20));
        };
        let err = match err_h.join() {
            Ok(Ok(v)) => v,
            _ => Vec::new(),
        };
        let _ = end_tx.send(Ok((status, err)));
    });

    // tcpdump writes classic pcap on stdout — parse records as they
    // arrive; `-U` means one read per packet, so latency stays low.
    let read = pcapr::read_stream(stdout, |p| {
        tx.send(RawFrame {
            ts_ms: p.ts_ms,
            linktype: p.linktype,
            data: p.data.to_vec(),
        })
        .is_ok()
    });

    // Whatever ended the reader, the child must not outlive it.
    let cancelled = cancel.load(Ordering::Relaxed);
    cancel.store(true, Ordering::Relaxed);
    let end = end_rx
        .recv()
        .unwrap_or_else(|_| Err(Error::Failed("watchdog".into())));

    // Prefer tcpdump's own stderr — it names the failed iface or the
    // permission problem better than a pcap parse error does.
    let stderr_msg = |v: &[u8]| {
        // wsl.exe writes UTF-16LE — strip NULs so the error reads clean.
        let s = String::from_utf8_lossy(v).replace('\0', "");
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_string())
    };
    let failed = |status: std::process::ExitStatus, err: &[u8]| {
        stderr_msg(err).map_or_else(
            || Error::Failed(format!("tcpdump exited {status}")),
            |m| Error::Failed(format!("tcpdump exited {status}: {m}")),
        )
    };
    if cancelled {
        return Ok(()); // caller stopped us — kill is not an error
    }
    match (read, end) {
        (Err(e), Ok((status, err))) => {
            Err(stderr_msg(&err)
                .map_or_else(|| Error::Parse(e.to_string()), |_| failed(status, &err)))
        }
        (Err(e), _) => Err(Error::Parse(e.to_string())),
        (Ok(_), Ok((status, err))) if !status.success() => Err(failed(status, &err)),
        (_, Err(e)) => Err(e),
        (Ok(_), Ok((_, _))) => Ok(()),
    }
}

/// `tcpdump -U -s0 -i <iface> -w - -- [bpf]` argv, validated.
/// `-U` flushes per packet so the reader sees frames as they land.
fn argv(iface: &str, bpf: Option<&str>) -> Result<Vec<String>, Error> {
    check_iface(iface)?;
    let mut argv: Vec<String> = vec![
        "tcpdump".into(),
        "-U".into(),
        "-s".into(),
        "0".into(),
        "-i".into(),
        iface.to_string(),
        "-w".into(),
        "-".into(),
    ];
    // Whole expression as one argv element after `--` — prevents flag injection.
    if let Some(f) = bpf.map(str::trim).filter(|f| !f.is_empty()) {
        check_bpf(f)?;
        argv.push("--".into());
        argv.push(f.to_string());
    }
    Ok(argv)
}

fn check_bpf(f: &str) -> Result<(), Error> {
    let ok = !f.starts_with('-') && !f.chars().any(char::is_control) && f.len() <= 1024;
    ok.then_some(()).ok_or_else(|| Error::BadTarget(f.into()))
}

pub(crate) fn check_iface(i: &str) -> Result<(), Error> {
    let ok = !i.is_empty()
        && !i.starts_with('-')
        && i.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c));
    ok.then_some(()).ok_or_else(|| Error::BadIface(i.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_names_are_strict() {
        assert!(check_iface("any").is_ok());
        assert!(check_iface("wlan0mon").is_ok());
        assert!(check_iface("eth0.100").is_ok());
        assert!(check_iface("pci:0000").is_ok());
        assert!(check_iface("-i").is_err());
        assert!(check_iface("eth0;rm -rf /").is_err());
    }

    #[test]
    fn bpf_rejects_flag_injection() {
        assert!(check_bpf("tcp port 443").is_ok());
        assert!(check_bpf("host 10.0.0.1 and not port 22").is_ok());
        assert!(check_bpf("-z /bin/sh").is_err());
        assert!(check_bpf("-r /etc/passwd").is_err());
        assert!(check_bpf("port 80\n-z id").is_err());
    }
}
