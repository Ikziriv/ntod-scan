//! WebSocket command channel — one command at a time per connection.
//!
//! Client → {"action":"scan",  "subnet"?: CIDR, "timeout_ms"?: u64, "workers"?: n}
//!        → {"action":"sniff", "filter"?: Filter, "via"?: backend,
//!          "iface"?: string, "bpf"?: string}
//!        → {"action":"analyze", "seconds"?: u64, "via"?: backend,
//!          "iface"?: string, "bpf"?: string}
//!        → {"action":"monitor", "window"?: u64, "via"?: backend,
//!          "iface"?: string}
//!        → {"action":"stop"}
//! Server → {"type":"found","ip":"..."}           host replied (fast phase)
//!        → {"type":"host","host":{...}}          enriched host (slow phase)
//!        → {"type":"packet","packet":{...}}      live packet (sniff)
//!        → {"type":"packets","packets":[...]}    batched sniff (opt-in)
//!        → {"type":"stopped","packets":N,"capture_id":id|null,  sniff end
//!          "partial":bool}
//!        → {"type":"analyzing","packets":N,"elapsed_ms":M}   triage progress
//!        → {"type":"report","report":{...}}      analysis report (analyze)
//!        → {"type":"monitor","window":N,"packets":N}         monitor window done
//!        → {"type":"finding","finding":{...}}    new-device/anomaly event
//!        → {"type":"done","hosts":N} | {"type":"error","msg":"..."}

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use ntod_core::{Filter, Host};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::AppState;

/// RAII guard that sets `cancel = true` whenever a WS command exits early
/// (disconnect, send failure, or panic) so background captures/subprocesses stop.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| run(socket, state))
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
enum Cmd {
    Scan {
        subnet: Option<String>,
        timeout_ms: Option<u64>,
        workers: Option<usize>,
        #[serde(default)]
        arp: Option<bool>,
        #[serde(default)]
        deep: Option<bool>,
    },
    Sniff {
        filter: Option<Filter>,
        /// Remote capture backend ("wsl[:distro]" | "ssh:[user@]host")
        /// — streams `tcpdump -w -`, needs the `tools` feature.
        #[serde(default)]
        via: Option<String>,
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        bpf: Option<String>,
        /// Opt-in: accept `{"type":"packets","packets":[…]}` batches.
        /// Absent → the old one-message-per-packet wire shape, so
        /// third-party clients are unaffected.
        #[serde(default)]
        batch: bool,
    },
    Analyze {
        seconds: Option<u64>,
        /// Remote capture backend ("local" | "wsl[:distro]" |
        /// "ssh:[user@]host") — needs the `tools` feature.
        #[serde(default)]
        via: Option<String>,
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        bpf: Option<String>,
    },
    Monitor {
        window: Option<u64>,
        #[serde(default)]
        via: Option<String>,
        #[serde(default)]
        iface: Option<String>,
    },
    Stop,
}

async fn send(socket: &mut WebSocket, v: serde_json::Value) -> bool {
    socket
        .send(Message::Text(v.to_string().into()))
        .await
        .is_ok()
}

async fn send_err(socket: &mut WebSocket, msg: impl std::fmt::Display) {
    send(socket, json!({"type": "error", "msg": msg.to_string()})).await;
}

async fn run(mut socket: WebSocket, state: Arc<AppState>) {
    while let Some(Ok(msg)) = socket.recv().await {
        let Message::Text(t) = msg else { continue };
        let Ok(cmd) = serde_json::from_str::<Cmd>(&t) else {
            send_err(&mut socket, "bad command").await;
            continue;
        };
        let keep_going = match cmd {
            Cmd::Scan {
                subnet,
                timeout_ms,
                workers,
                arp,
                deep,
            } => cmd_scan(&mut socket, subnet, timeout_ms, workers, arp, deep).await,
            Cmd::Sniff {
                filter,
                via,
                iface,
                bpf,
                batch,
            } => cmd_sniff(&mut socket, &state, filter, via, iface, bpf, batch).await,
            Cmd::Analyze {
                seconds,
                via,
                iface,
                bpf,
            } => cmd_analyze(&mut socket, &state, seconds, via, iface, bpf).await,
            Cmd::Monitor { window, via, iface } => {
                cmd_monitor(&mut socket, &state, window, via, iface).await
            }
            Cmd::Stop => true,
        };
        if !keep_going {
            return;
        }
    }
}

/// Scan: stream found IPs immediately, then stream enriched hosts.
async fn cmd_scan(
    socket: &mut WebSocket,
    subnet: Option<String>,
    timeout_ms: Option<u64>,
    workers: Option<usize>,
    arp: Option<bool>,
    deep: Option<bool>,
) -> bool {
    let subnet = match crate::resolve_subnet_async(subnet).await {
        Ok(s) => s,
        Err((_, e)) => {
            send_err(socket, e).await;
            return true;
        }
    };
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(800).clamp(50, 10_000));
    let workers = workers.unwrap_or(64).clamp(1, 256);
    let arp = arp.unwrap_or(true);
    let deep = deep.unwrap_or(false);
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());

    let (atx, mut arx) = mpsc::channel::<Host>(256);
    let cancel_bg = cancel.clone();
    let sweep = tokio::task::spawn_blocking(move || {
        let rx = ntod_core::scan::scan_stream_cancellable(
            subnet,
            timeout,
            workers,
            arp,
            Some(cancel_bg),
        );
        for h in rx.iter() {
            if atx.blocking_send(h).is_err() {
                break;
            }
        }
    });

    let mut hosts = Vec::new();
    loop {
        tokio::select! {
            item = arx.recv() => match item {
                Some(h) => {
                    let ip = h.ip;
                    hosts.push(h);
                    if !send(socket, json!({"type": "found", "ip": ip})).await {
                        return false;
                    }
                }
                None => break,
            },
            msg = socket.recv() => {
                cancel.store(true, Ordering::Relaxed);
                if let Some(Ok(_)) = msg {
                    return true;
                }
                return false;
            }
        }
    }
    let _ = sweep.await;

    let mut enriched = match tokio::task::spawn_blocking(move || {
        ntod_core::discover::enrich(&mut hosts);
        crate::deep_merge(&mut hosts, deep);
        hosts
    })
    .await
    {
        Ok(h) => h,
        Err(e) => {
            send_err(socket, e).await;
            return true;
        }
    };
    let count = enriched.len();
    for h in enriched.drain(..) {
        if !send(socket, json!({"type": "host", "host": h})).await {
            return false;
        }
    }
    send(socket, json!({"type": "done", "hosts": count})).await
}

/// Map a capture-backend failure to a structured WS error — `kind` lets
/// the UI pick the right fix, `hint` spells it out for the empty state.
fn capture_err_json(e: &ntod_capture::Error) -> serde_json::Value {
    let (kind, hint) = match e {
        ntod_capture::Error::NeedsAdmin => (
            "needs-admin",
            if cfg!(windows) {
                "Relaunch the daemon elevated, install Npcap and rebuild with \
                 `pcap-backend` for unprivileged capture, or set the backend \
                 field to a wsl:/ssh: host running tcpdump."
            } else {
                "Relaunch the daemon as root or with cap_net_raw, \
                 or set the backend field to an ssh: host running tcpdump."
            },
        ),
        ntod_capture::Error::Unavailable(_) => (
            "unavailable",
            "This build has no local capture backend — rebuild with the \
             `pcap-backend` feature, or set the backend field for a remote capture.",
        ),
        ntod_capture::Error::Io(_) => (
            "io",
            "The capture backend failed to start — retry, or set the backend \
             field for a remote capture.",
        ),
    };
    json!({"type": "error", "kind": kind, "msg": e.to_string(), "hint": hint})
}

/// Sniff: live packet events until the client sends anything or disconnects.
/// Needs Administrator (Windows raw socket) or the pcap-backend feature —
/// or a remote `via` backend streaming `tcpdump -w -` (tools feature).
/// Frames are retained (bounded, like /api/analyze) so the finished capture
/// can be re-exported via /api/capture/{id}/pcap — the `stopped` message
/// carries the id. Any client message cancels; the socket stays open until
/// `stopped` lands so the client learns the export id.
async fn cmd_sniff(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    filter: Option<Filter>,
    via: Option<String>,
    iface: Option<String>,
    bpf: Option<String>,
    batch: bool,
) -> bool {
    if via.is_some() {
        return cmd_sniff_remote(socket, state, filter, via, iface, bpf, batch).await;
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());

    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(1024);
    let cancel_bg = cancel.clone();
    let st = state.clone();
    tokio::task::spawn_blocking(move || {
        let ip = match ntod_core::local_subnet() {
            Ok(s) => s.ip(),
            Err(e) => {
                let _ = atx.blocking_send(json!({
                    "type": "error",
                    "kind": "no-interface",
                    "msg": e.to_string(),
                    "hint": "No usable IPv4 interface — check the network adapter.",
                }));
                return;
            }
        };
        let mut cap = match ntod_capture::start(ip) {
            Ok(c) => c,
            Err(e) => {
                let _ = atx.blocking_send(capture_err_json(&e));
                return;
            }
        };
        let Some(rx) = cap.take_rx() else {
            let _ = atx.blocking_send(json!({
                "type": "error",
                "kind": "io",
                "msg": "capture channel unavailable",
            }));
            return;
        };

        let out = pump_frames(rx, &filter, &atx, &cancel_bg, batch);
        cap.stop();
        finish_pump(out, &atx, &st);
    });

    relay_frames(socket, &mut arx, &cancel).await
}

/// What a frame pump collected — packets forwarded plus the retained
/// frames (bounded) that become the pcap export.
struct PumpOut {
    frames: Vec<ntod_capture::RawFrame>,
    packets: u64,
    partial: bool,
}

/// Forward decoded frames from a live frame channel onto the WS queue
/// until cancel/disconnect. Same 32 MB bound as analyze_retain — past it
/// the stream keeps flowing but the export is marked partial.
/// Events batch into `packets` messages when `batch` is set: one
/// serialization per ~64 packets instead of one JSON tree + WS frame per
/// packet — the wire and the client both see burst shapes, not
/// packet-rate message churn. Without it, the legacy `packet` shape is
/// emitted per event (one-element "batch").
fn pump_frames(
    rx: std::sync::mpsc::Receiver<ntod_capture::RawFrame>,
    filter: &Option<Filter>,
    atx: &mpsc::Sender<serde_json::Value>,
    cancel: &AtomicBool,
    batch: bool,
) -> PumpOut {
    use std::sync::mpsc::RecvTimeoutError;
    const RETAIN_MAX: usize = 32 << 20;
    const BATCH_MAX: usize = 64;
    let batch_max = if batch { BATCH_MAX } else { 1 };
    let mut frames = Vec::new();
    let mut retain_bytes = 0usize;
    let mut packets = 0u64;
    let mut partial = false;
    let mut batch: Vec<ntod_capture::PacketEvent> = Vec::with_capacity(BATCH_MAX);

    while !cancel.load(Ordering::Relaxed) {
        // Flush on a full batch or an idle tick — the latter keeps
        // low-rate captures responsive within ~200ms.
        let flush = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(frame) => {
                let Some(ev) =
                    ntod_capture::decode::decode_frame(frame.linktype, &frame.data, frame.ts_ms)
                else {
                    continue;
                };
                if let Some(f) = filter
                    && !ev.matches(f)
                {
                    continue;
                }
                packets += 1;
                if retain_bytes < RETAIN_MAX {
                    retain_bytes += frame.data.len();
                    frames.push(frame);
                } else {
                    partial = true;
                }
                batch.push(ev);
                batch.len() >= batch_max
            }
            Err(RecvTimeoutError::Timeout) => !batch.is_empty(),
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if flush {
            if atx.blocking_send(batch_msg(&batch)).is_err() {
                return PumpOut {
                    frames,
                    packets,
                    partial,
                };
            }
            batch.clear();
        }
    }
    if !batch.is_empty() {
        let _ = atx.blocking_send(batch_msg(&batch));
    }
    PumpOut {
        frames,
        packets,
        partial,
    }
}

/// Wire message for a drained batch: a lone packet keeps the legacy
/// `packet` shape, bigger flushes use `packets`.
fn batch_msg(batch: &[ntod_capture::PacketEvent]) -> serde_json::Value {
    if batch.len() == 1 {
        json!({"type": "packet", "packet": batch.first()})
    } else {
        json!({"type": "packets", "packets": batch})
    }
}

/// Store the retained frames and report the finished capture.
fn finish_pump(out: PumpOut, atx: &mpsc::Sender<serde_json::Value>, st: &Arc<AppState>) {
    if atx.is_closed() {
        return;
    }
    let capture_id = st.store_capture(out.frames);
    let _ = atx.blocking_send(json!({
        "type": "stopped",
        "packets": out.packets,
        "capture_id": capture_id,
        "partial": out.partial,
    }));
}

/// Relay queued WS messages to the socket until a terminal message
/// (`stopped`/`error`) or a client/disconnect signal. Any client message
/// cancels; the socket stays open so the terminal message still lands.
async fn relay_frames(
    socket: &mut WebSocket,
    arx: &mut mpsc::Receiver<serde_json::Value>,
    cancel: &AtomicBool,
) -> bool {
    loop {
        tokio::select! {
            ev = arx.recv() => {
                match ev {
                    Some(m) => {
                        let done = matches!(
                            m.get("type").and_then(|t| t.as_str()),
                            Some("stopped" | "error")
                        );
                        if !send(socket, m).await {
                            return false;
                        }
                        if done {
                            return true;
                        }
                    }
                    None => break,
                }
            },
            msg = socket.recv() => {
                if let Some(Ok(_)) = msg {
                    cancel.store(true, Ordering::Relaxed);
                    continue; // drain until `stopped` so the export id lands
                }
                return false;
            }
        }
    }
    false
}

/// Sniff on a remote backend: `tcpdump -w -` streams classic pcap over
/// the pipe and each record lands as a live packet — same stream shape,
/// same retention + export id, as the local raw-socket path.
#[cfg(feature = "tools")]
async fn cmd_sniff_remote(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    filter: Option<Filter>,
    via: Option<String>,
    iface: Option<String>,
    bpf: Option<String>,
    batch: bool,
) -> bool {
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());

    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(1024);
    let cancel_bg = cancel.clone();
    let st = state.clone();
    tokio::task::spawn_blocking(move || {
        let backend = match via.as_deref().map(ntod_tools::Backend::from_spec) {
            Some(Ok(b)) => b,
            other => {
                let msg = match other {
                    Some(Err(e)) => e.to_string(),
                    _ => "empty backend spec".into(),
                };
                let _ = atx.blocking_send(json!({
                    "type": "error",
                    "kind": "bad-backend",
                    "msg": msg,
                }));
                return;
            }
        };
        let (ftx, frx) = std::sync::mpsc::sync_channel::<ntod_capture::RawFrame>(4096);
        let iface = iface.unwrap_or_else(|| "any".into());
        let cancel_s = cancel_bg.clone();
        let producer = std::thread::spawn(move || {
            ntod_tools::sniff::stream(&backend, &iface, bpf.as_deref(), cancel_s, ftx)
        });

        let out = pump_frames(frx, &filter, &atx, &cancel_bg, batch);
        if atx.is_closed() {
            return;
        }
        match producer.join() {
            // A dead tcpdump is the error the user needs — surface it
            // instead of a clean `stopped` for an empty capture.
            Ok(Err(e)) => {
                let _ = atx.blocking_send(json!({
                    "type": "error",
                    "kind": "capture",
                    "msg": e.to_string(),
                    "hint": "tcpdump on the backend failed — check the iface, the BPF expression, and that tcpdump can capture there.",
                }));
            }
            Err(_) => {
                let _ = atx.blocking_send(json!({
                    "type": "error",
                    "kind": "capture",
                    "msg": "capture task failed",
                }));
            }
            Ok(Ok(())) => finish_pump(out, &atx, &st),
        }
    });

    relay_frames(socket, &mut arx, &cancel).await
}

/// Remote sniff needs the tools adapters.
#[cfg(not(feature = "tools"))]
async fn cmd_sniff_remote(
    socket: &mut WebSocket,
    _state: &Arc<AppState>,
    _filter: Option<Filter>,
    _via: Option<String>,
    _iface: Option<String>,
    _bpf: Option<String>,
    _batch: bool,
) -> bool {
    send_err(socket, "remote capture needs the `tools` build feature").await;
    true
}

/// Analyze: live triage through the same engine as pcap upload — streams
/// progress every second, then the finished report. Any client message
/// stops early and still delivers the partial report.
async fn cmd_analyze(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    seconds: Option<u64>,
    via: Option<String>,
    iface: Option<String>,
    bpf: Option<String>,
) -> bool {
    let secs = seconds.unwrap_or(30).clamp(5, 300);
    if via.is_some() {
        return cmd_analyze_remote(socket, state, secs, via, iface, bpf).await;
    }

    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(64);
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());
    let cancel2 = cancel.clone();
    let st = state.clone();

    tokio::task::spawn_blocking(move || {
        let ip = match ntod_core::local_subnet() {
            Ok(s) => s.ip(),
            Err(e) => {
                let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                return;
            }
        };
        let mut cap = match ntod_capture::start(ip) {
            Ok(c) => c,
            Err(e) => {
                let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                return;
            }
        };
        let Some(rx) = cap.take_rx() else {
            let _ =
                atx.blocking_send(json!({"type": "error", "msg": "capture channel unavailable"}));
            return;
        };

        let mut a = ntod_analysis::Analyzer::new();
        let started = Instant::now();
        ntod_analysis::feed_channel(
            &rx,
            &mut a,
            Duration::from_secs(secs),
            u64::MAX,
            || cancel2.load(Ordering::Relaxed) || atx.is_closed(),
            |n| {
                atx.blocking_send(json!({
                    "type": "analyzing",
                    "packets": n,
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                }))
                .is_ok()
            },
        );
        cap.stop();
        if atx.is_closed() {
            return;
        }
        let mut report = a.finish();
        st.store_objects(&mut report);
        st.history_observe(&mut report);
        let _ = atx.blocking_send(json!({"type": "report", "report": report}));
    });

    loop {
        tokio::select! {
            ev = arx.recv() => {
                match ev {
                    Some(m) => {
                        let done = matches!(
                            m.get("type").and_then(|t| t.as_str()),
                            Some("report" | "error")
                        );
                        if !send(socket, m).await {
                            return false;
                        }
                        if done {
                            return true;
                        }
                    }
                    None => break,
                }
            }
            msg = socket.recv() => {
                if let Some(Ok(_)) = msg {
                    cancel.store(true, Ordering::Relaxed);
                    continue; // keep draining until the partial report arrives
                }
                return false;
            }
        }
    }
    false
}

/// Analyze on a remote backend: `tcpdump -w -` streams whole-pcap bytes,
/// the local engine produces the same report. Supports early client cancel.
async fn cmd_analyze_remote(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    secs: u64,
    via: Option<String>,
    iface: Option<String>,
    bpf: Option<String>,
) -> bool {
    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(64);
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());
    let cancel2 = cancel.clone();
    let st = state.clone();

    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let send_err = |m: String| {
            let _ = atx.blocking_send(json!({"type": "error", "msg": m}));
        };
        #[cfg(feature = "tools")]
        {
            let backend = match via.as_deref().map(ntod_tools::Backend::from_spec) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return send_err(e.to_string()),
                None => return send_err("empty backend spec".into()),
            };
            let bytes = match ntod_tools::sniff::capture_cancellable(
                &backend,
                iface.as_deref().unwrap_or("any"),
                secs,
                bpf.as_deref(),
                256 << 20,
                Some(&cancel2),
            ) {
                Ok(b) => b,
                Err(e) => return send_err(e.to_string()),
            };
            if atx.is_closed() {
                return;
            }
            let mut a = ntod_analysis::Analyzer::new();
            if !bytes.is_empty()
                && let Err(e) = ntod_capture::pcapr::for_each(&bytes, |p| {
                    a.feed(p.ts_ms, p.linktype, p.data);
                    true
                })
            {
                return send_err(e.to_string());
            }
            let _ = atx.blocking_send(json!({
                "type": "analyzing",
                "packets": a.packets(),
                "elapsed_ms": started.elapsed().as_millis() as u64,
            }));
            let mut report = a.finish();
            st.store_objects(&mut report);
            st.history_observe(&mut report);
            let _ = atx.blocking_send(json!({"type": "report", "report": report}));
        }
        #[cfg(not(feature = "tools"))]
        {
            let _ = (secs, via, iface, bpf, started, cancel2, st);
            send_err("remote capture needs the `tools` build feature".into());
        }
    });

    loop {
        tokio::select! {
            ev = arx.recv() => match ev {
                Some(m) => {
                    let done = matches!(
                        m.get("type").and_then(|t| t.as_str()),
                        Some("report" | "error")
                    );
                    if !send(socket, m).await {
                        return false;
                    }
                    if done {
                        return true;
                    }
                }
                None => break,
            },
            msg = socket.recv() => {
                if let Some(Ok(_)) = msg {
                    cancel.store(true, Ordering::Relaxed);
                    continue;
                }
                return false;
            }
        }
    }
    false
}

/// Monitor: rolling windowed analysis forever — each window feeds the
/// device-history store and pushes new-device / anomaly findings as
/// they happen. Session-bounded at 1h; any client message stops it.
async fn cmd_monitor(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    window: Option<u64>,
    via: Option<String>,
    iface: Option<String>,
) -> bool {
    let win = Duration::from_secs(window.unwrap_or(15).clamp(5, 60));
    if via.is_some() {
        return cmd_monitor_remote(socket, state, win, via, iface).await;
    }

    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(64);
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());
    let cancel2 = cancel.clone();
    let st = state.clone();

    tokio::task::spawn_blocking(move || {
        let ip = match ntod_core::local_subnet() {
            Ok(s) => s.ip(),
            Err(e) => {
                let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                return;
            }
        };
        let mut cap = match ntod_capture::start(ip) {
            Ok(c) => c,
            Err(e) => {
                let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                return;
            }
        };
        let Some(rx) = cap.take_rx() else {
            let _ =
                atx.blocking_send(json!({"type": "error", "msg": "capture channel unavailable"}));
            return;
        };

        let session_end = Instant::now() + Duration::from_secs(3600);
        let mut n = 0u64;
        loop {
            let mut a = ntod_analysis::Analyzer::new();
            ntod_analysis::feed_channel(
                &rx,
                &mut a,
                win,
                u64::MAX,
                || cancel2.load(Ordering::Relaxed) || atx.is_closed(),
                |_| true,
            );
            if atx.is_closed() {
                cap.stop();
                return;
            }
            let report = a.finish();
            n += 1;
            let findings = st.observe_history(&report);
            for f in findings {
                if atx
                    .blocking_send(json!({"type": "finding", "finding": f}))
                    .is_err()
                {
                    cap.stop();
                    return;
                }
            }
            if atx
                .blocking_send(json!({
                    "type": "monitor",
                    "window": n,
                    "packets": report.meta.packets,
                }))
                .is_err()
            {
                cap.stop();
                return;
            }
            if cancel2.load(Ordering::Relaxed) || Instant::now() >= session_end {
                break;
            }
        }
        cap.stop();
        let _ = atx.blocking_send(json!({"type": "monitor-done", "windows": n}));
    });

    loop {
        tokio::select! {
            ev = arx.recv() => {
                match ev {
                    Some(m) => {
                        let done = matches!(
                            m.get("type").and_then(|t| t.as_str()),
                            Some("monitor-done" | "error")
                        );
                        if !send(socket, m).await {
                            return false;
                        }
                        if done {
                            return true;
                        }
                    }
                    None => break,
                }
            }
            msg = socket.recv() => {
                if let Some(Ok(_)) = msg {
                    cancel.store(true, Ordering::Relaxed);
                    continue; // drain until monitor-done
                }
                return false;
            }
        }
    }
    false
}

/// Monitor on a remote backend: each window is a fresh `tcpdump` capture,
/// analyzed and folded into history like the local path.
#[cfg(feature = "tools")]
async fn cmd_monitor_remote(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    win: Duration,
    via: Option<String>,
    iface: Option<String>,
) -> bool {
    let backend = match via.as_deref().map(ntod_tools::Backend::from_spec) {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            send_err(socket, e).await;
            return true;
        }
        None => {
            send_err(socket, "empty backend spec").await;
            return true;
        }
    };
    let iface = iface.unwrap_or_else(|| "any".into());

    let (atx, mut arx) = mpsc::channel::<serde_json::Value>(64);
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(cancel.clone());
    let cancel2 = cancel.clone();
    let st = state.clone();

    tokio::task::spawn_blocking(move || {
        let session_end = Instant::now() + Duration::from_secs(3600);
        let mut n = 0u64;
        loop {
            if cancel2.load(Ordering::Relaxed) || atx.is_closed() {
                break;
            }
            let bytes = match ntod_tools::sniff::capture_cancellable(
                &backend,
                &iface,
                win.as_secs(),
                None,
                256 << 20,
                Some(&cancel2),
            ) {
                Ok(b) => b,
                Err(e) => {
                    let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                    return;
                }
            };
            if atx.is_closed() {
                return;
            }
            let mut a = ntod_analysis::Analyzer::new();
            if !bytes.is_empty()
                && let Err(e) = ntod_capture::pcapr::for_each(&bytes, |p| {
                    a.feed(p.ts_ms, p.linktype, p.data);
                    true
                })
            {
                let _ = atx.blocking_send(json!({"type": "error", "msg": e.to_string()}));
                return;
            }
            let report = a.finish();
            n += 1;
            let findings = st.observe_history(&report);
            for f in findings {
                if atx
                    .blocking_send(json!({"type": "finding", "finding": f}))
                    .is_err()
                {
                    return;
                }
            }
            if atx
                .blocking_send(json!({
                    "type": "monitor",
                    "window": n,
                    "packets": report.meta.packets,
                }))
                .is_err()
            {
                return;
            }
            if cancel2.load(Ordering::Relaxed) || Instant::now() >= session_end {
                break;
            }
        }
        let _ = atx.blocking_send(json!({"type": "monitor-done", "windows": n}));
    });

    loop {
        tokio::select! {
            ev = arx.recv() => {
                match ev {
                    Some(m) => {
                        let done = matches!(
                            m.get("type").and_then(|t| t.as_str()),
                            Some("monitor-done" | "error")
                        );
                        if !send(socket, m).await {
                            return false;
                        }
                        if done {
                            return true;
                        }
                    }
                    None => break,
                }
            }
            msg = socket.recv() => {
                if let Some(Ok(_)) = msg {
                    cancel.store(true, Ordering::Relaxed);
                    continue;
                }
                return false;
            }
        }
    }
    false
}

#[cfg(not(feature = "tools"))]
async fn cmd_monitor_remote(
    socket: &mut WebSocket,
    _state: &Arc<AppState>,
    _win: Duration,
    _via: Option<String>,
    _iface: Option<String>,
) -> bool {
    send_err(socket, "remote monitor needs the `tools` build feature").await;
    true
}
