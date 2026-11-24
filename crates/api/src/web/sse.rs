//! `/sse/*` — server-sent event streams carrying maud HTML fragments.
//! Every event sets a 24h `retry:` so the browser's native reconnect
//! can't re-run a completed command after the stream ends; the htmx
//! sse extension also tears down the EventSource when the connect
//! element leaves the DOM.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use maud::Markup;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{AppState, now_ms};

use super::components::{device_rows, finding_card, host_row_oob, host_row_skeleton, sev_name};
use super::{layout, report};

/// Native-reconnect poison — applied to every event.
const RETRY: Duration = Duration::from_secs(86_400);

fn ev(name: &str, m: Markup) -> Result<Event, Infallible> {
    Ok(Event::default().event(name).data(m.into_string()))
}

fn ev_retry(e: Result<Event, Infallible>) -> Result<Event, Infallible> {
    e.map(|e| e.retry(RETRY))
}

fn send_blocking(tx: &mpsc::Sender<Result<Event, Infallible>>, name: &str, m: Markup) -> bool {
    tx.blocking_send(ev_retry(ev(name, m))).is_ok()
}

async fn send_async(tx: &mpsc::Sender<Result<Event, Infallible>>, name: &str, m: Markup) -> bool {
    tx.send(ev_retry(ev(name, m))).await.is_ok()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sse/scan", get(scan))
        .route("/sse/analyze", get(analyze))
        .route("/sse/monitor", get(monitor))
}

fn sse(rx: mpsc::Receiver<Result<Event, Infallible>>) -> impl axum::response::IntoResponse {
    Sse::new(ReceiverStream::new(rx)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn close() -> Markup {
    maud::html! {
        div id="live" hx-swap-oob="true" {}
        (layout::stop_slot_oob(None))
    }
}

fn pills_done(msg: &str) -> Markup {
    maud::html! {
        (layout::status_pill_oob(msg, "done", true))
        (layout::sys_pill_oob(false, "Ready", true))
    }
}

fn pills_err(msg: &str) -> Markup {
    let msg = msg.replace(['\r', '\n'], " ");
    maud::html! {
        (layout::status_pill_oob(&msg, "err", true))
        (layout::sys_pill_oob(false, "Ready", true))
    }
}

// ---------- /sse/scan ----------

#[derive(Deserialize)]
pub struct ScanQuery {
    subnet: Option<String>,
    timeout_ms: Option<u64>,
    workers: Option<usize>,
    /// `arp=0` skips ARP-first probing; `deep=1` merges nmap -sV detail.
    arp: Option<bool>,
    deep: Option<bool>,
}

async fn scan(Query(q): Query<ScanQuery>) -> impl axum::response::IntoResponse {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(256);
    let subnet = match crate::resolve_subnet_async(q.subnet).await {
        Ok(s) => s,
        Err((_, e)) => {
            let _ = send_async(&tx, "error", pills_err(&e)).await;
            let _ = send_async(&tx, "close", close()).await;
            return sse(rx);
        }
    };
    let timeout = Duration::from_millis(q.timeout_ms.unwrap_or(800).clamp(50, 10_000));
    let workers = q.workers.unwrap_or(64).clamp(1, 256);
    let arp = q.arp.unwrap_or(true);
    let deep = q.deep.unwrap_or(false);
    tokio::task::spawn_blocking(move || {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut hosts = Vec::new();
        for h in ntod_core::scan::scan_stream_cancellable(
            subnet,
            timeout,
            workers,
            arp,
            Some(cancel.clone()),
        )
        .iter()
        {
            if !send_blocking(&tx, "found", host_row_skeleton(hosts.len() + 1, h.ip)) {
                cancel.store(true, Ordering::Relaxed);
                return;
            }
            hosts.push(h);
        }
        if tx.is_closed() {
            return;
        }
        ntod_core::discover::enrich(&mut hosts);
        crate::deep_merge(&mut hosts, deep);
        for (i, h) in hosts.iter().enumerate() {
            if !send_blocking(&tx, "host", host_row_oob(i + 1, h)) {
                return;
            }
        }
        let n = hosts.len();
        let _ = send_blocking(
            &tx,
            "done",
            pills_done(&format!("{n} host{}", if n == 1 { "" } else { "s" })),
        );
        let _ = send_blocking(&tx, "close", close());
    });
    sse(rx)
}

// ---------- /sse/analyze ----------

#[derive(Deserialize)]
pub struct AnalyzeQuery {
    tk: Option<u64>,
    seconds: Option<u64>,
}

async fn analyze(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AnalyzeQuery>,
) -> impl axum::response::IntoResponse {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    let secs = q.seconds.unwrap_or(30).clamp(5, 300);
    let tk = q.tk.unwrap_or(0);
    let cancel = state.token_flag(tk);
    tokio::task::spawn_blocking(move || {
        analyze_local(&state, &tx, secs, cancel);
        state.drop_token(tk);
    });
    sse(rx)
}

fn analyze_local(
    state: &AppState,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    secs: u64,
    cancel: Arc<AtomicBool>,
) {
    use std::time::Instant;

    let ip = match ntod_core::local_subnet() {
        Ok(s) => s.ip(),
        Err(e) => {
            send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
    };
    let mut cap = match ntod_capture::start(ip) {
        Ok(c) => c,
        Err(e) => {
            send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
    };
    let Some(rx) = cap.take_rx() else {
        send_blocking(tx, "error", pills_err("capture channel unavailable"));
        close_stream(tx);
        return;
    };

    let mut a = ntod_analysis::Analyzer::new();
    let started = Instant::now();
    ntod_analysis::feed_channel(
        &rx,
        &mut a,
        Duration::from_secs(secs),
        u64::MAX,
        || cancel.load(Ordering::Relaxed) || tx.is_closed(),
        |n| {
            let m = maud::html! {
                span.pill.running id="status" hx-swap-oob="true" {
                    "Capturing… " (n) " pkts · "
                    (started.elapsed().as_millis() / 1000) "s"
                }
                span id="report-meta" hx-swap-oob="true" { (n) " pkts" }
            };
            send_blocking(tx, "analyzing", m)
        },
    );
    cap.stop();
    if tx.is_closed() {
        return;
    }
    let mut r = a.finish();
    state.store_objects(&mut r);
    state.history_observe(&mut r);
    send_report(state, tx, r);
    close_stream(tx);
}

fn send_report(
    state: &AppState,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    r: ntod_analysis::Report,
) {
    let nf = r.findings.len();
    let np = r.meta.packets;
    let (rid, rep) = state.store_report(r);
    let m = maud::html! {
        (report::report_oob(&rep, rid))
        span id="report-meta" hx-swap-oob="true" {
            (np) " pkts · " (super::components::fmt_bytes(rep.meta.bytes))
        }
        (layout::status_pill_oob(
            &format!("{np} pkts · {nf} finding{}", if nf == 1 { "" } else { "s" }),
            if nf > 0 { "err" } else { "done" },
            true,
        ))
        (layout::sys_pill_oob(false, "Ready", true))
    };
    let _ = send_blocking(tx, "report", m);
}

fn close_stream(tx: &mpsc::Sender<Result<Event, Infallible>>) {
    let _ = send_blocking(tx, "close", close());
}

// ---------- /sse/monitor ----------

#[derive(Deserialize)]
pub struct MonitorQuery {
    tk: Option<u64>,
    window: Option<u64>,
    via: Option<String>,
    iface: Option<String>,
}

async fn monitor(
    State(state): State<Arc<AppState>>,
    Query(q): Query<MonitorQuery>,
) -> impl axum::response::IntoResponse {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    let win = Duration::from_secs(q.window.unwrap_or(15).clamp(5, 60));
    let tk = q.tk.unwrap_or(0);
    let cancel = state.token_flag(tk);
    tokio::task::spawn_blocking(move || {
        match (q.via.as_deref().map(str::trim), q.iface.as_deref()) {
            (Some(via), _) if !via.is_empty() => {
                #[cfg(feature = "tools")]
                monitor_remote(
                    &state,
                    &tx,
                    win,
                    cancel,
                    via,
                    q.iface.as_deref().unwrap_or("any"),
                );
                #[cfg(not(feature = "tools"))]
                {
                    let _ = via;
                    let _ = send_blocking(
                        &tx,
                        "error",
                        pills_err("remote monitor needs the `tools` build feature"),
                    );
                    close_stream(&tx);
                }
            }
            _ => monitor_local(&state, &tx, win, cancel),
        }
        state.drop_token(tk);
    });
    sse(rx)
}

/// Fold a finished window's findings into the mon-feed + refresh device table once per window.
fn emit_window(
    state: &AppState,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    findings: &[ntod_analysis::report::Finding],
    window: u64,
    packets: u64,
) -> bool {
    for f in findings {
        let m = maud::html! {
            (finding_card(None, None, sev_name(f.severity), &f.title, &f.detail, &f.evidence))
        };
        if !send_blocking(tx, "finding", m) {
            return false;
        }
    }
    let now = now_ms();
    let devs = state.devices();
    let m = maud::html! {
        span id="mon-status" hx-swap-oob="true" {
            "window " (window) " · " (packets) " pkts"
        }
        table {
            tbody id="rows" hx-swap-oob="innerHTML" {
                (device_rows(&devs, now))
            }
        }
    };
    send_blocking(tx, "monitor", m)
}

fn monitor_local(
    state: &AppState,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    win: Duration,
    cancel: Arc<AtomicBool>,
) {
    use std::time::Instant;

    let ip = match ntod_core::local_subnet() {
        Ok(s) => s.ip(),
        Err(e) => {
            let _ = send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
    };
    let mut cap = match ntod_capture::start(ip) {
        Ok(c) => c,
        Err(e) => {
            let _ = send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
    };
    let Some(rx) = cap.take_rx() else {
        let _ = send_blocking(tx, "error", pills_err("capture channel unavailable"));
        close_stream(tx);
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
            || cancel.load(Ordering::Relaxed) || tx.is_closed(),
            |_| true,
        );
        if tx.is_closed() {
            cap.stop();
            return;
        }
        let report = a.finish();
        n += 1;
        let findings = state.observe_history(&report);
        if !emit_window(state, tx, &findings, n, report.meta.packets) {
            cap.stop();
            return;
        }
        if cancel.load(Ordering::Relaxed) || Instant::now() >= session_end {
            break;
        }
    }
    cap.stop();
    let _ = send_blocking(
        tx,
        "monitor-done",
        maud::html! {
            span id="mon-status" hx-swap-oob="true" { "stopped after " (n) " windows" }
            (pills_done("Monitor stopped"))
        },
    );
    close_stream(tx);
}

#[cfg(feature = "tools")]
fn monitor_remote(
    state: &AppState,
    tx: &mpsc::Sender<Result<Event, Infallible>>,
    win: Duration,
    cancel: Arc<AtomicBool>,
    via: &str,
    iface: &str,
) {
    use std::time::Instant;

    let backend = match ntod_tools::Backend::from_spec(via) {
        Ok(b) => b,
        Err(e) => {
            let _ = send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
    };
    let session_end = Instant::now() + Duration::from_secs(3600);
    let mut n = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) || tx.is_closed() {
            break;
        }
        let bytes = match ntod_tools::sniff::capture_cancellable(
            &backend,
            iface,
            win.as_secs(),
            None,
            256 << 20,
            Some(&cancel),
        ) {
            Ok(b) => b,
            Err(e) => {
                let _ = send_blocking(tx, "error", pills_err(&e.to_string()));
                close_stream(tx);
                return;
            }
        };
        if tx.is_closed() {
            return;
        }
        let mut a = ntod_analysis::Analyzer::new();
        if !bytes.is_empty()
            && let Err(e) = ntod_capture::pcapr::for_each(&bytes, |p| {
                a.feed(p.ts_ms, p.linktype, p.data);
                true
            })
        {
            let _ = send_blocking(tx, "error", pills_err(&e.to_string()));
            close_stream(tx);
            return;
        }
        let report = a.finish();
        n += 1;
        let findings = state.observe_history(&report);
        if !emit_window(state, tx, &findings, n, report.meta.packets) {
            return;
        }
        if cancel.load(Ordering::Relaxed) || Instant::now() >= session_end {
            break;
        }
    }
    let _ = send_blocking(
        tx,
        "monitor-done",
        maud::html! {
            span id="mon-status" hx-swap-oob="true" { "stopped after " (n) " windows" }
            (pills_done("Monitor stopped"))
        },
    );
    close_stream(tx);
}
