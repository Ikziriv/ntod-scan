//! `/partials/*` — htmx fragment endpoints. One-shot views swap a table
//! or report; streaming starters emit an `hx-ext="sse"` connect element
//! whose sinks pull `/sse/*` events.

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use maud::{Markup, html};
use ntod_core::wifi::WifiNetwork;
use serde::Deserialize;

use crate::{AppState, now_ms};

#[cfg(feature = "tools")]
use super::components::portmap_block;
use super::components::{alert_card, devices_table, empty_block, table_panel, table_search_bar};
use super::{layout, pages, report};

const SCAN_COLS: &[&str] = &["#", "IP", "MAC", "Hostname", "Vendor", "Ports"];
#[cfg(feature = "tools")]
const TOOL_COLS: &[&str] = &["#", "IP", "MAC", "Hostname", "OS / Vendor", "Ports"];
#[cfg(feature = "tools")]
const AIRO_COLS: &[&str] = &["BSSID", "ESSID", "Ch", "SEC", "PWR"];

pub fn router() -> Router<Arc<AppState>> {
    let r = Router::new()
        .route("/partials/wifi", get(wifi))
        .route("/partials/devices", get(devices))
        .route("/partials/alerts", get(alerts))
        .route("/partials/scan/run", get(scan_run))
        .route(
            "/partials/analyze",
            post(analyze_upload).layer(DefaultBodyLimit::max(crate::MAX_UPLOAD)),
        )
        .route("/partials/analyze-live", get(analyze_live))
        .route("/partials/monitor/run", get(monitor_run))
        .route("/partials/stop/{tk}", post(stop_stream));
    #[cfg(feature = "tools")]
    let r = r
        .route("/partials/tools/probe", get(tools_probe))
        .route("/partials/tools/run", get(tools_run))
        .route("/partials/tools/sniff", get(tools_sniff));
    #[cfg(feature = "ai")]
    let r = r.route("/partials/ai-summary/{id}", post(ai_summary));
    r
}

/// `hx-ext="sse"` connect element + per-event sinks. Targeted events name
/// (event, css-target, swap-style); inert events carry all-OOB payloads.
/// Stop button is swapped OOB into `#stop-slot` inside `.page-actions` to
/// prevent layout shift.
fn stream_connect(
    url: &str,
    targeted: &[(&str, &str, &str)],
    inert: &[&str],
    stop_tk: Option<u64>,
) -> Markup {
    html! {
        div id="live" hx-ext="sse" sse-connect=(url) hidden {
            @for (ev, target, swap) in targeted {
                div sse-swap=(ev) hx-target=(target) hx-swap=(swap) {}
            }
            @for ev in inert {
                div sse-swap=(ev) hx-swap="none" hidden {}
            }
        }
        (layout::stop_slot_oob(stop_tk))
    }
}

fn err_table(cols: &[&str], msg: &str) -> Markup {
    html! {
        (table_panel(cols, html! {}, ""))
        (layout::status_pill_oob(msg, "err", true))
        (layout::sys_pill_oob(false, "Ready", true))
    }
}

// ---------- Wi-Fi ----------

fn wifi_row(w: &WifiNetwork) -> Markup {
    let lvl = w
        .signal
        .map(|s| ((s as u16 + 10) / 20).clamp(1, 5))
        .unwrap_or(0);
    html! {
        tr {
            td { @if w.ssid.is_empty() { "(hidden)" } @else { (w.ssid) } }
            @match &w.bssid {
                Some(b) => { td data-copy=(b) title="Click to copy BSSID" { (b) } }
                None => { td { "—" } }
            }
            td {
                @match w.signal {
                    Some(sig) => {
                        span.sec-pips.low[sig < 40] {
                            @for i in 0..5 { i.on[i < lvl] {} }
                        }
                        " " (sig) "%"
                    }
                    None => "—"
                }
            }
            td { @match w.channel { Some(c) => (c), None => "—" } }
        }
    }
}

async fn wifi() -> impl IntoResponse {
    match crate::wifi_data().await {
        Ok(nets) => {
            let n = nets.len();
            let rows = html! { @for w in &nets { (wifi_row(w)) } };
            html! {
                table {
                    thead id="cols" {
                        tr { th { "SSID" } th { "BSSID" } th { "Signal" } th { "Ch" } }
                    }
                    tbody id="rows" { (rows) }
                }
                (empty_block(if n == 0 { "No networks in range." } else { "" }))
                (layout::status_pill_oob(&format!("{n} network{}", if n == 1 { "" } else { "s" }), "done", true))
            }
        }
        Err((_, e)) => err_table(
            &["SSID", "BSSID", "Signal", "Ch"],
            &format!("Wi-Fi scan failed: {e}"),
        ),
    }
}

// ---------- Devices + alerts ----------

async fn devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let devs = state.devices();
    let n = devs.len();
    html! {
        (devices_table(&devs, now_ms()))
        (layout::status_pill_oob(&format!("{n} device{}", if n == 1 { "" } else { "s" }), "done", true))
    }
}

async fn alerts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let alerts = state.alerts();
    let now = now_ms();
    html! {
        @for a in alerts.iter().take(20) { (alert_card(a, now)) }
    }
}

// ---------- Scan stream starter ----------

async fn scan_run() -> impl IntoResponse {
    html! {
        (stream_connect(
            "/sse/scan",
            &[("found", "#rows", "beforeend")],
            &["host", "done", "error", "close"],
            None,
        ))
        (layout::sys_pill_oob(true, "Running", true))
        (layout::status_pill_oob("Scanning…", "running", true))
        (pages::portmap_island(false))
        div.dt {
            (table_search_bar("Filter hosts, IP, MAC, vendor, port…", ""))
            (table_panel(SCAN_COLS, html! {}, ""))
        }
    }
}

// ---------- Analyze ----------

async fn analyze_upload(
    State(state): State<Arc<AppState>>,
    mut mp: Multipart,
) -> impl IntoResponse {
    let mut bytes = Vec::new();
    let mut got = false;
    let mut too_big = false;
    while let Ok(Some(mut field)) = mp.next_field().await {
        if field.name() != Some("file") {
            continue;
        }
        got = true;
        loop {
            match field.chunk().await {
                Ok(Some(c)) => {
                    if bytes.len() + c.len() > crate::MAX_UPLOAD {
                        too_big = true;
                        break;
                    }
                    bytes.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(_) => {
                    too_big = true;
                    break;
                }
            }
        }
        break;
    }
    if !got || too_big || bytes.is_empty() {
        let msg = if too_big {
            "File too large — 64 MB max."
        } else {
            "No file received."
        };
        return html! {
            (report::report_slot())
            (layout::status_pill_oob(msg, "err", true))
        }
        .into_response();
    }
    match crate::analyze_bytes(&state, axum::body::Bytes::from(bytes)).await {
        Ok(r) => analyze_response(&state, r),
        Err((_, e)) => html! {
            (report::report_slot())
            (layout::status_pill_oob(&format!("Analysis failed: {e}"), "err", true))
            (layout::sys_pill_oob(false, "Ready", true))
        }
        .into_response(),
    }
}

/// Shared response shape for anything producing a Report — upload,
/// tools sniff. Report island + status pills, all inside #view-body.
fn analyze_response(state: &AppState, r: ntod_analysis::Report) -> axum::response::Response {
    let nf = r.findings.len();
    let np = r.meta.packets;
    let (rid, rep) = state.store_report(r);
    html! {
        div id="report-slot" { (report::report_fragment(&rep, rid)) }
        (empty_block(""))
        (layout::status_pill_oob(
            &format!("{np} pkts · {nf} finding{}", if nf == 1 { "" } else { "s" }),
            if nf > 0 { "err" } else { "done" },
            true,
        ))
        (layout::sys_pill_oob(false, "Ready", true))
    }
    .into_response()
}

/// Live-analyze starter — SSE progress ticks + report, stop via token.
async fn analyze_live(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tk = state.new_token();
    html! {
        (stream_connect(
            &format!("/sse/analyze?tk={tk}"),
            &[],
            &["analyzing", "report", "error", "close"],
            Some(tk),
        ))
        (layout::sys_pill_oob(true, "Running", true))
        (layout::status_pill_oob("Capturing 30s of live traffic…", "running", true))
        div id="report-slot" {
            div.telemetry-island id="island-report" {
                div.sec-head {
                    h2.sec-title { "Findings" }
                    span.legend { span id="report-meta" { "capturing…" } }
                }
            }
        }
    }
}

// ---------- Monitor (devices) ----------

#[derive(Deserialize)]
pub struct MonitorQuery {
    via: Option<String>,
    iface: Option<String>,
}

async fn monitor_run(
    State(state): State<Arc<AppState>>,
    Query(q): Query<MonitorQuery>,
) -> impl IntoResponse {
    let tk = state.new_token();
    let via = q.via.unwrap_or_default();
    let iface = q.iface.unwrap_or_default();
    let url = format!(
        "/sse/monitor?tk={tk}&via={}&iface={}",
        urlencoding(&via),
        urlencoding(&iface)
    );
    let devs = state.devices();
    let alerts = state.alerts();
    let now = now_ms();
    html! {
        (stream_connect(
            &url,
            &[("finding", "#mon-feed", "afterbegin")],
            &["monitor", "monitor-done", "error", "close"],
            Some(tk),
        ))
        (layout::sys_pill_oob(true, "Running", true))
        (layout::status_pill_oob("Monitoring…", "running", true))
        div.panel.control-panel id="island-dev" {
            div.sec-head {
                h2.sec-title { "Presence monitor" }
                span.legend { span id="mon-status" { "starting…" } }
            }
            form id="mon-form" {
                div.control-grid {
                    div.control-field {
                        label.toolbar-label for="mon-backend" { "Capture on" }
                        input.txt id="mon-backend" name="via" value=(via)
                            placeholder="local · wsl:kali-linux · ssh:user@host";
                    }
                    div.control-field {
                        label.toolbar-label for="mon-iface" { "Iface" }
                        input.txt id="mon-iface" name="iface" value=(iface) placeholder="any";
                    }
                }
            }
            div id="mon-feed" {}
            div id="alert-feed" {
                @for a in alerts.iter().take(20) { (alert_card(a, now)) }
            }
        }
        div.dt {
            (table_search_bar("Filter MAC, IP, vendor, device…", ""))
            div.panel.flush id="table-panel" {
                (devices_table(&devs, now))
            }
        }
    }
}

fn urlencoding(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':' | b'@') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

async fn stop_stream(State(state): State<Arc<AppState>>, Path(tk): Path<u64>) -> impl IntoResponse {
    state.cancel_token(tk);
    StatusCode::NO_CONTENT
}

// ---------- Tools (feature-gated) ----------

#[cfg(feature = "tools")]
#[derive(Deserialize)]
pub struct ToolsQuery {
    engine: Option<String>,
    via: Option<String>,
    targets: Option<String>,
    iface: Option<String>,
}

#[cfg(feature = "tools")]
async fn tools_probe(Query(q): Query<ToolsQuery>) -> impl IntoResponse {
    let text = match crate::tools::probe_data(q.via.as_deref()).await {
        Ok(ts) => ts
            .iter()
            .map(|t| {
                if t.version.is_some() {
                    format!("{} \u{2713}", t.name)
                } else {
                    format!("{} — missing", t.name)
                }
            })
            .collect::<Vec<_>>()
            .join(" · "),
        Err((_, e)) => format!("probe failed — {e}"),
    };
    html! { (text) }
}

#[cfg(feature = "tools")]
fn nmap_row(idx: usize, h: &ntod_tools::nmap::NmapHost) -> Markup {
    let ports = h
        .ports
        .iter()
        .map(|p| match &p.service {
            Some(s) => format!("{}/{s}", p.port),
            None => p.port.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    html! {
        tr.flash {
            td.idx { (idx) }
            td { (h.ip) }
            td { @match &h.mac { Some(m) => (m), None => "—" } }
            td { @match &h.hostname { Some(n) => (n), None => "—" } }
            td { @match h.os.as_deref().or(h.vendor.as_deref()) { Some(v) => (v), None => "—" } }
            td.acc { @if ports.is_empty() { "—" } @else { (ports) } }
        }
    }
}

#[cfg(feature = "tools")]
async fn tools_run(Query(q): Query<ToolsQuery>) -> impl IntoResponse {
    let engine = q.engine.as_deref().unwrap_or("nmap");
    if engine == "airodump" {
        return tools_airodump(&q).await;
    }
    let via = q.via.as_deref();
    let targets = q.targets.as_deref();
    let result = if engine == "masscan" {
        crate::tools::masscan_data(via, targets).await
    } else {
        crate::tools::nmap_data(via, targets).await
    };
    match result {
        Ok(hosts) => {
            let n = hosts.len();
            let rows = html! {
                @for (i, h) in hosts.iter().enumerate() { (nmap_row(i + 1, h)) }
            };
            let blocks = html! {
                @for h in &hosts {
                    (portmap_block(
                        &h.ip,
                        &[h.hostname.as_deref(), h.os.as_deref().or(h.vendor.as_deref())]
                            .into_iter().flatten().collect::<Vec<_>>().join(" · "),
                        &h.ports.iter().map(|p| p.port).collect::<Vec<_>>(),
                    ))
                }
            };
            html! {
                div.telemetry-island id="island-scan" hidden?[hosts.is_empty()] {
                    div.sec-head {
                        h2.sec-title { "Port map" }
                        span.legend {
                            span { i.l-open {} "open" }
                            span { i.l-closed {} "probed" }
                        }
                    }
                    div id="portmap" { (blocks) }
                }
                (table_panel(TOOL_COLS, rows, ""))
                (layout::status_pill_oob(
                    &format!("{n} host{}", if n == 1 { "" } else { "s" }),
                    "done", true,
                ))
            }
            .into_response()
        }
        Err((_, e)) => html! {
            (pages::portmap_island(true))
            (table_panel(TOOL_COLS, html! {},
                &format!("{engine} failed — install it on the backend or fix the via line.")))
            (layout::status_pill_oob(&format!("{engine} failed: {e}"), "err", true))
            (layout::sys_pill_oob(false, "Ready", true))
        }
        .into_response(),
    }
}

#[cfg(feature = "tools")]
async fn tools_airodump(q: &ToolsQuery) -> axum::response::Response {
    match crate::tools::airodump_data(q.via.as_deref(), q.iface.as_deref()).await {
        Ok(aps) => {
            let n = aps.len();
            let rows = html! {
                @for a in &aps {
                    tr.flash {
                        td { (a.bssid) }
                        td { @if a.essid.is_empty() { "(hidden)" } @else { (a.essid) } }
                        td { @match a.channel { Some(c) => (c), None => "—" } }
                        td { @match &a.privacy { Some(p) => (p), None => "—" } }
                        td.num { @match a.power { Some(p) => { (format!("{p} dBm")) } None => "—" } }
                    }
                }
            };
            html! {
                (pages::portmap_island(true))
                (table_panel(AIRO_COLS, rows,
                    if n == 0 { "Nothing heard — is that iface in monitor mode?" } else { "" }))
                (layout::status_pill_oob(&format!("{n} AP{}", if n == 1 { "" } else { "s" }), "done", true))
            }
            .into_response()
        }
        Err((_, e)) => html! {
            (pages::portmap_island(true))
            (table_panel(AIRO_COLS, html! {},
                "airodump failed — needs a monitor-mode iface on the backend."))
            (layout::status_pill_oob(&format!("airodump failed: {e}"), "err", true))
            (layout::sys_pill_oob(false, "Ready", true))
        }
        .into_response(),
    }
}

#[cfg(feature = "tools")]
async fn tools_sniff(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ToolsQuery>,
) -> impl IntoResponse {
    match crate::tools::sniff_data(&state, q.via.as_deref(), q.iface.as_deref()).await {
        Ok(r) => analyze_response(&state, r),
        Err((_, e)) => html! {
            (report::report_slot())
            (layout::status_pill_oob(&format!("Sniff failed: {e}"), "err", true))
            (layout::sys_pill_oob(false, "Ready", true))
        }
        .into_response(),
    }
}

// ---------- AI summary (feature-gated) ----------

#[cfg(feature = "ai")]
async fn ai_summary(State(state): State<Arc<AppState>>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(r) = state.get_report(id) else {
        return html! { p.fd { "Report expired — run the analysis again." } }.into_response();
    };
    let facts = serde_json::json!({
        "packets": r.meta.packets,
        "bytes": r.meta.bytes,
        "duration_ms": r.meta.duration_ms,
        "hosts": r.hosts.iter().take(10).map(|h| format!(
            "{} {}{}", h.ip, fmt_bytes_pub(h.bytes),
            h.vendor.as_deref().map(|v| format!(" ({v})")).unwrap_or_default()))
            .collect::<Vec<_>>(),
        "findings": r.findings.iter().map(|f| format!(
            "{}: {} — {}", super::components::sev_name(f.severity), f.title, f.detail))
            .collect::<Vec<_>>(),
        "dns_queries": r.dns.len(),
        "http_exchanges": r.http.len(),
        "tls_flows": r.tls.len(),
    });
    match ntod_ai::summarize(
        "packet-capture triage",
        &facts.to_string(),
        &state.ai as &dyn ntod_ai::AiBackend,
    )
    .await
    {
        Ok(s) => html! {
            div.finding { h3 { "AI summary" } p.fd { (s) } }
        }
        .into_response(),
        Err(e) => html! { p.fd { (format!("AI backend unreachable ({e})")) } }.into_response(),
    }
}

#[cfg(feature = "ai")]
fn fmt_bytes_pub(n: u64) -> String {
    super::components::fmt_bytes(n)
}
