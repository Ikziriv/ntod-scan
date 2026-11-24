//! HTTP+WebSocket seam every shell (web, desktop, mobile, extension) uses.
//! Thin wrapper around ntod-core/ntod-capture — no engine logic here.

mod state;
mod web;
mod ws;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use include_dir::{Dir, include_dir};
use serde::Deserialize;
use tower_http::services::ServeDir;

pub(crate) use state::{AppState, now_ms};

/// Upload cap for /api/analyze and /partials/analyze (~64 MB).
pub(crate) const MAX_UPLOAD: usize = 64 << 20;

/// The apps/web bundle baked into the binary — the static fallback when
/// no on-disk web root exists, so `serve` works from any directory.
static EMBEDDED_WEB: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../apps/web");

/// Reject cross-site requests & Cross-Site WebSocket Hijacking (CSWSH).
/// Local daemon only serves loopback origins (or non-browser clients with no Origin).
async fn origin_guard(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(site) = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        && site.eq_ignore_ascii_case("cross-site")
    {
        return (StatusCode::FORBIDDEN, "cross-site request blocked").into_response();
    }
    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        && !is_local_origin(origin)
    {
        return (StatusCode::FORBIDDEN, "non-local origin blocked").into_response();
    }
    next.run(req).await
}

fn is_local_origin(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    let Some(host_port) = rest else {
        return false;
    };
    let host = if let Some(h) = host_port.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Security headers middleware — strict CSP (zero inline scripts),
/// clickjacking defense, MIME-sniffing protection, and no-referrer policy.
async fn security_headers(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    res
}

/// `web_root`: directory served at `/` when it exists on disk; otherwise
/// the `apps/web` bundle embedded in the binary is used.
pub fn router(web_root: &str) -> Router {
    router_with_state(web_root, Arc::new(AppState::new()))
}

fn router_with_state(web_root: &str, state: Arc<AppState>) -> Router {
    let r = Router::new()
        .route("/api/subnet", get(subnet))
        .route("/api/scan", get(scan))
        .route("/api/wifi", get(wifi))
        .route(
            "/api/analyze",
            post(analyze).layer(DefaultBodyLimit::max(MAX_UPLOAD)),
        )
        .route("/api/analyze/live", get(analyze_live))
        .route("/api/devices", get(devices))
        .route("/api/alerts", get(alerts))
        .route("/api/objects/{id}", get(get_object))
        .route("/api/capture/{id}/pcap", get(export_pcap))
        .route("/api/report/{id}", get(report_json))
        .route("/ws", get(ws::handler))
        .merge(web::router());
    // On-disk bundle wins (live edits in dev); embedded is the
    // self-contained fallback.
    let r = if std::path::Path::new(web_root).is_dir() {
        r.fallback_service(ServeDir::new(web_root))
    } else {
        r.fallback(embedded_asset)
    };
    #[cfg(feature = "ai")]
    let r = r
        .route("/api/ai/filter", post(ai::filter))
        .route("/api/ai/summarize", post(ai::summarize));
    #[cfg(feature = "tools")]
    let r = r
        .route("/api/tools", get(tools::probe))
        .route("/api/tools/nmap", get(tools::nmap))
        .route("/api/tools/masscan", get(tools::masscan))
        .route("/api/tools/airodump", get(tools::airodump))
        .route("/api/tools/sniff", get(tools::sniff));
    r.with_state(state)
        .layer(axum::middleware::from_fn(origin_guard))
        .layer(axum::middleware::from_fn(security_headers))
}

/// Static asset from the embedded apps/web bundle.
async fn embedded_asset(uri: axum::http::Uri) -> axum::response::Response {
    let path = uri.path().trim_start_matches('/');
    match EMBEDDED_WEB.get_file(path) {
        Some(f) => (
            [(header::CONTENT_TYPE, mime_for(path))],
            Bytes::from_static(f.contents()),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn mime_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css",
        Some("js" | "mjs") => "text/javascript",
        Some("json" | "map") => "application/json",
        Some("html") => "text/html",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}

/// POST raw .pcap/.pcapng bytes → triage report JSON.
/// Runs on a blocking thread; parsing is CPU-bound. Retains up to 32 MB
/// of frames so /api/capture/{id}/pcap can export filtered subsets.
async fn analyze(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    match analyze_bytes(&state, body).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared analysis path — JSON /api/analyze and HTML /partials/analyze.
/// Uploads never touch device history.
pub(crate) async fn analyze_bytes(
    state: &Arc<AppState>,
    body: Bytes,
) -> Result<ntod_analysis::Report, (StatusCode, String)> {
    let _permit = state
        .heavy_jobs
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "server busy".into()))?;
    match tokio::task::spawn_blocking(move || ntod_analysis::analyze_retain(&body, 32 << 20)).await
    {
        Ok(Ok((mut r, frames, complete))) => {
            state.store_objects(&mut r);
            r.meta.capture_id = state.store_capture(frames);
            r.meta.export_partial = !complete;
            Ok(r)
        }
        Ok(Err(e)) => Err((StatusCode::BAD_REQUEST, e.to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/report/{id} — export a retained report as JSON.
async fn report_json(State(state): State<Arc<AppState>>, Path(id): Path<u64>) -> impl IntoResponse {
    let Some(rep) = state.get_report(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::task::spawn_blocking(move || serde_json::to_vec_pretty(&*rep)).await {
        Ok(Ok(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"ntod-report-{id}.json\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    a: Option<String>,
    b: Option<String>,
}

/// GET /api/capture/{id}/pcap?a=IP&b=IP — re-export retained frames as
/// a classic .pcap. With a+b, only packets between those two hosts
/// (either direction); without, the whole retained capture.
async fn export_pcap(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    // Grab the Arc under lock and release immediately before CPU work.
    let Some(frames) = state.get_capture(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let task = tokio::task::spawn_blocking(move || {
        let a: Option<std::net::IpAddr> = q.a.as_deref().and_then(|s| s.parse().ok());
        let b: Option<std::net::IpAddr> = q.b.as_deref().and_then(|s| s.parse().ok());
        let linktype = frames.first().map(|f| f.linktype).unwrap_or(101);
        let mut w = ntod_capture::pcapw::PcapWriter::with_linktype(Vec::new(), linktype).ok()?;
        for f in frames.iter() {
            if f.linktype != linktype {
                continue; // pcap is single-DLT; skip the odd frame
            }
            if a.is_some() || b.is_some() {
                let Some(ev) = ntod_capture::decode::decode_frame(f.linktype, &f.data, f.ts_ms)
                else {
                    continue;
                };
                let m = |want: Option<std::net::IpAddr>| {
                    want.is_none_or(|w| ev.src == w || ev.dst == w)
                };
                if !(m(a) && m(b)) {
                    continue;
                }
            }
            w.write_packet(f.ts_ms, &f.data).ok()?;
        }
        Some((w.into_inner().ok()?, a, b))
    })
    .await;
    match task {
        Ok(Some((bytes, a, b))) => {
            let name = match (a, b) {
                (Some(x), Some(y)) => format!("ntod-{id}-{x}-{y}.pcap"),
                _ => format!("ntod-{id}.pcap"),
            };
            (
                [
                    (
                        header::CONTENT_TYPE,
                        "application/vnd.tcpdump.pcap".to_string(),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{name}\""),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /api/objects/{id} — download a carved object (zero-copy `Bytes`).
async fn get_object(State(state): State<Arc<AppState>>, Path(id): Path<u64>) -> impl IntoResponse {
    match state.get_object(id) {
        Some((data, name)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}\""),
                ),
            ],
            data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
struct LiveQuery {
    seconds: Option<u64>,
}

/// GET /api/analyze/live?seconds=30 — the same report, built from a timed
/// live capture. Needs capture privileges (admin / pcap-backend), same as
/// the sniff stream.
async fn analyze_live(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LiveQuery>,
) -> impl IntoResponse {
    let secs = q.seconds.unwrap_or(30).clamp(5, 300);
    let _permit = match state.heavy_jobs.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "server busy").into_response(),
    };
    let st = state.clone();
    match tokio::task::spawn_blocking(move || -> Result<_, (StatusCode, String)> {
        let ip = ntod_core::local_subnet()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ip();
        let mut r = ntod_analysis::analyze_live(ip, Duration::from_secs(secs), 200_000)
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
        st.store_objects(&mut r);
        st.history_observe(&mut r);
        Ok(r)
    })
    .await
    {
        Ok(Ok(r)) => Json(r).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/devices — remembered device registry (in-memory RwLock, zero disk I/O).
async fn devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.devices()).into_response()
}

/// GET /api/alerts — persisted findings log, newest first (in-memory RwLock, zero disk I/O).
async fn alerts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.alerts()).into_response()
}

#[derive(Deserialize)]
struct ScanQuery {
    subnet: Option<String>,
    timeout_ms: Option<u64>,
    workers: Option<usize>,
    /// `arp=0` skips ARP-first probing (faster on dead-heavy subnets).
    arp: Option<bool>,
    /// `deep=1` merges nmap -sV service detail (needs the tools feature
    /// and nmap installed; silently degrades otherwise).
    deep: Option<bool>,
}

async fn subnet() -> impl IntoResponse {
    match tokio::task::spawn_blocking(ntod_core::local_subnet).await {
        Ok(Ok(s)) => Json(serde_json::json!({ "subnet": s.to_string() })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn scan(Query(q): Query<ScanQuery>) -> impl IntoResponse {
    let subnet = match resolve_subnet_async(q.subnet).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let timeout = Duration::from_millis(q.timeout_ms.unwrap_or(800).clamp(50, 10_000));
    let workers = q.workers.unwrap_or(64).clamp(1, 256);
    let arp = q.arp.unwrap_or(true);
    let deep = q.deep.unwrap_or(false);

    let result = tokio::task::spawn_blocking(move || {
        let mut hosts = ntod_core::scan(subnet, timeout, workers, arp);
        ntod_core::discover::enrich(&mut hosts);
        crate::deep_merge(&mut hosts, deep);
        hosts
    })
    .await;

    match result {
        Ok(hosts) => Json(hosts).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// nmap `-sV` merge for `deep=1` scans — no-op without the tools
/// feature or when nmap/backend is unavailable (caller keeps basics).
#[cfg(feature = "tools")]
pub(crate) fn deep_merge(hosts: &mut Vec<ntod_core::Host>, deep: bool) {
    if !deep {
        return;
    }
    if let Ok(b) = ntod_tools::Backend::from_spec("local") {
        let _ = ntod_tools::nmap::deep_merge(&b, hosts, 100);
    }
}

#[cfg(not(feature = "tools"))]
pub(crate) fn deep_merge(_hosts: &mut Vec<ntod_core::Host>, _deep: bool) {}

async fn wifi() -> impl IntoResponse {
    match wifi_data().await {
        Ok(nets) => Json(nets).into_response(),
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn wifi_data() -> Result<Vec<ntod_core::wifi::WifiNetwork>, (StatusCode, String)> {
    match tokio::task::spawn_blocking(ntod_core::wifi::networks).await {
        Ok(Ok(nets)) => Ok(nets),
        Ok(Err(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

pub(crate) async fn resolve_subnet_async(
    s: Option<String>,
) -> Result<ipnetwork::Ipv4Network, (StatusCode, String)> {
    match s {
        Some(s) => {
            let net: ipnetwork::Ipv4Network = s.parse().map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid subnet '{s}': {e}"),
                )
            })?;
            if net.prefix() < 16 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "subnet '/{}' too broad — /16 or smaller required",
                        net.prefix()
                    ),
                ));
            }
            Ok(net)
        }
        None => tokio::task::spawn_blocking(ntod_core::local_subnet)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// External Kali tools — same bounded-subprocess adapters the CLI uses,
/// behind `via` (local | wsl[:distro] | ssh:[user@]host).
#[cfg(feature = "tools")]
mod tools {
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde::Deserialize;

    use crate::AppState;

    fn backend(via: Option<&str>) -> Result<ntod_tools::Backend, (StatusCode, String)> {
        match via {
            Some(s) if !s.is_empty() => ntod_tools::Backend::from_spec(s)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string())),
            _ => Ok(ntod_tools::Backend::from_env()),
        }
    }

    #[derive(Deserialize)]
    pub struct ProbeQuery {
        via: Option<String>,
    }

    /// GET /api/tools?via=ssh:kali@10.0.0.5 — which adapters the backend runs.
    pub async fn probe(Query(q): Query<ProbeQuery>) -> impl IntoResponse {
        match probe_data(q.via.as_deref()).await {
            Ok(ts) => Json(ts).into_response(),
            Err(e) => e.into_response(),
        }
    }

    pub(crate) async fn probe_data(
        via: Option<&str>,
    ) -> Result<Vec<ntod_tools::ToolInfo>, (StatusCode, String)> {
        let b = backend(via)?;
        tokio::task::spawn_blocking(move || ntod_tools::probe(&b))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }

    #[derive(Deserialize)]
    pub struct NmapQuery {
        targets: Option<String>,
        via: Option<String>,
        top_ports: Option<u16>,
        service: Option<bool>,
    }

    /// Blank → the local subnet; otherwise whitespace/comma split.
    async fn resolve_targets(raw: Option<String>) -> Result<Vec<String>, (StatusCode, String)> {
        match raw {
            Some(t) if !t.trim().is_empty() => Ok(t
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()),
            _ => tokio::task::spawn_blocking(ntod_core::local_subnet)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|s| vec![s.to_string()])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// GET /api/tools/nmap?targets=10.0.0.0/24&service=1
    pub async fn nmap(Query(q): Query<NmapQuery>) -> impl IntoResponse {
        match nmap_data_opts(
            q.via.as_deref(),
            q.targets,
            q.top_ports.unwrap_or(100),
            q.service.unwrap_or(true),
        )
        .await
        {
            Ok(hosts) => Json(hosts).into_response(),
            Err(e) => e.into_response(),
        }
    }

    async fn nmap_data_opts(
        via: Option<&str>,
        targets: Option<String>,
        top: u16,
        service: bool,
    ) -> Result<Vec<ntod_tools::nmap::NmapHost>, (StatusCode, String)> {
        let targets = resolve_targets(targets).await?;
        let b = backend(via)?;
        match tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
            ntod_tools::nmap::scan(&b, &refs, top, service)
        })
        .await
        {
            Ok(Ok(hosts)) => Ok(hosts),
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// HTML partials entry — nmap defaults (top 100, service detection).
    pub(crate) async fn nmap_data(
        via: Option<&str>,
        targets: Option<&str>,
    ) -> Result<Vec<ntod_tools::nmap::NmapHost>, (StatusCode, String)> {
        nmap_data_opts(via, targets.map(str::to_string), 100, true).await
    }

    #[derive(Deserialize)]
    pub struct MasscanQuery {
        targets: Option<String>,
        via: Option<String>,
        ports: Option<String>,
        rate: Option<u32>,
    }

    /// GET /api/tools/masscan?targets=10.0.0.0/24&ports=1-1000&rate=1000
    pub async fn masscan(Query(q): Query<MasscanQuery>) -> impl IntoResponse {
        match masscan_data_opts(
            q.via.as_deref(),
            q.targets,
            q.ports.as_deref().unwrap_or("1-1000"),
            q.rate.unwrap_or(1000),
        )
        .await
        {
            Ok(hosts) => Json(hosts).into_response(),
            Err(e) => e.into_response(),
        }
    }

    async fn masscan_data_opts(
        via: Option<&str>,
        targets: Option<String>,
        ports: &str,
        rate: u32,
    ) -> Result<Vec<ntod_tools::nmap::NmapHost>, (StatusCode, String)> {
        let targets = resolve_targets(targets).await?;
        let b = backend(via)?;
        let ports = ports.to_string();
        match tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
            ntod_tools::masscan::scan(&b, &refs, &ports, rate)
        })
        .await
        {
            Ok(Ok(hosts)) => Ok(hosts),
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// HTML partials entry — masscan defaults (1-1000 @ 1000pps).
    pub(crate) async fn masscan_data(
        via: Option<&str>,
        targets: Option<&str>,
    ) -> Result<Vec<ntod_tools::nmap::NmapHost>, (StatusCode, String)> {
        masscan_data_opts(via, targets.map(str::to_string), "1-1000", 1000).await
    }

    #[derive(Deserialize)]
    pub struct AirodumpQuery {
        via: Option<String>,
        iface: Option<String>,
        seconds: Option<u64>,
    }

    /// GET /api/tools/airodump?via=ssh:kali@lab&iface=wlan0mon&seconds=10
    pub async fn airodump(Query(q): Query<AirodumpQuery>) -> impl IntoResponse {
        match airodump_data_opts(
            q.via.as_deref(),
            q.iface.as_deref(),
            q.seconds.unwrap_or(10).clamp(3, 600),
        )
        .await
        {
            Ok(aps) => Json(aps).into_response(),
            Err(e) => e.into_response(),
        }
    }

    async fn airodump_data_opts(
        via: Option<&str>,
        iface: Option<&str>,
        seconds: u64,
    ) -> Result<Vec<ntod_tools::airodump::AiroAp>, (StatusCode, String)> {
        let b = backend(via)?;
        let iface = iface.unwrap_or("wlan0mon").to_string();
        match tokio::task::spawn_blocking(move || ntod_tools::airodump::survey(&b, &iface, seconds))
            .await
        {
            Ok(Ok(aps)) => Ok(aps),
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// HTML partials entry — 10s survey on the given iface.
    pub(crate) async fn airodump_data(
        via: Option<&str>,
        iface: Option<&str>,
    ) -> Result<Vec<ntod_tools::airodump::AiroAp>, (StatusCode, String)> {
        airodump_data_opts(via, iface, 10).await
    }

    #[derive(Deserialize)]
    pub struct SniffQuery {
        via: Option<String>,
        iface: Option<String>,
        seconds: Option<u64>,
        bpf: Option<String>,
    }

    /// GET /api/tools/sniff?via=ssh:kali@lab&iface=wlan0mon&seconds=30
    pub async fn sniff(
        State(state): State<Arc<AppState>>,
        Query(q): Query<SniffQuery>,
    ) -> impl IntoResponse {
        match sniff_data_opts(
            &state,
            q.via.as_deref(),
            q.iface.as_deref(),
            q.seconds.unwrap_or(15).clamp(5, 300),
            q.bpf.as_deref(),
        )
        .await
        {
            Ok(r) => Json(r).into_response(),
            Err(e) => e.into_response(),
        }
    }

    async fn sniff_data_opts(
        state: &Arc<AppState>,
        via: Option<&str>,
        iface: Option<&str>,
        secs: u64,
        bpf: Option<&str>,
    ) -> Result<ntod_analysis::Report, (StatusCode, String)> {
        let b = backend(via)?;
        let _permit = state
            .heavy_jobs
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "server busy".into()))?;
        let iface = iface.unwrap_or("any").to_string();
        let bpf = bpf.map(str::to_string);
        let st = state.clone();
        match tokio::task::spawn_blocking(move || -> Result<_, String> {
            let bytes = ntod_tools::sniff::capture(&b, &iface, secs, bpf.as_deref(), 256 << 20)
                .map_err(|e| e.to_string())?;
            let (mut r, frames, complete) =
                ntod_analysis::analyze_retain(&bytes, 32 << 20).map_err(|e| e.to_string())?;
            st.store_objects(&mut r);
            r.meta.capture_id = st.store_capture(frames);
            r.meta.export_partial = !complete;
            st.history_observe(&mut r);
            Ok(r)
        })
        .await
        {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, e)),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }

    /// HTML partials entry — 15s on the given iface, no filter.
    pub(crate) async fn sniff_data(
        state: &Arc<AppState>,
        via: Option<&str>,
        iface: Option<&str>,
    ) -> Result<ntod_analysis::Report, (StatusCode, String)> {
        sniff_data_opts(state, via, iface, 15, None).await
    }
}

#[cfg(feature = "ai")]
mod ai {
    use std::sync::Arc;

    use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
    use ntod_ai::AiBackend;
    use serde::Deserialize;

    use crate::AppState;

    #[derive(Deserialize)]
    pub struct FilterReq {
        q: String,
    }

    /// NL → Filter. Falls back to built-in rules when no LLM is up.
    pub async fn filter(
        State(state): State<Arc<AppState>>,
        Json(req): Json<FilterReq>,
    ) -> impl IntoResponse {
        Json(ntod_ai::nl_to_filter(&req.q, Some(&state.ai)).await)
    }

    #[derive(Deserialize)]
    pub struct SummarizeReq {
        kind: Option<String>,
        facts: String,
    }

    /// Summarize facts (host/flow aggregates — never payloads).
    pub async fn summarize(
        State(state): State<Arc<AppState>>,
        Json(req): Json<SummarizeReq>,
    ) -> impl IntoResponse {
        match ntod_ai::summarize(
            req.kind.as_deref().unwrap_or("network scan"),
            &req.facts,
            &state.ai as &dyn AiBackend,
        )
        .await
        {
            Ok(text) => Json(serde_json::json!({ "summary": text })).into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let dir = std::env::temp_dir().join(format!("ntod-api-test-{}", std::process::id()));
        router_with_state(".", Arc::new(AppState::with_data_dir(dir)))
    }

    #[tokio::test]
    async fn security_headers_present_and_cross_origin_blocked() {
        let app = test_app();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            res.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );

        // Cross-site Origin must be rejected (protects /ws and API).
        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .header(header::ORIGIN, "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);

        // Localhost Origin is allowed.
        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .header(header::ORIGIN, "http://127.0.0.1:7878")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sse_scan_invalid_subnet_does_not_panic() {
        let app = test_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/sse/scan?subnet=not-a-subnet")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn embedded_assets_served_when_web_root_missing() {
        let dir = std::env::temp_dir().join(format!("ntod-api-test-embed-{}", std::process::id()));
        let app = router_with_state("no-such-web-root", Arc::new(AppState::with_data_dir(dir)));
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/brand.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
    }

    #[tokio::test]
    async fn rejects_overbroad_subnet() {
        let app = test_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/scan?subnet=10.0.0.0/8")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
