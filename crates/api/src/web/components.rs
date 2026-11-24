//! Shared fragments — host rows, port-map grid, finding cards, the
//! standard table panel. Remote-provided strings (SSIDs, hostnames) are
//! untrusted: everything goes through maud escaping, never PreEscaped.

use maud::{Markup, PreEscaped, html};
use ntod_analysis::history::{AlertRec, DevInfo};
use ntod_analysis::report::{Finding, Severity};
use ntod_core::Host;
use ntod_core::discover::TOP_PORTS;

pub fn fmt_bytes(n: u64) -> String {
    let u = ["B", "KB", "MB", "GB"];
    let mut n = n as f64;
    let mut i = 0;
    while n >= 1024.0 && i < u.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n as u64, u[i])
    } else {
        format!("{n:.1} {}", u[i])
    }
}

/// Human-readable TLS version label (raw hex preserved in tooltip).
pub fn fmt_tls_version(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".into(),
        0x0303 => "TLS 1.2".into(),
        0x0302 => "TLS 1.1".into(),
        0x0301 => "TLS 1.0".into(),
        0x0300 => "SSL 3.0".into(),
        _ => format!("0x{v:04x}"),
    }
}

/// Relative timestamp ("just now", "5m ago").
pub fn fmt_ago(ts_ms: i64, now_ms: i64) -> String {
    let s = ((now_ms - ts_ms) / 1000).max(0);
    if s < 60 {
        "just now".into()
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        fmt_date(ts_ms)
    }
}

/// `<time>` — JS rewrites the text to the browser's local timezone on
/// load/swap; the fallback text is UTC.
pub fn time_ms(ts: i64) -> Markup {
    html! { time data-ts=(ts) { (fmt_time(ts)) } }
}

fn fmt_time(ts_ms: i64) -> String {
    let secs = ts_ms / 1000;
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (h, m, s) = (tod / 3600, tod % 3600 / 60, tod % 60);
    let _ = days;
    format!("{h:02}:{m:02}:{s:02}")
}

fn fmt_date(ts_ms: i64) -> String {
    // Days since epoch → civil date (Howard Hinnant's algorithm).
    let z = ts_ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y}-{m:02}-{d:02}")
}

/// Search toolbar above filterable tables (reuses `.dt-tools` from app.css).
pub fn table_search_bar(placeholder: &str, count_label: &str) -> Markup {
    html! {
        div.dt-tools {
            div.field-in.dt-search-wrap {
                svg.ic viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                    stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" {
                    (PreEscaped(r#"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>"#))
                }
                input.txt type="search" data-table-filter="table" aria-label=(placeholder) placeholder=(placeholder);
            }
            span.dt-count { (count_label) }
        }
    }
}

/// Empty state under a table — hidden when `msg` is empty.
pub fn empty_block(msg: &str) -> Markup {
    html! {
        @if msg.is_empty() {
            div.empty id="empty" hidden {}
        } @else {
            div.empty id="empty" {
                span.empty-ic aria-hidden="true" {
                    svg.ic viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                        stroke-linecap="round" stroke-linejoin="round" {
                        (PreEscaped(r#"<circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><circle cx="12" cy="16" r=".8" fill="currentColor" stroke="none"/>"#))
                    }
                }
                span.empty-title { (msg) }
            }
        }
    }
}

/// `.panel.flush` table region.
pub fn table_panel(cols: &[&str], rows: Markup, empty_msg: &str) -> Markup {
    html! {
        div.panel.flush id="table-panel" {
            table {
                thead id="cols" {
                    tr { @for c in cols { th { (c) } } }
                }
                tbody id="rows" { (rows) }
            }
            (empty_block(empty_msg))
        }
    }
}

/// Element-id-safe form of an ip — htmx OOB looks targets up with
/// querySelector("#"+id), so dots are fatal. "10.0.0.5" → "10-0-0-5".
fn dom_id(ip: impl std::fmt::Display) -> String {
    ip.to_string()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Enriched-row replacement pushed OOB by the scan stream.
pub fn host_row_oob(idx: usize, h: &Host) -> Markup {
    html! {
        table {
            tbody {
                tr.flash id={"scan-" (dom_id(h.ip))} hx-swap-oob="true" {
                    (host_cells(idx, h))
                }
            }
        }
        (portmap_block_oob(h.ip, &host_sub(h), &h.open_ports))
    }
}

fn host_sub(h: &Host) -> String {
    [&h.hostname, &h.vendor]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn host_cells(idx: usize, h: &Host) -> Markup {
    html! {
        td.idx { (idx) }
        td data-copy=(h.ip) title="Click to copy IP" { (h.ip) }
        @match &h.mac {
            Some(m) => { td data-copy=(m) title="Click to copy MAC" { (m) } }
            None => { td { "—" } }
        }
        td { @match &h.hostname { Some(n) => (n), None => "—" } }
        td { @match &h.vendor { Some(v) => (v), None => "—" } }
        td.acc {
            @if let Some(svcs) = &h.services {
                (svcs
                    .iter()
                    .map(|s| match &s.name {
                        Some(n) => format!("{}/{n}", s.port),
                        None => s.port.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", "))
            } @else if h.open_ports.is_empty() { "—" } @else {
                (h.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
            }
        }
    }
}

/// Skeleton row pushed by the scan "found" phase — enriched later OOB.
pub fn host_row_skeleton(idx: usize, ip: impl std::fmt::Display) -> Markup {
    html! {
        tr.flash id={"scan-" (dom_id(&ip))} {
            td.idx { (idx) }
            td data-copy=(ip) title="Click to copy IP" { (ip) }
            td { "…" } td { "…" } td { "…" } td { "…" }
        }
    }
}

/// Per-host port grid — the scan view's signature telemetry block.
#[cfg(feature = "tools")]
#[allow(dead_code)]
pub fn portmap_block(ip: impl std::fmt::Display, sub: &str, open_ports: &[u16]) -> Markup {
    portmap_inner(ip.to_string(), sub, open_ports, None)
}

/// OOB form for SSE — `beforeend:#portmap` appends the block itself.
pub fn portmap_block_oob(ip: impl std::fmt::Display, sub: &str, open_ports: &[u16]) -> Markup {
    portmap_inner(ip.to_string(), sub, open_ports, Some("beforeend:#portmap"))
}

fn portmap_inner(ip: String, sub: &str, open_ports: &[u16], oob: Option<&str>) -> Markup {
    let did = dom_id(&ip);
    html! {
        @match oob {
            Some(spec) => {
                div id={"pm-" (did)} hx-swap-oob=(spec) {
                    (portmap_content(&ip, sub, open_ports))
                }
            }
            None => {
                div id={"pm-" (did)} {
                    (portmap_content(&ip, sub, open_ports))
                }
            }
        }
    }
}

fn portmap_content(ip: &str, sub: &str, open_ports: &[u16]) -> Markup {
    html! {
        div.host-head {
            (ip)
            @if !sub.is_empty() { " " span.hc { (sub) } }
        }
        div.grid {
            @for p in TOP_PORTS {
                @if open_ports.contains(p) {
                    span.cell.open title={(p) "/tcp — open"} { (p) }
                } @else {
                    span.cell.closed title={(p) "/tcp — probed"} { (p) }
                }
            }
        }
    }
}

pub fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Alert => "alert",
    }
}

/// Finding card. When `fidx` is set the card is keyboard-accessible and
/// drillable — data attrs carry the target tab and evidence list for ntod.js.
pub fn finding_card(
    fidx: Option<usize>,
    tab: Option<&str>,
    sev: &str,
    title: &str,
    detail: &str,
    evidence: &[String],
) -> Markup {
    html! {
        @match fidx {
            Some(i) => {
                div.finding role="button" tabindex="0"
                    data-fidx=(i)
                    data-ftitle=(title)
                    data-tab=(tab.unwrap_or("conversations"))
                    data-ev=(serde_json::to_string(evidence).unwrap_or_default())
                    title="Drill into matching evidence" {
                    h3 {
                        span.sev class={"sev-" (sev)} { (sev) }
                        (title)
                        span.finding-drill aria-hidden="true" { "Inspect →" }
                    }
                    p.fd { (detail) }
                    @if !evidence.is_empty() { p.ev { (evidence.join(" · ")) } }
                }
            }
            None => {
                div.finding {
                    h3 { span.sev class={"sev-" (sev)} { (sev) } (title) }
                    p.fd { (detail) }
                    @if !evidence.is_empty() { p.ev { (evidence.join(" · ")) } }
                }
            }
        }
    }
}

pub fn report_finding(idx: usize, f: &Finding) -> Markup {
    finding_card(
        if f.evidence.is_empty() {
            None
        } else {
            Some(idx)
        },
        Some(drill_tab(f.kind)),
        sev_name(f.severity),
        &f.title,
        &f.detail,
        &f.evidence,
    )
}

/// Alert-log line (persisted findings, devices view).
pub fn alert_card(a: &AlertRec, now_ms: i64) -> Markup {
    let sev = a.severity.as_str();
    html! {
        div.finding {
            h3 { span.sev class={"sev-" (sev)} { (sev) } (fmt_ago(a.ts, now_ms)) " — " (a.title) }
        }
    }
}

const DEV_COLS: &[&str] = &[
    "",
    "MAC",
    "IPs",
    "Vendor",
    "Device",
    "First seen",
    "Last seen",
];

/// One remembered-device row — the "on" dot is last_seen within 5 min.
pub fn device_row(d: &DevInfo, now: i64) -> Markup {
    let on = now - d.last_seen < 5 * 60 * 1000;
    let ips = d.ips.join(", ");
    html! {
        tr {
            td {
                i class=(if on { "dot on" } else { "dot" })
                    title=(if on { "seen in the last 5 min" } else { "offline" }) {}
            }
            td data-copy=(d.mac) title="Click to copy MAC" { (d.mac) }
            td data-copy=(ips) title="Click to copy IP" { (ips) }
            td { @match &d.vendor { Some(v) => (v), None => "—" } }
            td { @match &d.device { Some(v) => (v), None => "—" } }
            td { (fmt_ago(d.first_seen, now)) }
            td { (fmt_ago(d.last_seen, now)) }
        }
    }
}

/// Whole devices table (thead + tbody + empty) — swapped as one unit by
/// the devices partial; monitor findings refresh just the tbody OOB.
pub fn devices_table(devs: &[DevInfo], now: i64) -> Markup {
    html! {
        table {
            thead id="cols" {
                tr { @for c in DEV_COLS { th { (c) } } }
            }
            tbody id="rows" {
                @for d in devs { (device_row(d, now)) }
            }
        }
        (empty_block(if devs.is_empty() {
            "Nothing remembered yet — run Monitor or a live analysis first."
        } else {
            ""
        }))
    }
}

#[allow(dead_code)]
pub fn device_rows(devs: &[DevInfo], now: i64) -> Markup {
    html! { @for d in devs { (device_row(d, now)) } }
}

/// Which report tab a finding kind drills into.
pub fn drill_tab(kind: &str) -> &'static str {
    match kind {
        "heavy-hitter" | "rate-anomaly" | "new-device" | "device-returned" | "arp-spoof" => "hosts",
        "dns-tunnel" => "dns",
        "cleartext-creds" => "creds",
        k if k.starts_with("cert-")
            || k.starts_with("sni-")
            || k.starts_with("weak-tls")
            || k.starts_with("ja3")
            || k.starts_with("heartbleed") =>
        {
            "tls"
        }
        _ => "conversations",
    }
}
