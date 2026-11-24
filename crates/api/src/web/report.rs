//! Report → HTML — per-protocol tab views with separated obsidian hero KPIs
//! and crisp light/dark workspace panels. All tabs render up front; ntod.js
//! toggles panels client-side and drives accessible finding→evidence drill-down.

use maud::{Markup, html};
use ntod_analysis::Report;
use ntod_core::Proto;

use super::components::{
    empty_block, fmt_bytes, fmt_tls_version, report_finding, table_search_bar, time_ms,
};

const TABS: &[&str] = &[
    "conversations",
    "hosts",
    "dns",
    "http",
    "tls",
    "dhcp",
    "creds",
    "files",
];

fn proto_name(p: Proto) -> String {
    match p {
        Proto::Tcp => "TCP".into(),
        Proto::Udp => "UDP".into(),
        Proto::Icmp => "ICMP".into(),
        Proto::Other(n) => format!("PROTO-{n}"),
    }
}

fn clip(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

fn tab_count(tab: &str, r: &Report) -> usize {
    match tab {
        "hosts" => r.hosts.len(),
        "dns" => r.dns.len(),
        "http" => r.http.len(),
        "tls" => r.tls.len(),
        "dhcp" => r.dhcp.len(),
        "creds" => r.credentials.len(),
        "files" => r.objects.len(),
        _ => r.conversations.len(),
    }
}

/// Full report — obsidian hero KPI strip + light/dark findings, tabs, and tables.
pub fn report_fragment(r: &Report, rid: u64) -> Markup {
    let m = &r.meta;
    let dur = if m.duration_ms >= 1000 {
        format!("{:.1}s", m.duration_ms as f64 / 1000.0)
    } else {
        format!("{}ms", m.duration_ms)
    };
    let meta = format!("{} pkts · {} · {dur}", m.packets, fmt_bytes(m.bytes));
    let findings_cls = if r.findings.is_empty() {
        "stat ok"
    } else {
        "stat err"
    };
    let l7_total = r.dns.len() + r.http.len() + r.tls.len() + r.dhcp.len();

    html! {
        div id="report-workspace" {
            div.telemetry-island.report-hero id="island-report" {
                div.sec-head {
                    h2.sec-title { "Capture summary" }
                    span.legend { span id="report-meta" { (meta) } }
                }
                div.stats {
                    div class=(findings_cls) {
                        div.v { (r.findings.len()) }
                        div.k { "Findings" }
                    }
                    div.stat {
                        div.v { (r.hosts.len()) }
                        div.k { "Hosts" }
                    }
                    div.stat {
                        div.v { (r.conversations.len()) }
                        div.k { "Conversations" }
                    }
                    div.stat {
                        div.v { (l7_total) }
                        div.k { "L7 events" }
                    }
                }
                div.report-actions id="report-stats" {
                    @if let Some(cid) = m.capture_id {
                        a.chip.chip-link href={"/api/capture/" (cid) "/pcap"} download
                            hx-boost="false" { "Download PCAP" (if m.export_partial { "*" } else { "" }) }
                    }
                    a.chip.chip-link href={"/api/report/" (rid)} download hx-boost="false" { "Export JSON" }
                    @if cfg!(feature = "ai") {
                        button.chip.chip-link type="button"
                            hx-post={"/partials/ai-summary/" (rid)} hx-target="#ai-out"
                            hx-swap="innerHTML" hx-disabled-elt="this" { "AI summary" }
                    }
                }
            }

            section aria-label="Triage findings" {
                div id="findings" {
                    @if r.findings.is_empty() {
                        div.finding { p.fd { "No triage findings in this capture." } }
                    } @else {
                        @for (i, f) in r.findings.iter().enumerate() { (report_finding(i, f)) }
                    }
                }
                div id="ai-out" {}
            }

            div.report-filter-bar id="report-filter-bar" role="status" aria-live="polite" hidden {
                span id="report-filter-label" {}
                button.btn.xs.ghost type="button" data-clear-filter="true" { "Clear filter" }
            }

            div.seg id="report-tabs" role="tablist" aria-label="Report sections" {
                @for (i, t) in TABS.iter().enumerate() {
                    @let n = tab_count(t, r);
                    label {
                        input type="radio" name="rtab" value=(t) checked?[i == 0];
                        span.opt {
                            (t)
                            @if n > 0 { span.tab-cnt { (n) } }
                        }
                    }
                }
            }

            @for (i, t) in TABS.iter().enumerate() {
                div.rtab-panel data-rtab=(t) hidden?[i != 0] {
                    (tab_panel(t, r))
                }
            }
        }
    }
}

fn tab_panel(tab: &str, r: &Report) -> Markup {
    match tab {
        "hosts" => table(
            &[
                "IP", "Device", "OS", "Bytes", "MAC", "Vendor", "Ports", "Names",
            ],
            hosts_rows(r),
            "hosts",
            r.hosts.len(),
        ),
        "dns" => table(
            &["Time", "Client", "Name", "Type", "Rcode", "Answers"],
            dns_rows(r),
            "dns",
            r.dns.len(),
        ),
        "http" => table(
            &["Time", "Client", "Method", "Host", "Path", "Status", "Type"],
            http_rows(r),
            "http",
            r.http.len(),
        ),
        "tls" => table(
            &[
                "Client", "Server", "SNI", "Version", "Cipher", "JA4", "JA3", "Certs",
            ],
            tls_rows(r),
            "tls",
            r.tls.len(),
        ),
        "dhcp" => table(
            &["Time", "MAC", "Type", "Your IP", "Hostname", "Requested"],
            dhcp_rows(r),
            "dhcp",
            r.dhcp.len(),
        ),
        "creds" => table(
            &["Proto", "Source", "Destination", "User", "Secret"],
            creds_rows(r),
            "creds",
            r.credentials.len(),
        ),
        "files" => table(
            &["Time", "Client", "Host", "Path", "Type", "Size", ""],
            files_rows(r),
            "files",
            r.objects.len(),
        ),
        _ => table(
            &[
                "Host A",
                "Host B",
                "Protos",
                "Pkts",
                "Bytes",
                "Top ports",
                "",
            ],
            conv_rows(r),
            "conversations",
            r.conversations.len(),
        ),
    }
}

fn table(cols: &[&str], rows: Markup, tab: &str, count: usize) -> Markup {
    let empty = count == 0;
    let count_lbl = format!("{count} row{}", if count == 1 { "" } else { "s" });
    html! {
        div.dt {
            @if !empty {
                (table_search_bar(&format!("Filter {tab}…"), &count_lbl))
            }
            div.panel.flush {
                table {
                    thead { tr { @for c in cols { th { (c) } } } }
                    tbody { (rows) }
                }
                div.empty id={"empty-" (tab)} hidden?[!empty] {
                    span.empty-title { "No " (tab) " in this capture." }
                }
            }
        }
    }
}

fn conv_rows(r: &Report) -> Markup {
    let cid = r.meta.capture_id;
    html! {
        @for c in r.conversations.iter().take(500) {
            tr {
                td data-copy=(c.a) title="Click to copy IP" { (c.a) }
                td data-copy=(c.b) title="Click to copy IP" { (c.b) }
                td {
                    @for p in &c.protos {
                        span.proto-badge { (proto_name(*p)) } " "
                    }
                }
                td.num { (c.pkts) }
                td.num { (fmt_bytes(c.bytes)) }
                td { @if c.top_ports.is_empty() { "—" } @else {
                    (c.top_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
                } }
                td {
                    @if let Some(cid) = cid {
                        a.chip.chip-link href={"/api/capture/" (cid) "/pcap?a=" (c.a) "&b=" (c.b)}
                            download hx-boost="false" { "pcap" }
                    } @else { "—" }
                }
            }
        }
    }
}

fn hosts_rows(r: &Report) -> Markup {
    html! {
        @for h in &r.hosts {
            tr {
                td data-copy=(h.ip) title="Click to copy IP" { (h.ip) }
                td { (h.device.unwrap_or("—")) }
                td { (h.os.unwrap_or("—")) }
                td.num { (fmt_bytes(h.bytes)) }
                @match &h.mac {
                    Some(m) => { td data-copy=(m) title="Click to copy MAC" { (m) } }
                    None => { td { "—" } }
                }
                td { @match &h.vendor { Some(v) => (v), None => "—" } }
                td { @if h.ports.is_empty() { "—" } @else {
                    (h.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
                } }
                td { (h.names.join(", ")) }
            }
        }
    }
}

fn dns_rows(r: &Report) -> Markup {
    html! {
        @for d in r.dns.iter().take(500) {
            tr {
                td { (time_ms(d.ts)) }
                td data-copy=(d.client) { (d.client) }
                td data-copy=(d.name) { (d.name) }
                td { (d.qtype) "/" (d.service) }
                td { @match d.rcode { Some(c) => (c), None => "—" } }
                td { (d.answers.iter().take(4).cloned().collect::<Vec<_>>().join(", ")) }
            }
        }
    }
}

fn http_rows(r: &Report) -> Markup {
    html! {
        @for h in r.http.iter().take(500) {
            tr {
                td { (time_ms(h.ts)) }
                td data-copy=(h.client) { (h.client) }
                td { @match &h.method { Some(m) => span.proto-badge { (m) }, None => "—" } }
                td { @match &h.host { Some(m) => (m), None => "—" } }
                td { @match &h.path { Some(m) => (m), None => "—" } }
                @match h.status {
                    Some(s) if s >= 400 => { td.err { (s) } }
                    Some(s) => { td { (s) } }
                    None => { td { "—" } }
                }
                td { @match &h.content_type { Some(m) => (m), None => "—" } }
            }
        }
    }
}

fn tls_rows(r: &Report) -> Markup {
    html! {
        @for t in r.tls.iter().take(500) {
            tr {
                td data-copy=(t.client) { (t.client) }
                td data-copy=(format!("{}:{}", t.server, t.server_port)) { (t.server) ":" (t.server_port) }
                td { @match &t.sni { Some(s) => (s), None => "—" } }
                td { @match t.server_version.or(t.client_version) {
                    Some(v) => {
                        span title=(format!("0x{v:04x}")) { (fmt_tls_version(v)) }
                    }
                    None => "—"
                } }
                td { @match t.cipher { Some(c) => { (format!("0x{c:04x}")) } None => "—" } }
                @match &t.ja4 {
                    Some(j) => { td data-copy=(j) title=(j) { (clip(j, 16)) } }
                    None => { td { "—" } }
                }
                @match &t.ja3 {
                    Some(j) => { td data-copy=(j) title=(j) { (clip(j, 12)) } }
                    None => { td { "—" } }
                }
                td {
                    (t.certs.iter()
                        .map(|c| c.subject_cn.as_deref().unwrap_or("?"))
                        .collect::<Vec<_>>().join("; "))
                }
            }
        }
    }
}

fn dhcp_rows(r: &Report) -> Markup {
    html! {
        @for d in &r.dhcp {
            tr {
                td { (time_ms(d.ts)) }
                td data-copy=(d.client_mac) { (d.client_mac) }
                td { (d.msg_type) }
                td data-copy=(d.yiaddr) { (d.yiaddr) }
                td { @match &d.hostname { Some(h) => (h), None => "—" } }
                td { @match d.requested { Some(ip) => (ip), None => "—" } }
            }
        }
    }
}

fn creds_rows(r: &Report) -> Markup {
    html! {
        @for c in &r.credentials {
            tr {
                td { span.proto-badge { (c.proto) } }
                td data-copy=(c.src) { (c.src) }
                td data-copy=(c.dst) { (c.dst) }
                td { (c.user) }
                td {
                    span.secret-cell {
                        span.secret-val data-secret=(c.secret) data-revealed="false" { "••••••••" }
                        button.btn.xs.ghost.secret-toggle type="button" aria-expanded="false" { "Reveal" }
                    }
                }
            }
        }
    }
}

fn files_rows(r: &Report) -> Markup {
    html! {
        @for o in &r.objects {
            tr {
                td { (time_ms(o.ts)) }
                td data-copy=(o.client) { (o.client) }
                td { @match &o.host { Some(h) => (h), None => "—" } }
                td { @match &o.path { Some(p) => (p), None => "—" } }
                td { (o.mime) }
                td.num { (fmt_bytes(o.size as u64)) @if o.truncated { "*" } }
                td {
                    @if let Some(id) = o.id {
                        a.chip.chip-link href={"/api/objects/" (id)} download hx-boost="false" { "get" }
                    } @else { "—" }
                }
            }
        }
    }
}

/// Whole-fragment OOB form — used by the SSE "report" event so the
/// workspace replaces `#report-slot` while the event sink stays inert.
pub fn report_oob(r: &Report, rid: u64) -> Markup {
    html! {
        div id="report-slot" hx-swap-oob="true" {
            (report_fragment(r, rid))
        }
    }
}

/// Empty placeholder for `#report-slot` before a report exists.
pub fn report_slot() -> Markup {
    html! { div id="report-slot" {} (empty_block("Pick a .pcap/.pcapng — or capture 30s of live traffic.")) }
}
