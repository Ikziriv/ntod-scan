//! View bodies — the static first paint of each page. Live regions get
//! filled by /partials/* (htmx) or /sse/* (server-sent events); sniff is
//! a Svelte island over /ws.

use maud::{Markup, PreEscaped, html};

use super::components::{table_panel, table_search_bar};

const SCAN_COLS: &[&str] = &["#", "IP", "MAC", "Hostname", "Vendor", "Ports"];
const SNIFF_COLS: &[&str] = &["Time", "Proto", "Source", "Destination", "Bytes"];
const WIFI_COLS: &[&str] = &["SSID", "BSSID", "Signal", "Ch"];
#[cfg(feature = "tools")]
const TOOL_COLS: &[&str] = &["#", "IP", "MAC", "Hostname", "OS / Vendor", "Ports"];
const DEV_COLS: &[&str] = &[
    "",
    "MAC",
    "IPs",
    "Vendor",
    "Device",
    "First seen",
    "Last seen",
];

pub fn scan() -> (Markup, Markup) {
    let actions = html! {
        button.btn type="button" hx-get="/partials/scan/run" hx-target="#view-body"
            hx-swap="innerHTML" hx-disabled-elt="this" {
            "Scan"
        }
    };
    let body = html! {
        (portmap_island(true))
        div.dt {
            (table_search_bar("Filter hosts, IP, MAC, vendor, port…", ""))
            (table_panel(SCAN_COLS, html!{}, "Nothing yet — run a scan."))
        }
    };
    (actions, body)
}

/// Port-map island, shared by scan + tools pages and their fragments.
/// Stream starters render it unhidden — the header explains itself even
/// while empty.
pub fn portmap_island(hidden: bool) -> Markup {
    html! {
        div.telemetry-island id="island-scan" hidden?[hidden] {
            div.sec-head {
                h2.sec-title { "Port map" }
                span.legend {
                    span { i.l-open aria-hidden="true" {} "open" }
                    span { i.l-closed aria-hidden="true" {} "probed" }
                }
            }
            div id="portmap" {}
        }
    }
}

pub fn sniff() -> (Markup, Markup) {
    let actions = html! {
        button.btn type="button" id="go" data-sniff-toggle="true" aria-pressed="false" { "Capture" }
        // Revealed by the island once the daemon reports a stored capture
        // (WS `stopped` carries capture_id → /api/capture/{id}/pcap).
        a.btn.ghost id="dl" href="#" download hidden { "Download PCAP" }
    };
    // The Svelte island mounts on [data-island] and owns this region —
    // wave, packet table, capture state. Static fallback shows the
    // empty region until the bundle loads.
    let body = html! {
        div.panel.control-panel id="sniff-ctl" {
            div.sec-head {
                h2.sec-title { "Capture source" }
                span.legend { "blank = built-in socket (needs Administrator)" }
            }
            form id="sniff-form" {
                div.control-grid {
                    div.control-field {
                        label.toolbar-label for="sniff-backend" { "Capture on" }
                        input.txt id="sniff-backend" name="via"
                            placeholder="local · wsl:kali-linux · ssh:user@host";
                    }
                    div.control-field {
                        label.toolbar-label for="sniff-iface" { "Iface" }
                        input.txt id="sniff-iface" name="iface" placeholder="any";
                    }
                    div.control-field {
                        label.toolbar-label for="sniff-bpf" { "BPF filter" }
                        input.txt id="sniff-bpf" name="bpf" placeholder="tcp port 443";
                    }
                }
            }
        }
        div data-island="sniff" {
            div.telemetry-island id="island-sniff" {
                div.sec-head {
                    h2.sec-title { "Packet rate" }
                    span.legend { span id="wave-proto" { "—" } }
                }
                svg.wave id="wave" viewBox="0 0 480 68" preserveAspectRatio="none"
                    role="img" aria-label="Packets per second" {
                    path.base d="M0 34 H480" {}
                    path.fill id="wave-fill" d="" {}
                    path.sig id="wave-sig" d="" {}
                }
                div.wave-meta {
                    span { "48s window" }
                    span { span.peak id="wave-peak" { "0" } " pkt/s peak" }
                    span id="wave-total" { "0 total" }
                }
            }
            (table_panel(SNIFF_COLS, html!{}, "Nothing yet — start a capture."))
        }
    };
    (actions, body)
}

pub fn wifi() -> (Markup, Markup) {
    let actions = html! {
        button.btn type="button" hx-get="/partials/wifi" hx-target="#table-panel"
            hx-swap="innerHTML" hx-disabled-elt="this" {
            "Survey"
        }
    };
    let body = html! {
        div.dt {
            (table_search_bar("Filter SSID, BSSID, channel…", ""))
            (table_panel(WIFI_COLS, html!{}, "Nothing yet — run a survey."))
        }
    };
    (actions, body)
}

pub fn analyze() -> (Markup, Markup) {
    let actions = html! {
        form.upload-form hx-post="/partials/analyze" hx-encoding="multipart/form-data"
            hx-trigger="change" hx-target="#view-body" hx-swap="innerHTML" {
            label.btn for="pcap-file" { "Open file" }
            input id="pcap-file" type="file" name="file" accept=".pcap,.pcapng" hidden;
        }
        button.btn.ghost type="button" hx-get="/partials/analyze-live" hx-target="#view-body"
            hx-swap="innerHTML" hx-disabled-elt="this" {
            "Live 30s"
        }
    };
    let body = html! {
        div id="report-slot" {}
        div.empty.dropzone id="pcap-dropzone" role="button" tabindex="0"
            aria-label="Drop a .pcap or .pcapng file to analyze, or press Enter to browse" {
            span.empty-ic aria-hidden="true" {
                svg.ic viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                    stroke-linecap="round" stroke-linejoin="round" {
                    (PreEscaped(r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>"#))
                }
            }
            span.empty-title { "Drop a .pcap or .pcapng file here" }
            span.empty-sub { "Parsed locally in memory — nothing leaves this machine. Or click Live 30s to capture." }
        }
    };
    (actions, body)
}

#[cfg(feature = "tools")]
pub fn tools() -> (Markup, Markup) {
    let actions = html! {
        button.btn id="tool-submit-btn" type="submit" form="tool-form" hx-disabled-elt="this" { "Run nmap" }
        button.btn.ghost type="button" hx-get="/partials/tools/sniff" hx-include="#tool-form"
            hx-target="#tool-out" hx-swap="innerHTML" hx-disabled-elt="this" { "Sniff" }
    };
    let body = html! {
        div.panel.control-panel id="island-tools" {
            div.sec-head {
                h2.sec-title { "Backend" }
                span.legend {
                    span id="tool-probe" hx-get="/partials/tools/probe" hx-trigger="load"
                        hx-include="#tool-form" hx-swap="innerHTML" { "probing…" }
                }
            }
            form id="tool-form" hx-get="/partials/tools/run" hx-target="#tool-out"
                hx-swap="innerHTML" hx-disabled-elt="#tool-submit-btn" {
                div.control-grid {
                    div.control-field {
                        label.toolbar-label for="tool-engine" { "Tool" }
                        select.txt id="tool-engine" name="engine" {
                            option value="nmap" selected { "nmap" }
                            option value="masscan" { "masscan" }
                            option value="airodump" { "airodump-ng" }
                        }
                    }
                    div.control-field {
                        label.toolbar-label for="tool-backend" { "Run on" }
                        input.txt id="tool-backend" name="via" value="local"
                            placeholder="local · wsl:kali-linux · ssh:user@host";
                    }
                    div.control-field {
                        label.toolbar-label for="tool-targets" { "Targets" }
                        input.txt id="tool-targets" name="targets"
                            placeholder="10.0.0.0/24 or host — blank = LAN";
                    }
                    div.control-field {
                        label.toolbar-label for="tool-iface" { "Iface" }
                        input.txt id="tool-iface" name="iface" placeholder="any";
                    }
                }
            }
        }
        div id="tool-out" {
            (portmap_island(true))
            (table_panel(TOOL_COLS, html!{}, "Pick a tool and run it."))
        }
    };
    (actions, body)
}

#[cfg(not(feature = "tools"))]
pub fn tools() -> (Markup, Markup) {
    let actions = html! {};
    let body = html! {
        div.empty {
            span.empty-title { "The `tools` build feature is off" }
            span.empty-sub { "Rebuild with --features tools to enable nmap, masscan, and airodump-ng adapters." }
        }
    };
    (actions, body)
}

pub fn devices() -> (Markup, Markup) {
    let actions = html! {
        button.btn type="button" hx-get="/partials/devices" hx-target="#table-panel"
            hx-swap="innerHTML" hx-disabled-elt="this" {
            "Refresh"
        }
        button.btn.ghost type="button" hx-get="/partials/monitor/run" hx-include="#mon-form"
            hx-target="#view-body" hx-swap="innerHTML" hx-disabled-elt="this" { "Monitor" }
    };
    let body = html! {
        div.panel.control-panel id="island-dev" {
            div.sec-head {
                h2.sec-title { "Presence monitor" }
                span.legend { span id="mon-status" { "idle" } }
            }
            form id="mon-form" {
                div.control-grid {
                    div.control-field {
                        label.toolbar-label for="mon-backend" { "Capture on" }
                        input.txt id="mon-backend" name="via"
                            placeholder="local · wsl:kali-linux · ssh:user@host";
                    }
                    div.control-field {
                        label.toolbar-label for="mon-iface" { "Iface" }
                        input.txt id="mon-iface" name="iface" placeholder="any";
                    }
                }
            }
            div id="mon-feed" {}
            div id="alert-feed" hx-get="/partials/alerts" hx-trigger="load" hx-swap="innerHTML" {}
        }
        div.dt {
            (table_search_bar("Filter MAC, IP, vendor, device…", ""))
            (table_panel(DEV_COLS, html!{}, "Nothing remembered yet — run Monitor or a live analysis first."))
        }
    };
    (actions, body)
}
