//! Page shell — same markup shape as the vendored ntok design system,
//! refined for web, mobile (bottom dock), desktop, WCAG 2.2 AA, and strict CSP.

use maud::{DOCTYPE, Markup, PreEscaped, html};

/// (slug, title, lede) — nav order, drives the whole header.
pub const VIEWS: [(&str, &str, &str); 6] = [
    (
        "scan",
        "Network scan",
        "Discover live hosts on the local segment.",
    ),
    (
        "sniff",
        "Packet capture",
        "Live frames — built-in socket needs Administrator, or stream tcpdump over wsl:/ssh:.",
    ),
    ("wifi", "Wi-Fi survey", "Broadcast networks in range."),
    (
        "analyze",
        "Capture analysis",
        "Open a .pcap/.pcapng — parsed locally, nothing leaves this machine.",
    ),
    (
        "tools",
        "Tool box",
        "nmap and tcpdump — on the daemon host, in WSL, or over SSH.",
    ),
    (
        "devices",
        "Devices",
        "Every device remembered from live captures — Monitor watches for arrivals.",
    ),
];

fn nav_icon(view: &str) -> Markup {
    let inner = match view {
        "scan" => {
            r#"<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.5 5.5"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/>"#
        }
        "sniff" => r#"<path d="M3 12h4l2.5-6.5 4.5 13L16.5 12H21"/>"#,
        "wifi" => {
            r#"<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.7a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor" stroke="none"/>"#
        }
        "analyze" => {
            r#"<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5"/><circle cx="11" cy="14" r="2.2"/><path d="m12.8 15.8 1.9 1.9"/>"#
        }
        "tools" => {
            r#"<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M12 15h5"/>"#
        }
        _ => {
            r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/>"#
        }
    };
    html! {
        svg.ic viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
            stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" {
            (PreEscaped(inner))
        }
    }
}

/// Engine status pill — re-emitted OOB by streams (live / ready).
pub fn sys_pill(live: bool, label: &str) -> Markup {
    sys_pill_oob(live, label, false)
}

pub fn sys_pill_oob(live: bool, label: &str, oob: bool) -> Markup {
    let cls = if live { "sys-pill live" } else { "sys-pill" };
    html! {
        @if oob {
            span class=(cls) id="sys" role="status" aria-live="polite" title="Local engine status" hx-swap-oob="true" {
                (sys_pill_inner(label))
            }
        } @else {
            span class=(cls) id="sys" role="status" aria-live="polite" title="Local engine status" {
                (sys_pill_inner(label))
            }
        }
    }
}

fn sys_pill_inner(label: &str) -> Markup {
    html! {
        span.sys-k { "Engine" }
        span.sys-st {
            span.sys-dot aria-hidden="true" {}
            span id="sys-state" { (label) }
        }
    }
}

/// Status pill under the table — re-emitted OOB by fragments.
/// `kind`: "" | "running" | "done" | "err".
pub fn status_pill(msg: &str, kind: &str) -> Markup {
    status_pill_oob(msg, kind, false)
}

pub fn status_pill_oob(msg: &str, kind: &str, oob: bool) -> Markup {
    let cls = if kind.is_empty() {
        "pill".to_string()
    } else {
        format!("pill {kind}")
    };
    html! {
        @if oob {
            span class=(cls) id="status" role="status" aria-live="polite" hx-swap-oob="true" hidden?[msg.is_empty()] { (msg) }
        } @else {
            span class=(cls) id="status" role="status" aria-live="polite" hidden?[msg.is_empty()] { (msg) }
        }
    }
}

/// Stop-button slot inside `.page-actions` — swapped OOB when a cancellable
/// SSE stream starts, and cleared when the stream closes.
pub fn stop_slot_oob(tk: Option<u64>) -> Markup {
    html! {
        span id="stop-slot" hx-swap-oob="true" {
            @if let Some(tk) = tk {
                button.btn.danger type="button" hx-post={"/partials/stop/" (tk)} hx-swap="none" hx-disabled-elt="this" {
                    "Stop"
                }
            }
        }
    }
}

fn header(active: &str) -> Markup {
    html! {
        div.top-wrap {
            header.top {
                a.brand href="/" title="NTOD — LAN discovery & packet tools" {
                    span.mark { img src="/brand.png" alt=""; }
                    span.brand-text {
                        span.brand-name { "NTOD" }
                        span.brand-sub { "LAN discovery & packet tools" }
                    }
                }
                nav.nav aria-label="Views" {
                    @for (idx, (slug, _, _)) in VIEWS.iter().enumerate() {
                        @let hint = format!("{} (shortcut {})", nav_label(slug), idx + 1);
                        @if *slug == active {
                            a.navbtn href={"/" (slug)} data-nav=(slug) title=(hint) aria-current="page" {
                                (nav_icon(slug)) (nav_label(slug))
                            }
                        } @else {
                            a.navbtn href={"/" (slug)} data-nav=(slug) title=(hint) {
                                (nav_icon(slug)) (nav_label(slug))
                            }
                        }
                    }
                }
                div.top-right {
                    (sys_pill(false, "Ready"))
                }
            }
        }
    }
}

fn mobile_nav(active: &str) -> Markup {
    html! {
        nav.mobile-nav aria-label="Mobile navigation" {
            @for (slug, _, _) in VIEWS {
                @if slug == active {
                    a href={"/" (slug)} data-nav=(slug) aria-current="page" {
                        (nav_icon(slug))
                        span { (nav_label(slug)) }
                    }
                } @else {
                    a href={"/" (slug)} data-nav=(slug) {
                        (nav_icon(slug))
                        span { (nav_label(slug)) }
                    }
                }
            }
        }
    }
}

/// Nav labels (Scan/Sniff/Wi-Fi/Analyze/Tools/Devices).
fn nav_label(slug: &str) -> &'static str {
    match slug {
        "wifi" => "Wi-Fi",
        "scan" => "Scan",
        "sniff" => "Sniff",
        "analyze" => "Analyze",
        "tools" => "Tools",
        _ => "Devices",
    }
}

/// `<main>` — page head (title/lede/actions) + the swappable view body.
pub fn main_region(active: &str, actions: Markup, body: Markup) -> Markup {
    let (_, title, lede) = VIEWS
        .iter()
        .find(|(s, _, _)| *s == active)
        .copied()
        .unwrap_or(VIEWS[0]);
    html! {
        main id="main-content" tabindex="-1" {
            div.page-head {
                div {
                    span.eyebrow { "NTOD · " (nav_label(active)) }
                    h1 id="view-title" { (title) }
                    p.lede id="view-lede" { (lede) }
                }
                span.sp {}
                div.page-actions id="page-actions" {
                    (actions)
                    span id="stop-slot" {}
                }
            }
            div id="view-body" { (body) }
            div.status-row { (status_pill("", "")) }
        }
        footer.foot {
            span.foot-note { "NTOD — scan only systems you own or are authorized to test." }
            span.foot-note { "Keys: 1–6 views · / search · Esc clear" }
        }
    }
}

/// Full document.
pub fn shell(active: &str, content: Markup) -> Markup {
    let (_, title, _) = VIEWS
        .iter()
        .find(|(s, _, _)| *s == active)
        .copied()
        .unwrap_or(VIEWS[0]);
    html! {
        (DOCTYPE)
        html lang="en" data-view="night" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover";
                meta name="theme-color" id="meta-theme" content="#05080F";
                title { (title) " — NTOD" }
                link rel="icon" type="image/png" href="/icon.png";
                link rel="manifest" href="/manifest.json";
                link rel="stylesheet" href="/fonts.css";
                script src="/boot.js" {}
                link rel="stylesheet" href="/app.css";
                link rel="stylesheet" href="/ntod.css";
                script src="/vendor/htmx.min.js" defer {}
                script src="/vendor/sse.js" defer {}
                script src="/ntod.js" defer {}
                script src="/islands/loader.js" defer {}
            }
            body hx-boost="true" {
                a.skip-link href="#main-content" { "Skip to content" }
                (header(active))
                (content)
                (mobile_nav(active))
            }
        }
    }
}
