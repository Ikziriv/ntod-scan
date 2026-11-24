#[cfg(feature = "cut")]
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ipnetwork::Ipv4Network;

#[derive(Parser)]
#[command(name = "ntod", version, about = "ntod: LAN discovery & packet tools")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Discover live hosts on the LAN (Fing tier)
    Scan {
        /// CIDR to scan; defaults to the /24 of the primary interface
        #[arg(long)]
        subnet: Option<Ipv4Network>,
        /// Per-probe timeout in milliseconds
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        /// Max concurrent probes
        #[arg(long, default_value_t = 64)]
        workers: usize,
        /// Skip enrichment (hostname/vendor/ports) — fast mode
        #[arg(long)]
        fast: bool,
        /// Skip the ARP-first probe — faster on dead-heavy subnets,
        /// but ICMP-hidden hosts stay undiscovered and MACs rely on the cache
        #[arg(long)]
        no_arp: bool,
        /// Merge nmap service/version detail into results (needs nmap installed)
        #[cfg(feature = "tools")]
        #[arg(long)]
        deep: bool,
    },
    /// Live packet capture (needs Administrator; tcpdump tier)
    Sniff {
        /// Stop after N packets (default: until Ctrl+C)
        #[arg(long)]
        count: Option<usize>,
    },
    /// Nearby WiFi networks (Kismet-lite)
    Wifi,
    /// Analyze a .pcap/.pcapng capture — the online-analyzer tier, local.
    Analyze {
        /// Capture file to analyze
        file: std::path::PathBuf,
        /// Dump the full report as JSON instead of a summary
        #[arg(long)]
        json: bool,
        /// Write carved HTTP objects to this directory
        #[arg(long)]
        carve: Option<std::path::PathBuf>,
    },
    /// Explicit HTTP/CONNECT proxy (Fiddler-lite)
    Proxy {
        #[arg(long, default_value_t = 8888)]
        port: u16,
        /// Allow forwarding to loopback / link-local targets (disabled by default for SSRF safety)
        #[arg(long)]
        allow_local: bool,
    },
    /// ARP-cut a host off the LAN (own networks only)
    #[cfg(feature = "cut")]
    Cut {
        target: Ipv4Addr,
        #[arg(long)]
        gateway: Ipv4Addr,
    },
    /// Throttle a host's throughput via full-MITM forward+drop
    #[cfg(feature = "cut")]
    Throttle {
        target: Ipv4Addr,
        #[arg(long)]
        gateway: Ipv4Addr,
        /// Rate cap in bytes/sec
        #[arg(long, default_value_t = 256_000)]
        rate: u32,
    },
    /// External Kali tools — nmap/tcpdump local, in WSL, or over SSH
    #[cfg(feature = "tools")]
    Tool {
        #[command(subcommand)]
        tool: ToolCmd,
        /// Where tools run: local | wsl[:distro] | ssh:[user@]host
        #[arg(long, global = true, default_value = "local")]
        via: String,
    },
    /// Run the daemon: HTTP API + web UI for all shells
    Serve {
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// Directory serving the web UI
        #[arg(long, default_value = "apps/web")]
        web_root: String,
    },
}

#[cfg(feature = "tools")]
#[derive(Subcommand)]
enum ToolCmd {
    /// Which adapters the backend can run (nmap, tcpdump)
    Probe,
    /// nmap port/service scan
    Nmap {
        /// Targets: IPs, CIDRs, hostnames
        #[arg(required = true)]
        targets: Vec<String>,
        /// Probe the N most common ports
        #[arg(long, default_value_t = 100)]
        top_ports: u16,
        /// Service/version detection (-sV --version-light)
        #[arg(long)]
        service: bool,
        /// Raw JSON output
        #[arg(long)]
        json: bool,
    },
    /// masscan — fast subnet sweep (needs root on the backend)
    Masscan {
        /// Targets: IPs, CIDRs
        #[arg(required = true)]
        targets: Vec<String>,
        /// Port spec: 80,443,1-1000 or U:53
        #[arg(long, default_value = "1-1000")]
        ports: String,
        /// Packets/sec
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// Raw JSON output
        #[arg(long)]
        json: bool,
    },
    /// airodump-ng monitor-mode WiFi survey (iface already in monitor mode)
    Airodump {
        /// Monitor-mode interface on the backend
        #[arg(long, default_value = "wlan0mon")]
        iface: String,
        /// Survey length in seconds
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Raw JSON output
        #[arg(long)]
        json: bool,
    },
    /// tcpdump capture → the same triage report as `analyze`
    Sniff {
        /// Interface on the backend (any, eth0, wlan0mon, ...)
        #[arg(long, default_value = "any")]
        iface: String,
        /// Capture length in seconds
        #[arg(long, default_value_t = 15)]
        seconds: u64,
        /// BPF filter, e.g. "host 10.0.0.4 and port 53"
        #[arg(long)]
        bpf: Option<String>,
        /// Write the raw .pcap here instead of analyzing
        #[arg(long)]
        save: Option<std::path::PathBuf>,
        /// Raw JSON report
        #[arg(long)]
        json: bool,
    },
}

fn run_async<F: std::future::Future<Output = Result<()>>>(fut: F) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(fut)
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Scan {
            subnet,
            timeout_ms,
            workers,
            fast,
            no_arp,
            #[cfg(feature = "tools")]
            deep,
        } => {
            let subnet = match subnet {
                Some(s) => s,
                None => ntod_core::local_subnet()?,
            };
            eprintln!("scanning {subnet} ...");
            let mut hosts =
                ntod_core::scan(subnet, Duration::from_millis(timeout_ms), workers, !no_arp);
            if !fast {
                ntod_core::discover::enrich(&mut hosts);
            }
            if hosts.is_empty() {
                println!("no hosts found");
            }
            #[cfg(feature = "tools")]
            if deep
                && let Ok(backend) = ntod_tools::Backend::from_spec("local")
                && let Err(e) = ntod_tools::nmap::deep_merge(&backend, &mut hosts, 100)
            {
                eprintln!("deep scan failed ({e}); showing basic results");
            }
            println!("IP\tMAC\tHOSTNAME\tVENDOR\tPORTS");
            for h in &hosts {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    h.ip,
                    h.mac.as_deref().unwrap_or("-"),
                    h.hostname.as_deref().unwrap_or("-"),
                    h.vendor.as_deref().unwrap_or("-"),
                    port_list(h),
                );
            }
            eprintln!("{} hosts", hosts.len());
        }
        Cmd::Sniff { count } => run_async(async move {
            let ip = ntod_core::local_subnet()?.ip();
            let mut cap = ntod_capture::start(ip)?;
            let Some(rx) = cap.take_rx() else {
                anyhow::bail!("capture channel unavailable");
            };
            eprintln!("capturing on {ip} — Ctrl+C to stop");
            let printer = std::thread::spawn(move || {
                for (i, frame) in rx.iter().enumerate() {
                    if let Some(n) = count
                        && i >= n
                    {
                        return true;
                    }
                    let Some(p) = ntod_capture::decode::decode_frame(
                        frame.linktype,
                        &frame.data,
                        frame.ts_ms,
                    ) else {
                        continue;
                    };
                    println!(
                        "{:?} {}:{} -> {}:{} ({}B)",
                        p.proto,
                        p.src,
                        p.sport.map(|p| p.to_string()).unwrap_or("-".into()),
                        p.dst,
                        p.dport.map(|p| p.to_string()).unwrap_or("-".into()),
                        p.len
                    );
                }
                false
            });
            tokio::select! {
                _ = tokio::signal::ctrl_c() => { cap.stop(); }
                _ = tokio::task::spawn_blocking(move || printer.join()) => {}
            }
            Ok(())
        })?,
        Cmd::Wifi => {
            let nets = ntod_core::wifi::networks()?;
            if nets.is_empty() {
                println!("no wifi networks found (adapter off or wired-only?)");
            }
            println!("SSID\tBSSID\tSIGNAL\tCH");
            for n in &nets {
                println!(
                    "{}\t{}\t{}\t{}",
                    n.ssid,
                    n.bssid.as_deref().unwrap_or("-"),
                    n.signal.map(|s| format!("{s}%")).unwrap_or("-".into()),
                    n.channel.map(|c| c.to_string()).unwrap_or("-".into())
                );
            }
        }
        Cmd::Analyze { file, json, carve } => {
            let bytes = std::fs::read(&file)?;
            let mut r = ntod_analysis::analyze(&bytes)?;
            if let Some(dir) = carve {
                std::fs::create_dir_all(&dir)?;
                let mut n = 0usize;
                for (i, o) in r.objects.iter_mut().enumerate() {
                    if o.data.is_empty() {
                        continue;
                    }
                    let ext: String = o
                        .mime
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .take(16)
                        .collect();
                    let name = format!("obj-{i:03}.{}", if ext.is_empty() { "bin" } else { &ext });
                    std::fs::write(dir.join(name), &o.data)?;
                    o.data.clear();
                    n += 1;
                }
                eprintln!("{n} carved object(s) → {}", dir.display());
            }
            print_report(&r, json)?;
        }
        Cmd::Proxy { port, allow_local } => run_async(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<ntod_proxy::ProxyEvent>(1024);
            tokio::spawn(async move {
                while let Some(e) = rx.recv().await {
                    println!(
                        "{} {} {} (up {}B, down {}B)",
                        e.client, e.method, e.target, e.bytes_up, e.bytes_down
                    );
                }
            });
            eprintln!("proxy on 127.0.0.1:{port} — set it as your HTTP(S) proxy");
            let cfg = ntod_proxy::ProxyConfig {
                allow_local,
                ..Default::default()
            };
            ntod_proxy::serve_with_config(format!("127.0.0.1:{port}").parse()?, tx, cfg).await?;
            Ok(())
        })?,
        #[cfg(feature = "cut")]
        Cmd::Cut { target, gateway } => run_async(async move {
            eprintln!("WARNING: cutting {target} off via {gateway} — own networks only");
            let cut = ntod_control::Cut::start(target, gateway)?;
            eprintln!("poisoning… Ctrl+C to restore");
            tokio::signal::ctrl_c().await?;
            drop(cut); // restores victim's ARP
            eprintln!("restored");
            Ok(())
        })?,
        #[cfg(feature = "cut")]
        Cmd::Throttle {
            target,
            gateway,
            rate,
        } => run_async(async move {
            eprintln!(
                "WARNING: throttling {target} via {gateway} at {rate} B/s — own networks only"
            );
            let t = ntod_control::Throttle::start(target, gateway, rate)?;
            eprintln!("poisoning both ways… Ctrl+C to restore");
            tokio::signal::ctrl_c().await?;
            drop(t);
            eprintln!("restored");
            Ok(())
        })?,
        #[cfg(feature = "tools")]
        Cmd::Tool { tool, via } => {
            let backend = ntod_tools::Backend::from_spec(&via)?;
            match tool {
                ToolCmd::Probe => {
                    for t in ntod_tools::probe(&backend) {
                        println!("{}\t{}", t.name, t.version.as_deref().unwrap_or("MISSING"));
                    }
                }
                ToolCmd::Nmap {
                    targets,
                    top_ports,
                    service,
                    json,
                } => {
                    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
                    let hosts = ntod_tools::nmap::scan(&backend, &refs, top_ports, service)?;
                    print_tool_hosts(&hosts, json)?;
                }
                ToolCmd::Masscan {
                    targets,
                    ports,
                    rate,
                    json,
                } => {
                    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
                    let hosts = ntod_tools::masscan::scan(&backend, &refs, &ports, rate)?;
                    print_tool_hosts(&hosts, json)?;
                }
                ToolCmd::Airodump {
                    iface,
                    seconds,
                    json,
                } => {
                    let aps =
                        ntod_tools::airodump::survey(&backend, &iface, seconds.clamp(1, 600))?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&aps)?);
                    } else {
                        println!("BSSID\tESSID\tCH\tSEC\tPWR");
                        for a in &aps {
                            println!(
                                "{}\t{}\t{}\t{}\t{}",
                                a.bssid,
                                a.essid,
                                a.channel.map(|c| c.to_string()).unwrap_or("-".into()),
                                a.privacy.as_deref().unwrap_or("-"),
                                a.power.map(|p| format!("{p}dBm")).unwrap_or("-".into())
                            );
                        }
                        eprintln!("{} APs", aps.len());
                    }
                }
                ToolCmd::Sniff {
                    iface,
                    seconds,
                    bpf,
                    save,
                    json,
                } => {
                    let bytes = ntod_tools::sniff::capture(
                        &backend,
                        &iface,
                        seconds.clamp(1, 3600),
                        bpf.as_deref(),
                        256 << 20,
                    )?;
                    if let Some(path) = save {
                        std::fs::write(&path, &bytes)?;
                        eprintln!("{} bytes → {}", bytes.len(), path.display());
                    } else {
                        print_report(&ntod_analysis::analyze(&bytes)?, json)?;
                    }
                }
            }
        }
        Cmd::Serve { port, web_root } => run_async(async move {
            let web_root = resolve_web_root(&web_root);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
            eprintln!("ntod daemon → http://127.0.0.1:{port} (ui: {web_root})");
            axum::serve(listener, ntod_api::router(&web_root)).await?;
            Ok(())
        })?,
    }
    Ok(())
}

// --web-root resolves relative to cwd; fall back to cwd/exe ancestors so
// the UI serves regardless of the launch directory.
fn resolve_web_root(web_root: &str) -> String {
    let root = std::path::Path::new(web_root);
    if root.is_dir() {
        return web_root.into();
    }
    let seeds = [
        std::env::current_dir().ok(),
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(std::path::Path::to_path_buf)),
    ];
    match find_in_ancestors(root, seeds.iter().flatten().map(|p| p.as_path())) {
        Some(p) => p.to_string_lossy().into_owned(),
        None => web_root.into(),
    }
}

fn find_in_ancestors<'a>(
    root: &std::path::Path,
    seeds: impl Iterator<Item = &'a std::path::Path>,
) -> Option<std::path::PathBuf> {
    seeds
        .flat_map(|s| s.ancestors())
        .map(|d| d.join(root))
        .find(|c| c.is_dir())
}

/// Ports as "22/ssh,443/https" when deep services exist, else plain ports.
fn port_list(h: &ntod_core::Host) -> String {
    match &h.services {
        Some(svcs) => svcs
            .iter()
            .map(|s| match &s.name {
                Some(n) => format!("{}/{n}", s.port),
                None => s.port.to_string(),
            })
            .collect::<Vec<_>>()
            .join(","),
        None => h
            .open_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

#[cfg(feature = "tools")]
fn print_tool_hosts(hosts: &[ntod_tools::nmap::NmapHost], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(hosts)?);
        return Ok(());
    }
    println!("IP\tMAC\tHOSTNAME\tOS/VENDOR\tPORTS");
    for h in hosts {
        let ports = h
            .ports
            .iter()
            .map(|p| match &p.service {
                Some(s) => format!("{}/{s}", p.port),
                None => p.port.to_string(),
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{}\t{}",
            h.ip,
            h.mac.as_deref().unwrap_or("-"),
            h.hostname.as_deref().unwrap_or("-"),
            h.os.as_deref().or(h.vendor.as_deref()).unwrap_or("-"),
            ports
        );
    }
    eprintln!("{} hosts", hosts.len());
    Ok(())
}

fn print_report(r: &ntod_analysis::Report, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(r)?);
        return Ok(());
    }
    println!(
        "{} packets · {} bytes · {}s",
        r.meta.packets,
        r.meta.bytes,
        r.meta.duration_ms / 1000
    );
    println!(
        "{} hosts · {} conversations · {} dns · {} http · {} tls · {} creds",
        r.hosts.len(),
        r.conversations.len(),
        r.dns.len(),
        r.http.len(),
        r.tls.len(),
        r.credentials.len()
    );
    if r.findings.is_empty() {
        println!("no findings");
    } else {
        println!("FINDINGS");
        for f in &r.findings {
            println!("  [{:?}] {} — {}", f.severity, f.title, f.detail);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_root_found_via_ancestor() {
        let base = std::env::temp_dir().join(format!("ntod-test-{}", std::process::id()));
        let deep = base.join("a/b/c");
        let web = base.join("apps/web");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(&web).unwrap();
        let found = find_in_ancestors(
            std::path::Path::new("apps/web"),
            [deep.as_path()].into_iter(),
        );
        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(found, Some(web));
    }

    #[test]
    fn web_root_missing_returns_none() {
        let found = find_in_ancestors(
            std::path::Path::new("no-such-dir-xyz"),
            [std::env::temp_dir().as_path()].into_iter(),
        );
        assert_eq!(found, None);
    }
}
