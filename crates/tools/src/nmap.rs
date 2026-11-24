//! nmap port/service scan — `-oX -` XML to stdout, never the tables.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ntod_core::{Host, Service};

use crate::error::Error;
use crate::runner::Backend;

/// Whole-run ceiling; a /24 top-100 sweep with -T4 takes seconds,
/// slow targets hit --host-timeout first anyway.
const RUN_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_XML: usize = 64 << 20;

/// A host nmap found up, with the open ports it reported.
#[derive(Debug, Clone, Serialize)]
pub struct NmapHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NmapPort {
    pub port: u16,
    pub proto: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// `nmap -oX - --top-ports N [-sV] <targets>`. Targets are IPs, CIDRs
/// or hostnames — validated so nothing smuggles a flag into argv.
pub fn scan(
    backend: &Backend,
    targets: &[&str],
    top_ports: u16,
    service: bool,
) -> Result<Vec<NmapHost>, Error> {
    if targets.is_empty() {
        return Err(Error::BadTarget("no targets".into()));
    }
    for t in targets {
        check_target(t)?;
    }
    let mut argv: Vec<String> = vec![
        "nmap".into(),
        "-oX".into(),
        "-".into(),
        "--top-ports".into(),
        top_ports.clamp(1, 1000).to_string(),
        "-T4".into(),
        "--host-timeout".into(),
        "60s".into(),
    ];
    if service {
        argv.push("-sV".into());
        argv.push("--version-light".into());
    }
    argv.extend(targets.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = backend.run(&refs, RUN_TIMEOUT, MAX_XML)?;
    parse_xml(&String::from_utf8_lossy(&out))
}

/// nmap `-sV --top-ports N` over already-discovered IPs and merge the
/// result in place — the `--deep` path shared by CLI and API.
pub fn deep_merge(backend: &Backend, hosts: &mut Vec<Host>, top_ports: u16) -> Result<(), Error> {
    if hosts.is_empty() {
        return Ok(());
    }
    let ips: Vec<String> = hosts.iter().map(|h| h.ip.to_string()).collect();
    let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
    let nmap_hosts = scan(backend, &refs, top_ports, true)?;
    apply_deep(hosts, nmap_hosts);
    Ok(())
}

/// Merge nmap findings into core hosts: fills missing mac/hostname/
/// vendor, attaches os + services, replaces open_ports with nmap's
/// (top-ports sweep covers more than the builtin 24). Hosts nmap saw
/// up that core missed are appended; the vec is re-sorted at the end.
pub fn apply_deep(hosts: &mut Vec<Host>, nmap_hosts: Vec<NmapHost>) {
    let mut by_ip: HashMap<Ipv4Addr, NmapHost> = nmap_hosts
        .into_iter()
        .filter_map(|h| h.ip.parse::<Ipv4Addr>().ok().map(|ip| (ip, h)))
        .collect();
    for h in hosts.iter_mut() {
        if let Some(n) = by_ip.remove(&h.ip) {
            fold_nmap(h, n);
        }
    }
    for (_, n) in by_ip {
        if let Ok(ip) = n.ip.parse::<Ipv4Addr>() {
            let mut h = Host::new(ip);
            fold_nmap(&mut h, n);
            hosts.push(h);
        }
    }
    hosts.sort_unstable();
}

/// Fold one nmap host into a core host — fills None gaps, replaces
/// ports/os/services outright (nmap's view is richer on all three).
fn fold_nmap(h: &mut Host, n: NmapHost) {
    if h.mac.is_none() {
        h.mac = n.mac;
    }
    if h.hostname.is_none() {
        h.hostname = n.hostname;
    }
    if h.vendor.is_none() {
        h.vendor = n.vendor;
    }
    h.os = n.os;
    h.open_ports = n.ports.iter().map(|p| p.port).collect();
    h.services = Some(
        n.ports
            .into_iter()
            .map(|p| Service {
                port: p.port,
                name: p.service,
                product: p.product,
                version: p.version,
            })
            .collect(),
    );
}

/// Targets become raw argv on every transport — reject anything that
/// could read as an nmap flag or a shell metachar.
pub(crate) fn check_target(t: &str) -> Result<(), Error> {
    let ok = !t.is_empty()
        && !t.starts_with('-')
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:/*_-[]".contains(c));
    ok.then_some(()).ok_or_else(|| Error::BadTarget(t.into()))
}

// ---- -oX schema (attributes come through serde as @name) ----

#[derive(Deserialize)]
struct NmapRun {
    #[serde(default)]
    host: Vec<XHost>,
}

#[derive(Deserialize)]
struct XHost {
    status: Option<XState>,
    #[serde(default)]
    address: Vec<XAddr>,
    hostnames: Option<XHostnames>,
    ports: Option<XPorts>,
    os: Option<XOs>,
}

#[derive(Deserialize)]
struct XState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Deserialize)]
struct XAddr {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
    #[serde(rename = "@vendor")]
    vendor: Option<String>,
}

#[derive(Deserialize)]
struct XHostnames {
    #[serde(default)]
    hostname: Vec<XName>,
}

#[derive(Deserialize)]
struct XName {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Deserialize)]
struct XPorts {
    #[serde(default)]
    port: Vec<XPort>,
}

#[derive(Deserialize)]
struct XPort {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: Option<XState>,
    service: Option<XService>,
}

#[derive(Deserialize)]
struct XService {
    #[serde(rename = "@name")]
    name: Option<String>,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
}

#[derive(Deserialize)]
struct XOs {
    #[serde(default)]
    osmatch: Vec<XOsMatch>,
}

#[derive(Deserialize)]
struct XOsMatch {
    #[serde(rename = "@name")]
    name: String,
}

fn parse_xml(xml: &str) -> Result<Vec<NmapHost>, Error> {
    let run: NmapRun = quick_xml::de::from_str(xml).map_err(|e| Error::Parse(e.to_string()))?;
    Ok(run.host.into_iter().filter_map(fold_host).collect())
}

fn fold_host(h: XHost) -> Option<NmapHost> {
    // Down/filtered hosts are emitted too — keep only "up".
    if h.status.map(|s| s.state != "up").unwrap_or(true) {
        return None;
    }
    let mut ip = None;
    let mut mac = None;
    let mut vendor = None;
    for a in h.address {
        match a.addrtype.as_str() {
            "mac" => {
                mac = Some(a.addr);
                vendor = a.vendor.or(vendor);
            }
            "ipv4" | "ipv6" => ip = ip.or(Some(a.addr)),
            _ => {}
        }
    }
    Some(NmapHost {
        ip: ip?,
        mac,
        hostname: h
            .hostnames
            .and_then(|hs| hs.hostname.into_iter().next())
            .map(|n| n.name),
        vendor,
        os: h
            .os
            .and_then(|os| os.osmatch.into_iter().next())
            .map(|m| m.name),
        ports: h
            .ports
            .map(|ps| {
                ps.port
                    .into_iter()
                    .filter(|p| p.state.as_ref().is_some_and(|s| s.state == "open"))
                    .map(|p| NmapPort {
                        port: p.portid,
                        proto: p.protocol,
                        service: p.service.as_ref().and_then(|s| s.name.clone()),
                        product: p.service.as_ref().and_then(|s| s.product.clone()),
                        version: p.service.and_then(|s| s.version),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - --top-ports 100 192.168.1.0/24" version="7.95">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="Netgear"/>
    <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="reset"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="97"/></os>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

    #[test]
    fn parses_up_hosts_with_open_ports() {
        let hosts = parse_xml(XML).unwrap();
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0];
        assert_eq!(h.ip, "192.168.1.1");
        assert_eq!(h.mac.as_deref(), Some("AA:BB:CC:11:22:33"));
        assert_eq!(h.hostname.as_deref(), Some("router.lan"));
        assert_eq!(h.vendor.as_deref(), Some("Netgear"));
        assert_eq!(h.os.as_deref(), Some("Linux 5.X"));
        assert_eq!(h.ports.len(), 2);
        assert_eq!(h.ports[0].port, 22);
        assert_eq!(h.ports[0].service.as_deref(), Some("ssh"));
        assert_eq!(h.ports[0].product.as_deref(), Some("OpenSSH"));
        assert_eq!(h.ports[1].port, 80);
    }

    #[test]
    fn apply_deep_fills_gaps_replaces_ports_and_appends() {
        let mut hosts = vec![{
            let mut h = Host::new(Ipv4Addr::new(10, 0, 0, 5));
            h.hostname = Some("known-name".into());
            h.open_ports = vec![80];
            h
        }];
        let nmap = vec![
            NmapHost {
                ip: "10.0.0.5".into(),
                mac: Some("aa:bb:cc:00:11:22".into()),
                hostname: Some("nmap-name".into()),
                vendor: Some("TestVendor".into()),
                os: Some("Linux 6.X".into()),
                ports: vec![
                    NmapPort {
                        port: 22,
                        proto: "tcp".into(),
                        service: Some("ssh".into()),
                        product: Some("OpenSSH".into()),
                        version: Some("9.6".into()),
                    },
                    NmapPort {
                        port: 443,
                        proto: "tcp".into(),
                        service: Some("https".into()),
                        product: None,
                        version: None,
                    },
                ],
            },
            NmapHost {
                ip: "10.0.0.9".into(),
                mac: None,
                hostname: None,
                vendor: None,
                os: None,
                ports: vec![],
            },
        ];
        apply_deep(&mut hosts, nmap);
        assert_eq!(hosts.len(), 2);
        let h = &hosts[0];
        assert_eq!(h.ip, Ipv4Addr::new(10, 0, 0, 5));
        // Core-found fields win; nmap only fills gaps.
        assert_eq!(h.hostname.as_deref(), Some("known-name"));
        assert_eq!(h.mac.as_deref(), Some("aa:bb:cc:00:11:22"));
        assert_eq!(h.vendor.as_deref(), Some("TestVendor"));
        assert_eq!(h.os.as_deref(), Some("Linux 6.X"));
        assert_eq!(h.open_ports, vec![22, 443]);
        let svcs = h.services.as_ref().unwrap();
        assert_eq!(svcs[0].name.as_deref(), Some("ssh"));
        assert_eq!(svcs[0].product.as_deref(), Some("OpenSSH"));
        // nmap-only host appended, sorted after 10.0.0.5.
        assert_eq!(hosts[1].ip, Ipv4Addr::new(10, 0, 0, 9));
    }

    #[test]
    fn rejects_flag_smuggling_targets() {
        assert!(check_target("192.168.1.0/24").is_ok());
        assert!(check_target("fd00::1").is_ok());
        assert!(check_target("router.lan").is_ok());
        assert!(check_target("-oX /tmp/x").is_err());
        assert!(check_target("1.2.3.4;id").is_err());
        assert!(check_target("").is_err());
    }
}
