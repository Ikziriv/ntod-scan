//! masscan — the fast subnet-wide sweep. `-oL -` list output: one
//! `open <proto> <port> <ip> <ts>` line per port, grouped into the same
//! host shape nmap returns.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::error::Error;
use crate::nmap::{NmapHost, NmapPort, check_target};
use crate::runner::Backend;

const RUN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_OUT: usize = 16 << 20;

/// `masscan <targets> -p<ports> --rate <n> -oL -`. `--wait` lets it
/// self-terminate after the final probes land. Needs root on the backend.
pub fn scan(
    backend: &Backend,
    targets: &[&str],
    ports: &str,
    rate: u32,
) -> Result<Vec<NmapHost>, Error> {
    if targets.is_empty() {
        return Err(Error::BadTarget("no targets".into()));
    }
    for t in targets {
        check_target(t)?;
    }
    check_ports(ports)?;
    let mut argv: Vec<String> = vec![
        "masscan".into(),
        format!("-p{ports}"),
        "--rate".into(),
        rate.clamp(1, 100_000).to_string(),
        "--wait".into(),
        "5".into(),
        "-oL".into(),
        "-".into(),
    ];
    argv.extend(targets.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = backend.run(&refs, RUN_TIMEOUT, MAX_OUT)?;
    parse_list(&String::from_utf8_lossy(&out))
}

/// `80,443,1-1000` or `U:53` — digits, ranges, proto prefixes only.
fn check_ports(p: &str) -> Result<(), Error> {
    let ok = !p.is_empty()
        && !p.starts_with('-')
        && p.chars().all(|c| c.is_ascii_digit() || ",-UT:".contains(c));
    ok.then_some(()).ok_or_else(|| Error::BadTarget(p.into()))
}

/// `open tcp 80 10.0.0.1 1700000000` lines → hosts with open ports.
fn parse_list(text: &str) -> Result<Vec<NmapHost>, Error> {
    let mut hosts: BTreeMap<String, NmapHost> = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        if f.next() != Some("open") {
            continue; // headers, banners lines, stats
        }
        let (Some(proto), Some(port), Some(ip)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let Ok(port) = port.parse() else { continue };
        hosts
            .entry(ip.to_string())
            .or_insert_with(|| NmapHost {
                ip: ip.to_string(),
                mac: None,
                hostname: None,
                vendor: None,
                os: None,
                ports: Vec::new(),
            })
            .ports
            .push(NmapPort {
                port,
                proto: proto.to_string(),
                service: None,
                product: None,
                version: None,
            });
    }
    if hosts.is_empty() && !text.contains("#masscan") {
        return Err(Error::Parse("no masscan header".into()));
    }
    Ok(hosts.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_open_lines_by_ip() {
        let out = "#masscan\n\
                   open tcp 22 10.0.0.1 1700000000\n\
                   open tcp 80 10.0.0.1 1700000000\n\
                   open udp 53 10.0.0.7 1700000001\n\
                   #end\n";
        let hosts = parse_list(out).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, "10.0.0.1");
        assert_eq!(hosts[0].ports.len(), 2);
        assert_eq!(hosts[1].ports[0].proto, "udp");
        assert!(parse_list("garbage").is_err());
    }

    #[test]
    fn port_specs_are_strict() {
        assert!(check_ports("80,443,1-1000").is_ok());
        assert!(check_ports("U:53,T:80").is_ok());
        assert!(check_ports("-p 80").is_err());
        assert!(check_ports("80;id").is_err());
    }
}
