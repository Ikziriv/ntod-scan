//! Kismet-lite: nearby WiFi network inventory via OS scan results.
//!
//! Not monitor-mode sniffing — that needs Linux + a capable driver.
//! Windows: `netsh wlan show networks mode=bssid` (no admin).
//! Linux:   `nmcli -t dev wifi`.

use std::process::Command;

use serde::Serialize;

use crate::error::Error;

#[derive(Debug, Clone, Serialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: Option<String>,
    /// Signal strength 0-100 where the OS reports it.
    pub signal: Option<u8>,
    pub channel: Option<u8>,
}

/// Nearby networks from the last OS WiFi scan.
pub fn networks() -> Result<Vec<WifiNetwork>, Error> {
    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["wlan", "show", "networks", "mode=bssid"])
            .output()?;
        Ok(parse_netsh(&String::from_utf8_lossy(&out.stdout)))
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("nmcli")
            .args(["-t", "-f", "SSID,BSSID,SIGNAL,CHAN", "dev", "wifi"])
            .output()?;
        if !out.status.success() {
            return Err(Error::Unsupported("nmcli scan failed"));
        }
        Ok(parse_nmcli(&String::from_utf8_lossy(&out.stdout)))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(Error::Unsupported("wifi scan not implemented on this OS"))
    }
}

/// Parse `netsh wlan show networks mode=bssid` output.
fn parse_netsh(text: &str) -> Vec<WifiNetwork> {
    let mut nets = Vec::new();
    let mut cur: Option<WifiNetwork> = None;
    let mut in_first_bssid = false;
    for line in text.lines() {
        let t = line.trim();
        let Some((key, val)) = t.split_once(':') else {
            continue;
        };
        let (key, val) = (key.trim(), val.trim());
        if key.starts_with("SSID") && !key.starts_with("BSSID") {
            if let Some(n) = cur.take() {
                nets.push(n);
            }
            cur = Some(WifiNetwork {
                ssid: val.to_string(),
                bssid: None,
                signal: None,
                channel: None,
            });
            in_first_bssid = false;
        } else if let Some(n) = cur.as_mut() {
            // BSSID blocks repeat (BSSID 1, 2, ...) — only the first counts.
            if key.starts_with("BSSID") {
                in_first_bssid = key == "BSSID 1";
                if in_first_bssid {
                    n.bssid = Some(val.to_string());
                }
                continue;
            }
            if in_first_bssid {
                match key {
                    "Signal" => n.signal = val.trim_end_matches('%').parse().ok(),
                    "Channel" => n.channel = val.parse().ok(),
                    _ => {}
                }
            }
        }
    }
    if let Some(n) = cur {
        nets.push(n);
    }
    nets
}

/// Parse `nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi` output.
/// `-t` escapes literal `:` (in SSID and BSSID) as `\:`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_nmcli(text: &str) -> Vec<WifiNetwork> {
    text.lines()
        .filter_map(|line| {
            let fields = split_unescaped_colons(line);
            if fields.len() < 4 {
                return None;
            }
            Some(WifiNetwork {
                ssid: fields[0].clone(),
                bssid: (!fields[1].is_empty()).then(|| fields[1].clone()),
                signal: fields[2].parse().ok(),
                channel: fields[3].parse().ok(),
            })
        })
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn split_unescaped_colons(line: &str) -> Vec<String> {
    let mut fields = Vec::with_capacity(4);
    let mut cur = String::new();
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ':' {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    fields.push(cur);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netsh_parses_ssid_bssid_signal_channel() {
        let out = "\
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 82%
         Channel            : 6
    BSSID 2                 : 11:22:33:44:55:66
         Signal             : 45%

SSID 2 : Cafe_Guest
    BSSID 1                 : 66:77:88:99:00:aa
         Signal             : 31%
         Channel            : 11
";
        let nets = parse_netsh(out);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].ssid, "HomeNet");
        assert_eq!(nets[0].bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(nets[0].signal, Some(82));
        assert_eq!(nets[0].channel, Some(6));
        assert_eq!(nets[1].ssid, "Cafe_Guest");
        assert_eq!(nets[1].signal, Some(31));
    }

    #[test]
    fn nmcli_handles_escaped_colons_in_ssid_and_bssid() {
        let out = r"My\:Home\:WiFi:AA\:BB\:CC\:DD\:EE\:FF:78:11";
        let nets = parse_nmcli(out);
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].ssid, "My:Home:WiFi");
        assert_eq!(nets[0].bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(nets[0].signal, Some(78));
        assert_eq!(nets[0].channel, Some(11));
    }
}
