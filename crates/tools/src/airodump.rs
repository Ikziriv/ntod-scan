//! airodump-ng — monitor-mode WiFi survey. Unlike tcpdump it can't
//! stream to stdout: it writes `<prefix>-*.csv` on the backend. So the
//! capture runs to a remote temp dir, gets killed at deadline, and the
//! CSV is fetched (and the dir removed) by a fixed `sh -c` script —
//! every variable in it is generated or validated here.
//!
//! The iface must already be in monitor mode (`airmon-ng start wlan0`)
//! — that's a backend-admin step, not something this runs for you.

use std::time::Duration;

use serde::Serialize;

use crate::error::Error;
use crate::runner::Backend;
use crate::sniff::check_iface;

const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CSV: usize = 8 << 20;

/// An AP airodump heard — the same row the WiFi survey shows, but from
/// a real monitor-mode adapter (sees hidden/undirected networks too).
#[derive(Debug, Clone, Serialize)]
pub struct AiroAp {
    pub bssid: String,
    pub essid: String,
    pub channel: Option<u8>,
    pub privacy: Option<String>,
    pub power: Option<i32>,
}

/// Run airodump for `seconds` on `iface` (wlan0mon), fetch the CSV back.
pub fn survey(backend: &Backend, iface: &str, seconds: u64) -> Result<Vec<AiroAp>, Error> {
    check_iface(iface)?;
    let raw_dir = backend.run(
        &["mktemp", "-d", "/tmp/ntod-airo.XXXXXX"],
        FETCH_TIMEOUT,
        4 << 10,
    )?;
    let dir = String::from_utf8_lossy(&raw_dir).trim().to_string();
    if !dir.starts_with("/tmp/ntod-airo.")
        || !dir
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
    {
        return Err(Error::Failed("unexpected mktemp path".into()));
    }
    let prefix = format!("{dir}/scan");
    let cap_res = backend.run_capture(
        &[
            "airodump-ng",
            "--output-format",
            "csv",
            "--write-interval",
            "1",
            "-w",
            &prefix,
            iface,
        ],
        seconds,
        4 << 20, // console UI on stdout — discarded, just drained
    );
    let out = backend.run(
        &["sh", "-c", &format!("cat '{dir}'/*.csv; rm -rf '{dir}'")],
        FETCH_TIMEOUT,
        MAX_CSV,
    );
    cap_res?;
    parse_csv(&String::from_utf8_lossy(&out?))
}

/// First CSV block = APs; a blank line ends it (stations follow, skipped).
/// Columns: BSSID, first, last, channel, Speed, Privacy, Cipher, Auth,
/// Power, #beacons, #IV, LAN IP, ID-len, ESSID, Key.
fn parse_csv(text: &str) -> Result<Vec<AiroAp>, Error> {
    let mut aps = Vec::new();
    let mut seen_header = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            break; // station block — done
        }
        if line.starts_with("BSSID") {
            seen_header = true;
            continue;
        }
        if !seen_header {
            continue;
        }
        let f: Vec<&str> = line.split(',').map(str::trim).collect();
        if f.len() < 14 {
            continue;
        }
        // ESSID is unquoted and may contain commas; drop the trailing empty Key column.
        let essid_end = if f.len() >= 15 && f.last().is_some_and(|s| s.is_empty()) {
            f.len() - 1
        } else {
            f.len()
        };
        aps.push(AiroAp {
            bssid: f[0].to_string(),
            channel: f[3].parse().ok(),
            privacy: Some(f[5]).filter(|s| !s.is_empty()).map(str::to_string),
            power: f[8].parse().ok(),
            essid: f[13..essid_end].join(",").trim().to_string(),
        });
    }
    if aps.is_empty() && !seen_header {
        return Err(Error::Parse("no airodump CSV header".into()));
    }
    Ok(aps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ap_block_stops_at_stations() {
        let csv = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n\
                   AA:BB:CC:11:22:33, 2024-01-01 10:00:00, 2024-01-01 10:00:15, 6, -1, WPA2, CCMP, PSK, -71, 120, 44, 0.0.0.0, 7, HomeNet, \n\
                   DD:EE:FF:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:00:15, 36, -1, OPN, , , -60, 30, 0, 0.0.0.0, 4, Cafe_WiFi, \n\
                   \n\
                   Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n\
                   00:11:22:33:44:55, 2024-01-01 10:00:00, 2024-01-01 10:00:15, -50, 12, AA:BB:CC:11:22:33, HomeNet\n";
        let aps = parse_csv(csv).unwrap();
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].bssid, "AA:BB:CC:11:22:33");
        assert_eq!(aps[0].essid, "HomeNet");
        assert_eq!(aps[0].channel, Some(6));
        assert_eq!(aps[0].power, Some(-71));
        assert_eq!(aps[0].privacy.as_deref(), Some("WPA2"));
        assert!(parse_csv("junk").is_err());
    }
}
