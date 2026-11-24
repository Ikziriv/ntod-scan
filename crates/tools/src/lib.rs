//! External-tool adapters (nmap, tcpdump — the Kali side).
//!
//! Every tool is spawned as a bounded child process: argv only (never a
//! shell string), a kill-on-deadline watchdog, and capped stdout. Each
//! adapter parses the tool's machine-readable output — XML, never the
//! human tables. `Backend` makes the same argv work locally, inside
//! WSL, or on a remote box over SSH.
//!
//! Sniffing remote interfaces is the whole point of the SSH backend:
//! `tcpdump -w -` streams pcap to stdout, so a Kali box's monitor-mode
//! adapter lands in the same `ntod-analysis` engine as a local capture.

pub mod airodump;
mod error;
pub mod masscan;
pub mod nmap;
mod runner;
pub mod sniff;

pub use error::Error;
pub use runner::{Backend, ToolInfo, probe};
