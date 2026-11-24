//! ntod-scan core engine: LAN discovery, packet capture, ARP control.
//!
//! Pure library — no UI, no HTTP. Shells (cli, api, ffi) build on this.

pub mod arp;
pub mod discover;
pub mod error;
pub mod model;
pub mod names;
pub mod oui;
mod oui_db;
pub mod scan;
pub mod wifi;

pub use error::Error;
pub use model::{Filter, Host, Proto, Service};
pub use scan::{local_subnet, scan, scan_stream};
