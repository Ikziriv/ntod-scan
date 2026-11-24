use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// A live host discovered on the LAN.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Host {
    pub ip: Ipv4Addr,
    /// MAC address resolved from the OS ARP cache, if present.
    pub mac: Option<String>,
    /// Reverse-DNS / mDNS hostname, if resolvable.
    pub hostname: Option<String>,
    /// NIC vendor guessed from the MAC OUI prefix.
    pub vendor: Option<String>,
    /// Open TCP ports from the common-ports probe.
    pub open_ports: Vec<u16>,
    /// OS guess from service fingerprinting — deep scans only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Service identities on open ports — deep scans only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

/// Service identity fingerprinted on an open port.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Service {
    pub port: u16,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            os: None,
            services: None,
        }
    }
}

/// Transport protocol of a packet/flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Proto {
    pub fn from_u8(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            n => Self::Other(n),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Other(n) => n,
        }
    }
}

/// Server-side packet filter — compiled to matcher in capture,
/// emitted by the AI NL→filter path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    pub proto: Option<Proto>,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub port: Option<u16>,
}
