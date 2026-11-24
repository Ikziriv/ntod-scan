#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid subnet: {0}")]
    Subnet(#[from] ipnetwork::IpNetworkError),
    #[error("probe failed")]
    Probe,
    #[error("no IPv4 local address found")]
    NoLocalAddr,
    #[error("{0}")]
    Unsupported(&'static str),
}
