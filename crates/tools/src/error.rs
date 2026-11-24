#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tool timed out")]
    Timeout,
    #[error("{0}")]
    Failed(String),
    #[error("invalid backend '{0}' (want local | wsl[:distro] | ssh:[user@]host)")]
    BadBackend(String),
    #[error("invalid target '{0}'")]
    BadTarget(String),
    #[error("invalid interface '{0}'")]
    BadIface(String),
    #[error("tool output not understood: {0}")]
    Parse(String),
}
