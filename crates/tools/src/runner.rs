//! Where a tool actually runs — the backend is just an argv prefix, so
//! every adapter works unchanged on all three transports.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::Error;

#[derive(Debug, Clone)]
pub enum Backend {
    /// Binaries on this host's PATH (nmap has a Windows build).
    Local,
    /// A WSL distro — Kali's natural home on this box. Scanning works;
    /// raw-socket sniffing on the host NIC does not.
    Wsl { distro: Option<String> },
    /// `ssh [user@]host -- <argv>` — the only way to get monitor-mode /
    /// promiscuous capture: the tool runs where the hardware is.
    Ssh { target: String },
}

/// One external binary and whether the backend can run it.
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    /// First line of `<tool> --version`, or `None` when unreachable.
    pub version: Option<String>,
}

/// Which adapters the backend can run (add a name here per new adapter).
pub fn probe(backend: &Backend) -> Vec<ToolInfo> {
    ["nmap", "tcpdump", "masscan", "airodump-ng"]
        .iter()
        .map(|name| ToolInfo {
            name,
            version: backend
                .run(&[name, "--version"], Duration::from_secs(10), 16 << 10)
                .ok()
                .and_then(|b| {
                    String::from_utf8_lossy(&b)
                        .lines()
                        .next()
                        .map(str::to_string)
                }),
        })
        .collect()
}

impl Backend {
    /// `local` | `wsl` | `wsl:<distro>` | `ssh:<[user@]host>`
    pub fn from_spec(spec: &str) -> Result<Self, Error> {
        let (kind, arg) = match spec.split_once(':') {
            Some((k, a)) => (k, a),
            None => (spec, ""),
        };
        match kind {
            "local" if arg.is_empty() => Ok(Self::Local),
            "wsl" => {
                if arg.is_empty() {
                    Ok(Self::Wsl { distro: None })
                } else if valid_wsl_distro(arg) {
                    Ok(Self::Wsl {
                        distro: Some(arg.to_string()),
                    })
                } else {
                    Err(Error::BadBackend(spec.into()))
                }
            }
            "ssh" if valid_ssh_target(arg) => Ok(Self::Ssh {
                target: arg.to_string(),
            }),
            _ => Err(Error::BadBackend(spec.into())),
        }
    }

    /// `$NTOD_TOOLS_BACKEND` when set, else local.
    pub fn from_env() -> Self {
        std::env::var("NTOD_TOOLS_BACKEND")
            .ok()
            .and_then(|s| Self::from_spec(&s).ok())
            .unwrap_or(Self::Local)
    }

    fn command(&self, argv: &[&str]) -> Command {
        match self {
            Self::Local => {
                let mut c = Command::new(argv[0]);
                c.args(&argv[1..]);
                c
            }
            Self::Wsl { distro } => {
                let mut c = Command::new("wsl");
                if let Some(d) = distro {
                    c.args(["-d", d]);
                }
                c.arg("--").args(argv);
                c
            }
            Self::Ssh { target } => {
                let mut c = Command::new("ssh");
                c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--"]);
                c.arg(target);
                // The remote side re-splits — single-quote every arg.
                c.arg(
                    argv.iter()
                        .map(|a| sh_quote(a))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                c
            }
        }
    }

    /// Run `argv` for exactly `seconds`, then kill it and keep whatever
    /// stdout arrived — the shape capture tools (tcpdump, airodump)
    /// need, since they run until stopped.
    pub fn run_capture(
        &self,
        argv: &[&str],
        seconds: u64,
        max_out: usize,
    ) -> Result<Vec<u8>, Error> {
        self.run_capture_cancellable(argv, seconds, max_out, None)
    }

    /// Like [`run_capture`](Self::run_capture), but stops early if `cancel`
    /// becomes `true`.
    pub fn run_capture_cancellable(
        &self,
        argv: &[&str],
        seconds: u64,
        max_out: usize,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, Error> {
        let (out, _timed_out) = self.exec(argv, Duration::from_secs(seconds), max_out, cancel)?;
        Ok(out)
    }

    /// Spawn `argv` with piped stdout/stderr for streaming tools — callers
    /// drain the pipes incrementally instead of waiting for a deadline.
    /// Same argv transport as every other runner path (local/WSL/SSH).
    pub fn spawn(&self, argv: &[&str]) -> Result<std::process::Child, Error> {
        Ok(self
            .command(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
    }

    /// Run `argv`, capture stdout bounded at `max_out`, kill at `timeout`.
    /// stderr is drained to a bounded buffer and surfaces on failure.
    pub fn run(&self, argv: &[&str], timeout: Duration, max_out: usize) -> Result<Vec<u8>, Error> {
        let (out, timed_out) = self.exec(argv, timeout, max_out, None)?;
        if timed_out {
            return Err(Error::Timeout);
        }
        Ok(out)
    }

    /// `(stdout, hit_deadline)` — deadline kill is reported, not raised;
    /// `run` turns it into `Timeout`, `run_capture` into the payload.
    fn exec(
        &self,
        argv: &[&str],
        timeout: Duration,
        max_out: usize,
        cancel: Option<&AtomicBool>,
    ) -> Result<(Vec<u8>, bool), Error> {
        let mut child = self
            .command(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        // Readers must drain in parallel or a full pipe deadlocks the poll.
        let out_h = thread::spawn(move || read_cap(stdout, max_out));
        let err_h = thread::spawn(move || read_cap(stderr, 64 << 10));

        let deadline = Instant::now() + timeout;
        let (status, timed_out) = loop {
            if let Some(s) = child.try_wait()? {
                break (s, false);
            }
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) || Instant::now() >= deadline {
                let _ = child.kill();
                break (child.wait()?, true);
            }
            thread::sleep(Duration::from_millis(20));
        };
        let out = out_h.join().map_err(|_| Error::Failed("reader".into()))??;
        let err = err_h.join().map_err(|_| Error::Failed("reader".into()))??;
        if !timed_out && !status.success() {
            return Err(Error::Failed(format!(
                "{} exited {status}: {}",
                argv[0],
                String::from_utf8_lossy(&err).trim()
            )));
        }
        Ok((out, timed_out))
    }
}

fn valid_wsl_distro(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_ssh_target(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    let (user, host) = match s.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, s),
    };
    if let Some(u) = user
        && (u.is_empty()
            || u.starts_with('-')
            || !u
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    {
        return false;
    }
    !host.is_empty()
        && !host.starts_with('-')
        && !host.contains('@')
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
}

pub(crate) fn read_cap(mut r: impl Read, max: usize) -> std::io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.by_ref().take(max as u64 + 1).read_to_end(&mut v)?;
    v.truncate(max);
    Ok(v)
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_specs() {
        assert!(matches!(
            Backend::from_spec("local").unwrap(),
            Backend::Local
        ));
        match Backend::from_spec("wsl:kali-linux").unwrap() {
            Backend::Wsl { distro } => assert_eq!(distro.as_deref(), Some("kali-linux")),
            _ => panic!("wsl expected"),
        }
        match Backend::from_spec("ssh:kali@192.168.1.50").unwrap() {
            Backend::Ssh { target } => assert_eq!(target, "kali@192.168.1.50"),
            _ => panic!("ssh expected"),
        }
        assert!(Backend::from_spec("ssh").is_err());
        assert!(Backend::from_spec("telnet:x").is_err());
        assert!(Backend::from_spec("ssh:-oProxyCommand=id").is_err());
        assert!(Backend::from_spec("ssh:user@-host").is_err());
        assert!(Backend::from_spec("ssh:host with spaces").is_err());
        assert!(Backend::from_spec("wsl:-e").is_err());
        assert!(Backend::from_spec("wsl:kali;id").is_err());
    }

    #[test]
    fn ssh_argv_is_quoted_as_one_remote_string() {
        let b = Backend::Ssh {
            target: "kali@lab".into(),
        };
        let c = b.command(&["tcpdump", "-w", "-", "host 1.2.3.4 and port 53"]);
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let remote = args.last().unwrap();
        // One remote argument, each argv element single-quoted.
        assert_eq!(remote, "'tcpdump' '-w' '-' 'host 1.2.3.4 and port 53'");
    }

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }
}
