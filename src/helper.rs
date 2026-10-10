//! Private, bounded stdio protocol between the unprivileged UI and collector.

use std::{
    fs,
    io::{BufRead, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::Snapshot;

pub const HELPER_PATH: &str = "/usr/local/libexec/nwtop-collector";
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_REQUEST: usize = 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub interface: Option<String>,
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            bail!("collector protocol mismatch; rerun capture setup after updating nwtop");
        }
        if let Some(name) = &self.interface
            && (name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || name
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\0'))
        {
            bail!("invalid interface name");
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Snapshot {
        version: u32,
        snapshot: Box<Snapshot>,
    },
    Error {
        version: u32,
        message: String,
    },
}

/// Consume at most max+1 bytes, including the required newline terminator.
pub fn read_frame(reader: &mut impl BufRead, max: usize) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let read = reader
        .take((max + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    if read > max || bytes.last() != Some(&b'\n') {
        bail!("collector protocol frame exceeds limit or is incomplete");
    }
    bytes.pop();
    Ok(Some(bytes))
}

pub fn write_reply(writer: &mut impl Write, reply: &Reply) -> Result<()> {
    let bytes = serde_json::to_vec(reply)?;
    if bytes.len() >= MAX_RESPONSE {
        bail!("collector response exceeds limit");
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Only the fixed administrator-installed path is eligible. No environment or
/// PATH override can select an executable to receive monitoring privileges.
pub fn trusted_helper() -> Result<bool> {
    let path = Path::new(HELPER_PATH);
    if !path.try_exists()? {
        return Ok(false);
    }
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            bail!(
                "capture helper path must be root-owned and not writable by other users: {}",
                component.display()
            );
        }
        if component == path && !metadata.is_file() {
            bail!("capture helper is not a regular file");
        }
    }
    Ok(true)
}

pub struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl Client {
    pub fn start() -> Result<Self> {
        if !trusted_helper()? {
            bail!("capture helper is not installed");
        }
        let mut child = Command::new(HELPER_PATH)
            .arg("--stdio")
            // Collector configuration never comes from the user's environment.
            .env_clear()
            .env("LANG", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context(
                "starting capture helper; rerun scripts/setup-capture.sh if access was revoked",
            )?;
        let input = child.stdin.take().context("opening helper input")?;
        let output = child.stdout.take().context("opening helper output")?;
        Ok(Self {
            child,
            input: Some(input),
            output,
        })
    }

    pub fn sample(
        &mut self,
        interface: Option<&str>,
        interrupted: impl Fn() -> bool,
    ) -> Result<Snapshot> {
        let request = Request {
            version: PROTOCOL_VERSION,
            interface: interface.map(str::to_owned),
        };
        request.validate()?;
        let input = self.input.as_mut().context("collector input closed")?;
        serde_json::to_writer(&mut *input, &request)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let frame = self.read_response(interrupted)?;
        let reply: Reply =
            serde_json::from_slice(&frame).context("decoding capture helper response")?;
        match reply {
            Reply::Snapshot { version, snapshot } if version == PROTOCOL_VERSION => Ok(*snapshot),
            Reply::Error { version, message } if version == PROTOCOL_VERSION => bail!("{message}"),
            _ => bail!("capture helper protocol mismatch; rerun scripts/setup-capture.sh"),
        }
    }

    fn read_response(&mut self, interrupted: impl Fn() -> bool) -> Result<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut bytes = Vec::new();
        loop {
            if interrupted() {
                bail!("capture helper interrupted");
            }
            if Instant::now() >= deadline {
                bail!("capture helper timed out");
            }
            let mut descriptor = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // A single reader owns this pipe. After readiness, read returns the
            // available bytes without waiting for a complete frame.
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                continue;
            }
            let mut chunk = [0u8; 8192];
            let count = self.output.read(&mut chunk)?;
            if count == 0 {
                bail!("capture helper exited; rerun scripts/setup-capture.sh after updating");
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > MAX_RESPONSE {
                bail!("capture helper response exceeds limit");
            }
            if let Some(end) = chunk[..count].iter().position(|&byte| byte == b'\n') {
                if end + 1 != count {
                    bail!("unexpected data after collector response");
                }
                bytes.pop();
                return Ok(bytes);
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        // This is our exclusively owned, headless child. Never leave a collector
        // running when its UI goes away, including on malformed responses.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn protocol_bounds_and_interface_validation() {
        assert!(read_frame(&mut Cursor::new(b"12345\n"), 5).is_err());
        assert!(read_frame(&mut Cursor::new(b"{}"), 10).is_err());
        assert_eq!(
            read_frame(&mut Cursor::new(b"{}\n"), 3).unwrap(),
            Some(b"{}".to_vec())
        );
        assert!(read_frame(&mut Cursor::new(b""), 3).unwrap().is_none());
        for name in ["", "../net", "eth0\nescape", "abcdefghijklmnop"] {
            assert!(
                Request {
                    version: 1,
                    interface: Some(name.into())
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Request {
                version: 1,
                interface: Some("enp112s0".into())
            }
            .validate()
            .is_ok()
        );
        assert!(
            Request {
                version: 2,
                interface: None
            }
            .validate()
            .is_err()
        );
    }
}
