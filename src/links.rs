//! Kernel-reported link kinds used to identify namespace boundary observations.
//! Names, sysfs layout and interface numbering are not evidence of a veth link.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const MAX_LINKS: usize = 4096;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;
const MAX_DATAGRAM: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_millis(250);

/// One read-only RTM_GETLINK dump in the caller's network namespace. An error
/// must not be interpreted as proof that no veth interfaces exist.
pub(super) fn veth_indexes() -> Result<HashSet<u32>> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("opening link-kind socket");
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            raw,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("binding link-kind socket");
    }
    let mut request = [0_u8; 32];
    request[..4].copy_from_slice(&32_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18_u16.to_ne_bytes()); // RTM_GETLINK
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = libc::AF_UNSPEC as u8;
    let sent = unsafe {
        libc::sendto(
            raw,
            request.as_ptr().cast(),
            request.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent != request.len() as isize {
        return Err(std::io::Error::last_os_error()).context("requesting link kinds");
    }
    let deadline = Instant::now() + DEADLINE;
    let mut state = Dump::default();
    let mut buffer = vec![0; MAX_DATAGRAM];
    let mut received = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("link-kind dump timed out");
        }
        let mut poll = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let status = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if status < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("waiting for link kinds");
        }
        if status == 0 {
            continue;
        }
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let length = unsafe { libc::recvmsg(raw, &mut message, libc::MSG_DONTWAIT) };
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error).context("receiving link kinds");
        }
        if length == 0 || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            bail!("truncated link-kind datagram");
        }
        if message.msg_namelen as usize != std::mem::size_of_val(&source)
            || source.nl_family != libc::AF_NETLINK as u16
            || source.nl_pid != 0
        {
            bail!("link-kind datagram was not sent by the kernel");
        }
        received += length as usize;
        if received > MAX_DUMP_BYTES {
            bail!("link-kind dump byte limit reached");
        }
        if state.parse(&buffer[..length as usize])? {
            return Ok(state.veth);
        }
    }
}

#[derive(Default)]
struct Dump {
    veth: HashSet<u32>,
    links: usize,
}

impl Dump {
    fn parse(&mut self, mut bytes: &[u8]) -> Result<bool> {
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                bail!("truncated link-kind header");
            }
            let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
            let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
            let sequence = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
            if length < 16 || length > bytes.len() || sequence != 1 {
                bail!("invalid link-kind message");
            }
            if flags & 0x10 != 0 {
                bail!("link-kind dump interrupted");
            }
            let body = &bytes[16..length];
            match kind {
                1 => {}
                2 => {
                    if body.len() < 4 {
                        bail!("truncated link-kind error");
                    }
                    let error = i32::from_ne_bytes(body[..4].try_into().unwrap());
                    if error != 0 {
                        bail!(
                            "link-kind netlink error {}",
                            std::io::Error::from_raw_os_error(error.saturating_neg())
                        );
                    }
                }
                3 => {
                    if !body.is_empty()
                        && (body.len() < 4
                            || i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0)
                    {
                        bail!("link-kind dump failed");
                    }
                    return Ok(true);
                }
                4 => bail!("link-kind buffer overrun"),
                16 => {
                    self.links += 1;
                    if self.links > MAX_LINKS {
                        bail!("link-kind count limit reached");
                    }
                    if let Some(index) = parse_link(body)? {
                        self.veth.insert(index);
                    }
                }
                _ => {}
            }
            let aligned = (length + 3) & !3;
            if aligned > bytes.len() {
                bail!("truncated link-kind padding");
            }
            bytes = &bytes[aligned..];
        }
        Ok(false)
    }
}

fn find_attribute(mut bytes: &[u8], wanted: u16) -> Result<Option<&[u8]>> {
    let mut found = None;
    let mut count = 0;
    while !bytes.is_empty() {
        count += 1;
        if bytes.len() < 4 || count > 128 {
            bail!("invalid link-kind attributes");
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if length < 4 || length > bytes.len() {
            bail!("invalid link-kind attribute length");
        }
        if kind == wanted {
            if found.is_some() {
                bail!("duplicate link-kind attribute");
            }
            found = Some(&bytes[4..length]);
        }
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            bail!("truncated link-kind attribute padding");
        }
        bytes = &bytes[aligned..];
    }
    Ok(found)
}

fn parse_link(body: &[u8]) -> Result<Option<u32>> {
    if body.len() < 16 {
        bail!("truncated ifinfomsg");
    }
    let index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
    if index <= 0 {
        bail!("invalid link index");
    }
    let Some(info) = find_attribute(&body[16..], 18)? else {
        return Ok(None);
    }; // IFLA_LINKINFO
    let Some(kind) = find_attribute(info, 1)? else {
        return Ok(None);
    }; // IFLA_INFO_KIND
    Ok((kind == b"veth\0").then_some(index as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn link(index: i32, kind: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[4..8].copy_from_slice(&index.to_ne_bytes());
        bytes.extend(attr(3, b"veth-misleading-name\0"));
        bytes.extend(attr(0x8012, &attr(1, kind)));
        bytes
    }

    fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&1_u32.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    #[test]
    fn link_kind_comes_from_nested_kernel_attributes_not_interface_name() {
        assert_eq!(parse_link(&link(42, b"veth\0")).unwrap(), Some(42));
        for kind in [b"bridge\0".as_slice(), b"dummy\0", b"vethX\0", b"veth"] {
            assert_eq!(parse_link(&link(42, kind)).unwrap(), None);
        }
        assert!(parse_link(&link(0, b"veth\0")).is_err());
        assert!(parse_link(&link(-1, b"veth\0")).is_err());
        let mut duplicate = link(42, b"veth\0");
        duplicate.extend(attr(18, &attr(1, b"bridge\0")));
        assert!(parse_link(&duplicate).is_err());
    }

    #[test]
    fn multipart_dump_rejects_partial_interrupted_or_wrong_sequence() {
        let row = message(16, 2, &link(42, b"veth\0"));
        let mut dump = Dump::default();
        assert!(!dump.parse(&row).unwrap());
        assert_eq!(dump.veth, HashSet::from([42]));
        assert!(dump.parse(&message(3, 2, &0_i32.to_ne_bytes())).unwrap());
        for length in 1..row.len() {
            assert!(Dump::default().parse(&row[..length]).is_err());
        }
        assert!(Dump::default().parse(&message(3, 0x10, &[])).is_err());
        let mut wrong_sequence = row.clone();
        wrong_sequence[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(Dump::default().parse(&wrong_sequence).is_err());
        let mut limited = Dump {
            links: MAX_LINKS,
            ..Dump::default()
        };
        assert!(limited.parse(&row).is_err());
    }

    #[test]
    fn live_link_kind_lookup_is_read_only_and_bounded() {
        let started = Instant::now();
        // A sandbox may reject netlink; that is a visible Result, never a
        // successful empty set fabricated from an incomplete dump.
        let result = veth_indexes();
        assert!(started.elapsed() < Duration::from_secs(2));
        if let Ok(indexes) = result {
            assert!(indexes.iter().all(|index| *index != 0));
        }
    }
}
