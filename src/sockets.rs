//! Linux socket tables and their visible inode owners. Socket queues are not rates.

use super::packet::Protocol;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const MAX_SOCKETS: usize = 32_768;
const MAX_PROCESSES: usize = 32_768;
const MAX_FD_LINKS: usize = 262_144;
const RETAIN_CLOSED: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Owner {
    pub identity: ProcessIdentity,
    pub user: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct SocketKey {
    pub inode: u64,
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Debug)]
pub(super) struct Socket {
    pub key: SocketKey,
    pub state: String,
    pub uid: u32,
    pub owners: Vec<Owner>,
    pub observed: Instant,
    pub current: bool,
    // /proc/net/{tcp,udp}6 omits this per-socket option. Unknown is deliberately
    // not treated as dual stack: an IPv6-only listener cannot own IPv4 traffic.
    pub ipv6_only: Option<bool>,
}

impl Socket {
    pub(super) fn owner(&self) -> Option<&Owner> {
        if self.owners.len() == 1 {
            self.owners.first()
        } else {
            None
        }
    }
}

pub(super) struct Inventory {
    pub sockets: Vec<Socket>,
    pub users: HashMap<u32, String>,
    pub restricted: bool,
    pub limited: bool,
    index: HashMap<(Protocol, u16), Vec<usize>>,
    owners: HashMap<u64, Vec<Owner>>,
    owner_keys: HashMap<u64, SocketKey>,
    last_scan: Option<Instant>,
    last_owner_scan: Option<Instant>,
}

impl Inventory {
    pub(super) fn new() -> Self {
        let users = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                Some((
                    fields.get(2)?.parse().ok()?,
                    sanitize_label(fields.first()?),
                ))
            })
            .collect();
        Self {
            sockets: Vec::new(),
            users,
            restricted: false,
            limited: false,
            index: HashMap::new(),
            owners: HashMap::new(),
            owner_keys: HashMap::new(),
            last_scan: None,
            last_owner_scan: None,
        }
    }

    pub(super) fn refresh(&mut self) {
        let now = Instant::now();
        if self
            .last_scan
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(500))
        {
            return;
        }
        let mut current = Vec::new();
        for (path, protocol, ipv6) in [
            ("/proc/net/tcp", Protocol::Tcp, false),
            ("/proc/net/tcp6", Protocol::Tcp, true),
            ("/proc/net/udp", Protocol::Udp, false),
            ("/proc/net/udp6", Protocol::Udp, true),
        ] {
            match fs::read_to_string(path) {
                Ok(contents) => {
                    for line in contents.lines().skip(1) {
                        if current.len() >= MAX_SOCKETS {
                            self.limited = true;
                            break;
                        }
                        if let Some(socket) = parse_socket(line, protocol, ipv6, now) {
                            current.push(socket);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    self.restricted = true
                }
                Err(_) => {}
            }
        }
        let live_inodes: HashSet<_> = current
            .iter()
            .map(|socket| socket.key.inode)
            .filter(|inode| *inode != 0)
            .collect();
        if self
            .last_owner_scan
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1))
        {
            let (owners, restricted, limited) = scan_owners(&live_inodes, &self.users);
            self.owners = owners;
            self.owner_keys = current
                .iter()
                .map(|socket| (socket.key.inode, socket.key.clone()))
                .collect();
            self.restricted |= restricted;
            self.limited |= limited;
            self.last_owner_scan = Some(now);
        }
        for socket in &mut current {
            // An inode reused for a different endpoint must not inherit stale
            // cached ownership before the next bounded descriptor scan.
            if self.owner_keys.get(&socket.key.inode) == Some(&socket.key) {
                socket.owners = self
                    .owners
                    .get(&socket.key.inode)
                    .cloned()
                    .unwrap_or_default();
            }
        }
        let ipv6_modes = ipv6_socket_modes(&current);
        for socket in &mut current {
            socket.ipv6_only = ipv6_modes.get(&socket.key).copied();
        }
        let live_keys: HashSet<_> = current.iter().map(|socket| socket.key.clone()).collect();
        for mut socket in self.sockets.drain(..) {
            if current.len() >= MAX_SOCKETS {
                self.limited = true;
                break;
            }
            if !live_keys.contains(&socket.key)
                && now.duration_since(socket.observed) <= RETAIN_CLOSED
            {
                socket.current = false;
                current.push(socket);
            }
        }
        self.sockets = current;
        self.index.clear();
        for (index, socket) in self.sockets.iter().enumerate() {
            self.index
                .entry((socket.key.protocol, socket.key.local.port()))
                .or_default()
                .push(index);
        }
        self.last_scan = Some(now);
    }

    /// Exact connected sockets outrank listeners. Tied inodes or shared owners
    /// remain unassigned instead of choosing an arbitrary PID.
    pub(super) fn resolve(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&Socket> {
        let candidates = self.index.get(&(protocol, local.port()))?;
        let mut best = None;
        let mut best_score = 0;
        let mut ambiguous = false;
        let mut matching_incarnations = 0;
        let mut retained_match = false;
        for &index in candidates {
            let socket = &self.sockets[index];
            let Some(score) = match_score(socket, local, remote) else {
                continue;
            };
            matching_incarnations += 1;
            retained_match |= !socket.current;
            if score > best_score {
                best = Some(socket);
                best_score = score;
                ambiguous = false;
            } else if score == best_score
                && best.is_some_and(|other: &Socket| other.key != socket.key)
            {
                ambiguous = true;
            }
        }
        // A batch can straddle a close/rebind. Prefer neither incarnation when
        // both match, even after both have closed: a retained connected socket
        // must not steal a later wildcard socket's packets, or vice versa.
        if ambiguous || (retained_match && matching_incarnations > 1) {
            None
        } else {
            best.filter(|socket| socket.owner().is_some())
        }
    }

    pub(super) fn user(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}

fn match_score(socket: &Socket, local: SocketAddr, remote: SocketAddr) -> Option<u8> {
    if socket.key.local.port() != local.port() {
        return None;
    }
    let local_ip = canonical_ip(socket.key.local.ip());
    let packet_local = canonical_ip(local.ip());
    let local_score = if local_ip == packet_local {
        2
    } else if local_ip.is_unspecified()
        && (local_ip.is_ipv4() == packet_local.is_ipv4()
            || (local_ip.is_ipv6() && socket.ipv6_only == Some(false)))
    {
        1
    } else {
        return None;
    };
    let remote_ip = canonical_ip(socket.key.remote.ip());
    let packet_remote = canonical_ip(remote.ip());
    if remote_ip.is_unspecified() && socket.key.remote.port() == 0 {
        Some(local_score)
    } else if remote_ip == packet_remote && socket.key.remote.port() == remote.port() {
        Some(local_score + 4)
    } else {
        None
    }
}

/// SOCK_DIAG exposes IPV6_V6ONLY without opening another process's descriptor.
/// Only wildcard IPv6 sockets need it; a denied/unsupported query leaves IPv4
/// attribution unknown. Bound both elapsed time and retained response data.
fn ipv6_socket_modes(sockets: &[Socket]) -> HashMap<SocketKey, bool> {
    let wanted: HashSet<_> = sockets
        .iter()
        .filter(|socket| socket.key.local.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .map(|socket| socket.key.clone())
        .collect();
    let mut modes = HashMap::new();
    let deadline = Instant::now() + Duration::from_millis(50);
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        if wanted.iter().any(|key| key.protocol == protocol) {
            read_ipv6_modes(protocol, &wanted, &mut modes, deadline);
        }
    }
    modes
}

fn read_ipv6_modes(
    protocol: Protocol,
    wanted: &HashSet<SocketKey>,
    modes: &mut HashMap<SocketKey, bool>,
    deadline: Instant,
) {
    // The request/response layouts are Linux UAPI inet_diag_req_v2 and
    // inet_diag_msg. Integer headers are native endian; addresses/ports are not.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return;
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = [0_u8; 72];
    request[0..4].copy_from_slice(&72_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = libc::AF_INET6 as u8;
    request[17] = if protocol == Protocol::Tcp { 6 } else { 17 };
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // All states.
    request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            descriptor.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    };
    if sent != request.len() as isize {
        return;
    }
    let mut buffer = [0_u8; 65_536];
    while Instant::now() < deadline {
        let mut ready = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .max(1) as i32;
        if unsafe { libc::poll(&mut ready, 1, timeout) } <= 0 {
            return;
        }
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
        let length = unsafe {
            libc::recvfrom(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut sender_len,
            )
        };
        if length <= 0 || length as usize > buffer.len() || sender.nl_pid != 0 {
            return;
        }
        let mut messages = &buffer[..length as usize];
        while messages.len() >= 16 {
            let length = u32::from_ne_bytes(messages[..4].try_into().unwrap()) as usize;
            if length < 16 || length > messages.len() {
                return;
            }
            let kind = u16::from_ne_bytes(messages[4..6].try_into().unwrap());
            let sequence = u32::from_ne_bytes(messages[8..12].try_into().unwrap());
            if sequence != 1 || matches!(kind, 2 | 3) {
                return; // NLMSG_ERROR / NLMSG_DONE
            }
            if kind == 20
                && let Some((key, only)) = parse_ipv6_mode(&messages[16..length], protocol)
                && wanted.contains(&key)
            {
                modes.insert(key, only);
            }
            let aligned = (length + 3) & !3;
            messages = messages.get(aligned..).unwrap_or_default();
        }
    }
}

fn parse_ipv6_mode(message: &[u8], protocol: Protocol) -> Option<(SocketKey, bool)> {
    if message.len() < 72 || message[0] != libc::AF_INET6 as u8 {
        return None;
    }
    let key = SocketKey {
        protocol,
        inode: u32::from_ne_bytes(message[68..72].try_into().ok()?) as u64,
        local: SocketAddr::new(
            canonical_ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&message[8..24]).ok()?,
            ))),
            u16::from_be_bytes(message[4..6].try_into().ok()?),
        ),
        remote: SocketAddr::new(
            canonical_ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&message[24..40]).ok()?,
            ))),
            u16::from_be_bytes(message[6..8].try_into().ok()?),
        ),
    };
    let mut attributes = &message[72..];
    while attributes.len() >= 4 {
        let length = u16::from_ne_bytes(attributes[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().ok()?);
        if length < 4 || length > attributes.len() {
            return None;
        }
        if kind == 11 && length == 5 {
            // INET_DIAG_SKV6ONLY
            return Some((key, attributes[4] != 0));
        }
        attributes = attributes.get(((length + 3) & !3)..)?;
    }
    None
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn parse_address(value: &str, ipv6: bool) -> Option<SocketAddr> {
    let (hex_ip, hex_port) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    let ip = if ipv6 {
        if hex_ip.len() != 32 {
            return None;
        }
        let mut bytes = [0; 16];
        for (index, chunk) in hex_ip.as_bytes().as_chunks::<8>().0.iter().enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        canonical_ip(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        let word = u32::from_str_radix(hex_ip, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

fn parse_socket(line: &str, protocol: Protocol, ipv6: bool, now: Instant) -> Option<Socket> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    let state = u8::from_str_radix(fields.get(3)?, 16).ok()?;
    Some(Socket {
        key: SocketKey {
            inode: fields.get(9)?.parse().ok()?,
            protocol,
            local: parse_address(fields.get(1)?, ipv6)?,
            remote: parse_address(fields.get(2)?, ipv6)?,
        },
        uid: fields.get(7)?.parse().ok()?,
        state: state_label(state, protocol).to_string(),
        owners: Vec::new(),
        observed: now,
        current: true,
        ipv6_only: None,
    })
}

fn state_label(state: u8, protocol: Protocol) -> &'static str {
    if protocol == Protocol::Udp {
        return if state == 1 { "CONNECTED" } else { "BOUND" };
    }
    match state {
        1 => "ESTABLISHED",
        2 => "SYN-SENT",
        3 => "SYN-RECV",
        4 => "FIN-WAIT-1",
        5 => "FIN-WAIT-2",
        6 => "TIME-WAIT",
        7 => "CLOSE",
        8 => "CLOSE-WAIT",
        9 => "LAST-ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW-SYN-RECV",
        _ => "UNKNOWN",
    }
}

fn start_time(stat: &str) -> Option<u64> {
    // comm is parenthesized and may contain spaces or parentheses.
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_ascii_whitespace().nth(19)?.parse().ok()
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .take(128)
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn scan_owners(
    inodes: &HashSet<u64>,
    users: &HashMap<u32, String>,
) -> (HashMap<u64, Vec<Owner>>, bool, bool) {
    let mut owners: HashMap<u64, Vec<Owner>> = HashMap::new();
    let mut restricted = false;
    let mut limited = false;
    let mut fd_links = 0;
    let Ok(processes) = fs::read_dir("/proc") else {
        return (owners, true, false);
    };
    for (process_count, entry) in processes
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .enumerate()
    {
        if process_count >= MAX_PROCESSES || fd_links >= MAX_FD_LINKS {
            limited = true;
            break;
        }
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(before_stat) = fs::read_to_string(path.join("stat")) else {
            continue;
        };
        let Some(before_start) = start_time(&before_stat) else {
            continue;
        };
        let descriptors = match fs::read_dir(path.join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                restricted |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        let mut matched = HashSet::new();
        for descriptor in descriptors.filter_map(Result::ok) {
            fd_links += 1;
            if fd_links >= MAX_FD_LINKS {
                limited = true;
                break;
            }
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) => {
                    // Directory listing and ptrace-gated symlink access are
                    // separate permissions, notably for nondumpable processes.
                    restricted |= error.kind() == std::io::ErrorKind::PermissionDenied;
                    continue;
                }
            };
            let text = target.to_string_lossy();
            let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if inodes.contains(&inode) {
                matched.insert(inode);
            }
        }
        if matched.is_empty() {
            continue;
        }
        let Ok(after_stat) = fs::read_to_string(path.join("stat")) else {
            continue;
        };
        if start_time(&after_stat) != Some(before_start) {
            continue;
        }
        let uid = fs::metadata(&path)
            .map(|metadata| metadata.uid())
            .unwrap_or(u32::MAX);
        let raw_name =
            fs::read_to_string(path.join("comm")).unwrap_or_else(|_| "unknown".to_string());
        let name = sanitize_label(raw_name.strip_suffix('\n').unwrap_or(&raw_name));
        let owner = Owner {
            identity: ProcessIdentity {
                pid,
                start_time: before_start,
            },
            user: users.get(&uid).cloned().unwrap_or_else(|| uid.to_string()),
            name,
        };
        for inode in matched {
            let entries = owners.entry(inode).or_default();
            // Forked/shared descriptors deliberately preserve all owners.
            if entries.len() < 32 {
                entries.push(owner.clone());
            } else {
                limited = true;
            }
        }
    }
    (owners, restricted, limited)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(local: &str, remote: &str, inode: u64) -> SocketKey {
        SocketKey {
            inode,
            protocol: Protocol::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
        }
    }

    fn owned_socket(key: SocketKey, pid: u32, current: bool) -> Socket {
        Socket {
            key,
            state: "BOUND".to_string(),
            uid: 1000,
            owners: vec![Owner {
                identity: ProcessIdentity {
                    pid,
                    start_time: 100,
                },
                user: "test".to_string(),
                name: "test".to_string(),
            }],
            observed: Instant::now(),
            current,
            ipv6_only: None,
        }
    }

    #[test]
    fn proc_addresses_use_native_endian_words() {
        let ipv4_word = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            parse_address(&format!("{ipv4_word:08X}:1F90"), false).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
        if cfg!(target_endian = "little") {
            assert_eq!(
                parse_address("00000000000000000000000001000000:01BB", true).unwrap(),
                "[::1]:443".parse().unwrap()
            );
            assert_eq!(
                parse_address("0000000000000000FFFF00000100007F:01BB", true).unwrap(),
                "127.0.0.1:443".parse().unwrap()
            );
        }
    }

    #[test]
    fn established_connections_outrank_wildcard_listener() {
        let local = "192.0.2.1:443".parse().unwrap();
        let remote = "198.51.100.2:23456".parse().unwrap();
        assert_eq!(
            match_score(
                &owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true),
                local,
                remote
            ),
            Some(1)
        );
        assert_eq!(
            match_score(
                &owned_socket(key("192.0.2.1:443", "198.51.100.2:23456", 2), 2, true),
                local,
                remote
            ),
            Some(6)
        );
        assert_eq!(
            match_score(
                &owned_socket(key("192.0.2.1:443", "198.51.100.3:23456", 3), 3, true),
                local,
                remote
            ),
            None
        );
    }

    #[test]
    fn ambiguous_and_shared_sockets_do_not_get_a_pid() {
        let mut inventory = Inventory::new();
        for inode in [1, 2] {
            inventory.sockets.push(Socket {
                key: key("0.0.0.0:443", "0.0.0.0:0", inode),
                state: "LISTEN".to_string(),
                uid: 1000,
                owners: vec![Owner {
                    identity: ProcessIdentity {
                        pid: inode as u32,
                        start_time: 100,
                    },
                    user: "test".to_string(),
                    name: "test".to_string(),
                }],
                observed: Instant::now(),
                current: true,
                ipv6_only: None,
            });
        }
        inventory.index.insert((Protocol::Tcp, 443), vec![0, 1]);
        assert!(
            inventory
                .resolve(
                    Protocol::Tcp,
                    "192.0.2.1:443".parse().unwrap(),
                    "198.51.100.2:23456".parse().unwrap()
                )
                .is_none()
        );
        inventory.index.insert((Protocol::Tcp, 443), vec![0]);
        let shared_owner = inventory.sockets[1].owners[0].clone();
        inventory.sockets[0].owners.push(shared_owner);
        assert!(
            inventory
                .resolve(
                    Protocol::Tcp,
                    "192.0.2.1:443".parse().unwrap(),
                    "198.51.100.2:23456".parse().unwrap()
                )
                .is_none()
        );
    }

    #[test]
    fn retained_connected_socket_cannot_steal_rebound_wildcard_traffic() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for current in [true, false] {
                let mut inventory = Inventory::new();
                inventory.sockets = vec![
                    owned_socket(key("192.0.2.1:53000", "198.51.100.2:53001", 1), 101, false),
                    owned_socket(key("0.0.0.0:53000", "0.0.0.0:0", 2), 102, current),
                ];
                for socket in &mut inventory.sockets {
                    socket.key.protocol = protocol;
                }
                inventory.index.insert((protocol, 53000), vec![0, 1]);
                let local = "192.0.2.1:53000".parse().unwrap();
                let remote = "198.51.100.2:53001".parse().unwrap();
                assert!(inventory.resolve(protocol, local, remote).is_none());
                // Once the conflicting incarnation expires, attribution resumes.
                inventory.index.insert((protocol, 53000), vec![1]);
                assert_eq!(
                    inventory
                        .resolve(protocol, local, remote)
                        .unwrap()
                        .owner()
                        .unwrap()
                        .identity
                        .pid,
                    102
                );
            }
        }
    }

    #[test]
    fn ipv4_matches_only_confirmed_dual_stack_wildcards() {
        let mut socket = owned_socket(key("[::]:53000", "[::]:0", 1), 101, true);
        let local = "127.0.0.1:53000".parse().unwrap();
        let remote = "127.0.0.1:53001".parse().unwrap();
        assert_eq!(match_score(&socket, local, remote), None);
        socket.ipv6_only = Some(true);
        assert_eq!(match_score(&socket, local, remote), None);
        socket.ipv6_only = Some(false);
        assert_eq!(match_score(&socket, local, remote), Some(1));
        assert_eq!(
            match_score(
                &socket,
                "[::1]:53000".parse().unwrap(),
                "[::1]:53001".parse().unwrap()
            ),
            Some(1)
        );
    }

    #[test]
    fn socket_diagnostics_validate_attribute_lengths_and_addresses() {
        let mut message = vec![0; 80];
        message[0] = libc::AF_INET6 as u8;
        message[4..6].copy_from_slice(&53000_u16.to_be_bytes());
        message[68..72].copy_from_slice(&123_u32.to_ne_bytes());
        message[72..74].copy_from_slice(&5_u16.to_ne_bytes());
        message[74..76].copy_from_slice(&11_u16.to_ne_bytes());
        let (socket, only) = parse_ipv6_mode(&message, Protocol::Udp).unwrap();
        assert_eq!(socket.local, "[::]:53000".parse().unwrap());
        assert_eq!(socket.inode, 123);
        assert!(!only);
        message[76] = 1;
        assert!(parse_ipv6_mode(&message, Protocol::Udp).unwrap().1);
        message[72..74].copy_from_slice(&3_u16.to_ne_bytes());
        assert!(parse_ipv6_mode(&message, Protocol::Udp).is_none());
        message[72..74].copy_from_slice(&100_u16.to_ne_bytes());
        assert!(parse_ipv6_mode(&message, Protocol::Udp).is_none());
        assert!(parse_ipv6_mode(&message[..40], Protocol::Udp).is_none());
    }

    #[test]
    fn process_identity_handles_parentheses_in_comm() {
        let mut fields = vec!["0"; 20];
        fields[19] = "123456";
        assert_eq!(
            start_time(&format!("42 (name (test)) {}", fields.join(" "))),
            Some(123456)
        );
        assert_ne!(
            ProcessIdentity {
                pid: 42,
                start_time: 10
            },
            ProcessIdentity {
                pid: 42,
                start_time: 11
            }
        );
    }

    #[test]
    fn process_and_user_labels_cannot_inject_terminal_controls() {
        assert_eq!(sanitize_label("evil\u{1b}[31m\n\tname"), "evil?[31m??name");
        assert_eq!(sanitize_label("unicode-äöü\u{7f}"), "unicode-äöü?");
        assert_eq!(sanitize_label(&"x".repeat(1024)).len(), 128);
    }
}
