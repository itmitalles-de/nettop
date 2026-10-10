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
/// Socket tables are reread at most this often, below the collector's
/// background attribution cadence.
const MIN_REFRESH: Duration = Duration::from_millis(200);
const MIN_OWNER_SCAN_GAP: Duration = Duration::from_millis(200);
const FULL_OWNER_RESCAN: Duration = Duration::from_secs(5);
const OWNER_CHECK: Duration = Duration::from_secs(1);
/// Budget for receiving one SOCK_DIAG dump, counted from after the request
/// was sent: the first query can autoload inet_diag/udp_diag synchronously
/// inside sendto().
const DIAG_DEADLINE: Duration = Duration::from_millis(50);
/// Pause after a complete or rejected dump that lacked a socket.
const DIAG_RETRY: Duration = Duration::from_secs(2);
/// Incomplete dumps (deadline, interruption) are retried on the next refresh
/// this many times in a row before backing off like failed lookups.
const DIAG_PROMPT_RETRIES: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Outcome of matching one flow endpoint against the socket inventory.
pub(super) enum Resolution<'a> {
    /// Exactly one best socket with a single owning process.
    Owned(&'a Socket),
    /// Several equally good sockets (SO_REUSEPORT) of one process; the
    /// socket is a representative only, the process is certain.
    Process(&'a Socket),
    /// The best socket is new and its owner has not been scanned yet, or the
    /// only candidate is an IPv6 wildcard whose V6ONLY mode is still unknown.
    Pending,
    /// No listed socket matches this endpoint.
    Missing,
    /// An ambiguous, or a shared/ownerless match.
    Unattributed,
}

/// The latest SOCK_DIAG lookup for one IPv6 wildcard socket that lacked it.
#[derive(Clone, Copy, Debug)]
struct DiagAttempt {
    at: Instant,
    /// Incomplete dumps in a row; a complete answer sets the full backoff.
    incomplete: u8,
}

impl DiagAttempt {
    fn due(&self, now: Instant) -> bool {
        self.incomplete < DIAG_PROMPT_RETRIES
            || now.saturating_duration_since(self.at) >= DIAG_RETRY
    }

    fn next(previous: Option<&Self>, outcome: DiagOutcome, now: Instant) -> Self {
        Self {
            at: now,
            incomplete: match outcome {
                DiagOutcome::Incomplete => {
                    previous.map_or(0, |attempt| attempt.incomplete.min(DIAG_PROMPT_RETRIES)) + 1
                }
                DiagOutcome::Complete | DiagOutcome::Rejected => DIAG_PROMPT_RETRIES,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiagOutcome {
    /// The dump ended (NLMSG_DONE); an open socket missing from it stays
    /// unknown, retried after DIAG_RETRY.
    Complete,
    /// The kernel rejected the query, e.g. without udp_diag support.
    Rejected,
    /// Deadline, interruption or a malformed reply: retry promptly.
    Incomplete,
}

type ExactKey = (Protocol, SocketAddr, SocketAddr);

pub(super) struct Inventory {
    pub sockets: Vec<Socket>,
    pub users: HashMap<u32, String>,
    /// Some socket tables or process descriptors were inaccessible during the
    /// latest table refresh or owner scan (not "ever since startup").
    pub restricted: bool,
    /// A socket, process or descriptor bound was hit during the latest table
    /// refresh or owner scan.
    pub limited: bool,
    /// Connected sockets by their full endpoint pair: one lookup per flow
    /// instead of scanning every connection sharing a busy local port.
    exact: HashMap<ExactKey, Vec<usize>>,
    /// Listeners, unconnected and wildcard sockets by local port.
    by_port: HashMap<(Protocol, u16), Vec<usize>>,
    owners: HashMap<u64, Vec<Owner>>,
    owner_keys: HashMap<u64, SocketKey>,
    owner_flags: (bool, bool),
    owners_stale: bool,
    /// Inodes whose previous owner the latest scan kept although no
    /// descriptor was found; a second miss drops it.
    carried_owners: HashSet<u64>,
    owner_scan_cost: Duration,
    ipv6_modes: HashMap<SocketKey, bool>,
    ipv6_attempts: HashMap<SocketKey, DiagAttempt>,
    last_scan: Option<Instant>,
    last_owner_scan: Option<Instant>,
    last_owner_check: Option<Instant>,
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
            exact: HashMap::new(),
            by_port: HashMap::new(),
            owners: HashMap::new(),
            owner_keys: HashMap::new(),
            owner_flags: (false, false),
            owners_stale: false,
            carried_owners: HashSet::new(),
            owner_scan_cost: Duration::ZERO,
            ipv6_modes: HashMap::new(),
            ipv6_attempts: HashMap::new(),
            last_scan: None,
            last_owner_scan: None,
            last_owner_check: None,
        }
    }

    pub(super) fn refresh(&mut self) {
        let now = Instant::now();
        if self
            .last_scan
            .is_some_and(|last| now.duration_since(last) < MIN_REFRESH)
        {
            return;
        }
        let mut restricted = false;
        let mut limited = false;
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
                            limited = true;
                            break;
                        }
                        if let Some(socket) = parse_socket(line, protocol, ipv6, now) {
                            current.push(socket);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    restricted = true
                }
                Err(_) => {}
            }
        }
        self.refresh_owners(&current, now);
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
        self.refresh_ipv6_modes(&current, now);
        for socket in &mut current {
            socket.ipv6_only = self.ipv6_modes.get(&socket.key).copied();
        }
        let live_keys: HashSet<_> = current.iter().map(|socket| socket.key.clone()).collect();
        for mut socket in self.sockets.drain(..) {
            if current.len() >= MAX_SOCKETS {
                limited = true;
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
        self.rebuild_index();
        let (owner_restricted, owner_limited) = self.owner_flags;
        self.restricted = restricted || owner_restricted;
        self.limited = limited || owner_limited;
        self.last_scan = Some(now);
    }

    /// Descriptor scans are the expensive part. Scan promptly when sockets
    /// without a scanned owner appear or a cached owner exited, but never more
    /// often than a gap proportional to the previous scan's cost; otherwise
    /// rescan only periodically to notice inherited or passed descriptors.
    fn refresh_owners(&mut self, current: &[Socket], now: Instant) {
        if self
            .last_owner_check
            .is_none_or(|last| now.saturating_duration_since(last) >= OWNER_CHECK)
        {
            // Cheap PID-reuse protection between full scans: drop owners whose
            // process exited or whose PID now belongs to another process.
            self.owners_stale |= remove_exited_owners(&mut self.owners);
            self.last_owner_check = Some(now);
        }
        let unscanned = current.iter().any(|socket| {
            socket.key.inode != 0 && self.owner_keys.get(&socket.key.inode) != Some(&socket.key)
        });
        let gap = self.owner_scan_gap();
        let due = self.last_owner_scan.is_none_or(|last| {
            let since = now.saturating_duration_since(last);
            since >= FULL_OWNER_RESCAN || ((unscanned || self.owners_stale) && since >= gap)
        });
        if !due {
            return;
        }
        let live_inodes: HashSet<_> = current
            .iter()
            .map(|socket| socket.key.inode)
            .filter(|inode| *inode != 0)
            .collect();
        let started = Instant::now();
        let (mut owners, restricted, limited) = scan_owners(&live_inodes, &self.users);
        self.owner_scan_cost = started.elapsed();
        self.carried_owners = carry_closing_owners(
            current,
            &mut owners,
            &self.owners,
            &self.owner_keys,
            &self.carried_owners,
        );
        self.owners = owners;
        self.owner_keys = current
            .iter()
            .filter(|socket| socket.key.inode != 0)
            .map(|socket| (socket.key.inode, socket.key.clone()))
            .collect();
        self.owner_flags = (restricted, limited);
        self.owners_stale = false;
        self.last_owner_scan = Some(now);
        self.last_owner_check = Some(now);
    }

    /// Minimum spacing of prompt owner scans: ten times the previous scan's
    /// cost, so scans use at most about a tenth of one CPU.
    pub(super) fn owner_scan_gap(&self) -> Duration {
        (self.owner_scan_cost * 10).clamp(MIN_OWNER_SCAN_GAP, FULL_OWNER_RESCAN)
    }

    /// When the socket tables were last reread, if ever.
    pub(super) fn refreshed_at(&self) -> Option<Instant> {
        self.last_scan
    }

    #[cfg(test)]
    pub(super) fn set_refreshed_at(&mut self, at: Option<Instant>) {
        self.last_scan = at;
    }

    /// IPV6_V6ONLY cannot change after bind, so results are cached per socket
    /// incarnation and only new wildcard sockets are queried. Sockets missing
    /// from a complete answer are retried after a pause instead of on every
    /// refresh; an incomplete dump is retried promptly a few times.
    fn refresh_ipv6_modes(&mut self, current: &[Socket], now: Instant) {
        let wanted: HashMap<&SocketKey, u32> = current
            .iter()
            .filter(|socket| socket.key.local.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
            .map(|socket| (&socket.key, state_mask(&socket.state, socket.key.protocol)))
            .collect();
        self.ipv6_modes.retain(|key, _| wanted.contains_key(key));
        self.ipv6_attempts.retain(|key, _| wanted.contains_key(key));
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut states = 0;
            let mut missing = HashSet::new();
            for (&key, &mask) in &wanted {
                if key.protocol == protocol
                    && !self.ipv6_modes.contains_key(key)
                    && self
                        .ipv6_attempts
                        .get(key)
                        .is_none_or(|attempt| attempt.due(now))
                {
                    missing.insert(key.clone());
                    states |= mask;
                }
            }
            if missing.is_empty() {
                continue;
            }
            // Each protocol has its own deadline; a slow TCP dump cannot starve UDP.
            let outcome = read_ipv6_modes(
                protocol,
                states,
                &missing,
                &mut self.ipv6_modes,
                DIAG_DEADLINE,
            );
            for key in missing {
                if self.ipv6_modes.contains_key(&key) {
                    self.ipv6_attempts.remove(&key);
                } else {
                    let attempt = DiagAttempt::next(self.ipv6_attempts.get(&key), outcome, now);
                    self.ipv6_attempts.insert(key, attempt);
                }
            }
        }
    }

    pub(super) fn rebuild_index(&mut self) {
        self.exact.clear();
        self.by_port.clear();
        for (index, socket) in self.sockets.iter().enumerate() {
            let key = &socket.key;
            if !key.local.ip().is_unspecified() && !key.remote.ip().is_unspecified() {
                self.exact
                    .entry((key.protocol, key.local, key.remote))
                    .or_default()
                    .push(index);
            } else {
                self.by_port
                    .entry((key.protocol, key.local.port()))
                    .or_default()
                    .push(index);
            }
        }
    }

    /// Exact connected sockets outrank listeners. Tied inodes or shared owners
    /// remain unassigned instead of choosing an arbitrary PID.
    pub(super) fn resolve(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Resolution<'_> {
        let exact = self
            .exact
            .get(&(protocol, local, remote))
            .map_or(&[][..], Vec::as_slice);
        let wildcard = self
            .by_port
            .get(&(protocol, local.port()))
            .map_or(&[][..], Vec::as_slice);
        // After a local close the kernel keeps the same endpoint pair without
        // an inode (FIN-WAIT, TIME-WAIT, LAST-ACK). That remnant continues the
        // retained socket; it is not a competing incarnation.
        let continued = exact.iter().any(|&index| {
            let socket = &self.sockets[index];
            !socket.current && socket.key.inode != 0
        });
        // A connection waiting in the accept queue is listed without an inode
        // until accept() gives it one. The vanished queue entry is that same
        // connection, not a competing incarnation of the later inode socket.
        let accepted_since = exact
            .iter()
            .map(|&index| &self.sockets[index])
            .filter(|socket| socket.key.inode != 0)
            .map(|socket| socket.observed)
            .max();
        let mut best = None;
        let mut best_score = 0;
        let mut tied: Vec<&Socket> = Vec::new();
        let mut matching_incarnations = 0;
        let mut retained_match = false;
        let mut unknown_mode = false;
        let candidates = exact
            .iter()
            .map(|&index| (index, true))
            .chain(wildcard.iter().map(|&index| (index, false)));
        let mut exact_match = false;
        for (index, is_exact) in candidates {
            let socket = &self.sockets[index];
            if is_exact && continued && closing_remnant(socket) {
                continue;
            }
            if is_exact && accepted_since.is_some_and(|seen| accepted_queue_entry(socket, seen)) {
                continue;
            }
            // Segments of an existing TCP connection never reach a listener on
            // the same port (they go to the connection or its TIME-WAIT
            // remnant), so a listener is no competing incarnation for them.
            if exact_match && protocol == Protocol::Tcp && socket.state == "LISTEN" {
                continue;
            }
            let Some(score) = match_score(socket, local, remote) else {
                unknown_mode |= socket.current && unknown_ipv6_mode(socket, local, remote);
                continue;
            };
            exact_match |= is_exact;
            matching_incarnations += 1;
            retained_match |= !socket.current;
            if score > best_score {
                best = Some(socket);
                best_score = score;
                tied.clear();
            } else if score == best_score
                && best.is_some_and(|other: &Socket| other.key != socket.key)
            {
                tied.push(socket);
            }
        }
        // A batch can straddle a close/rebind. Prefer neither incarnation when
        // both match, even after both have closed: a retained connected socket
        // must not steal a later wildcard socket's packets, or vice versa.
        if retained_match && matching_incarnations > 1 {
            return Resolution::Unattributed;
        }
        let Some(best) = best else {
            // An IPv4 packet and a dual-stack-capable IPv6 wildcard whose
            // V6ONLY lookup is still outstanding: wait instead of losing it.
            return if unknown_mode {
                Resolution::Pending
            } else {
                Resolution::Missing
            };
        };
        if !tied.is_empty() {
            // SO_REUSEPORT groups and similar ties: credit the process when
            // every tied socket belongs to the same single owner.
            let identity = best.owner().map(|owner| owner.identity);
            let pending = std::iter::once(best)
                .chain(tied.iter().copied())
                .any(|socket| self.awaiting_owner(socket));
            return if pending {
                Resolution::Pending
            } else if identity.is_some()
                && tied
                    .iter()
                    .all(|socket| socket.owner().map(|owner| owner.identity) == identity)
            {
                Resolution::Process(best)
            } else {
                Resolution::Unattributed
            };
        }
        if best.owner().is_some() {
            Resolution::Owned(best)
        } else if self.awaiting_owner(best) {
            Resolution::Pending
        } else {
            Resolution::Unattributed
        }
    }

    /// A live socket whose inode has not been part of a descriptor scan yet.
    fn awaiting_owner(&self, socket: &Socket) -> bool {
        socket.current
            && socket.key.inode != 0
            && socket.owners.is_empty()
            && self.owner_keys.get(&socket.key.inode) != Some(&socket.key)
    }

    pub(super) fn user(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }
}

/// The socket tables are read before descriptors are scanned. A process that
/// closes a socket in between leaves it listed but without a visible owner,
/// although that owner sent and received the bytes still awaiting attribution
/// in this pass. Keep the owner from the previous scan of the same socket
/// incarnation for one scan; the closed socket then leaves the table, or a
/// second scan without any owner drops it. Returns the carried inodes.
fn carry_closing_owners(
    current: &[Socket],
    owners: &mut HashMap<u64, Vec<Owner>>,
    previous: &HashMap<u64, Vec<Owner>>,
    previous_keys: &HashMap<u64, SocketKey>,
    previously_carried: &HashSet<u64>,
) -> HashSet<u64> {
    let mut carried = HashSet::new();
    for socket in current {
        let inode = socket.key.inode;
        if inode == 0
            || owners.contains_key(&inode)
            || previously_carried.contains(&inode)
            || previous_keys.get(&inode) != Some(&socket.key)
        {
            continue;
        }
        if let Some(known) = previous.get(&inode).filter(|known| !known.is_empty()) {
            owners.insert(inode, known.clone());
            carried.insert(inode);
        }
    }
    carried
}

/// A retained, inode-less TCP entry superseded by a socket of the same
/// endpoint pair that was still listed afterwards.
fn accepted_queue_entry(socket: &Socket, accepted_seen: Instant) -> bool {
    socket.key.protocol == Protocol::Tcp
        && !socket.current
        && socket.key.inode == 0
        && socket.owners.is_empty()
        && socket.observed < accepted_seen
}

fn closing_remnant(socket: &Socket) -> bool {
    socket.current
        && socket.key.inode == 0
        && socket.owners.is_empty()
        && matches!(
            socket.state.as_str(),
            "FIN-WAIT-1" | "FIN-WAIT-2" | "TIME-WAIT" | "CLOSE" | "LAST-ACK" | "CLOSING"
        )
}

fn remove_exited_owners(owners: &mut HashMap<u64, Vec<Owner>>) -> bool {
    let identities: HashSet<ProcessIdentity> = owners
        .values()
        .flatten()
        .map(|owner| owner.identity)
        .collect();
    let exited: HashSet<_> = identities
        .into_iter()
        .filter(|identity| {
            fs::read_to_string(format!("/proc/{}/stat", identity.pid))
                .ok()
                .and_then(|stat| start_time(&stat))
                != Some(identity.start_time)
        })
        .collect();
    if exited.is_empty() {
        return false;
    }
    for entries in owners.values_mut() {
        entries.retain(|owner| !exited.contains(&owner.identity));
    }
    true
}

/// SOCK_DIAG state bit for a socket table state label.
fn state_mask(label: &str, protocol: Protocol) -> u32 {
    let state = if protocol == Protocol::Udp {
        // Unconnected UDP sockets are TCP_CLOSE; connected ones TCP_ESTABLISHED.
        if label == "CONNECTED" { 1 } else { 7 }
    } else {
        (1..=12)
            .find(|state| state_label(*state, protocol) == label)
            .unwrap_or(10)
    };
    1 << state
}

fn match_score(socket: &Socket, local: SocketAddr, remote: SocketAddr) -> Option<u8> {
    endpoint_score(&socket.key, socket.ipv6_only, local, remote)
}

fn endpoint_score(
    key: &SocketKey,
    ipv6_only: Option<bool>,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u8> {
    if key.local.port() != local.port() {
        return None;
    }
    let local_ip = canonical_ip(key.local.ip());
    let packet_local = canonical_ip(local.ip());
    let local_score = if local_ip == packet_local {
        2
    } else if local_ip.is_unspecified()
        && (local_ip.is_ipv4() == packet_local.is_ipv4()
            || (local_ip.is_ipv6() && ipv6_only == Some(false)))
    {
        1
    } else {
        return None;
    };
    let remote_ip = canonical_ip(key.remote.ip());
    let packet_remote = canonical_ip(remote.ip());
    if remote_ip.is_unspecified() && key.remote.port() == 0 {
        Some(local_score)
    } else if remote_ip == packet_remote && key.remote.port() == remote.port() {
        Some(local_score + 4)
    } else {
        None
    }
}

/// An IPv4 packet that an IPv6 wildcard socket would own if it is dual
/// stack, while its V6ONLY mode is not known yet.
fn unknown_ipv6_mode(socket: &Socket, local: SocketAddr, remote: SocketAddr) -> bool {
    socket.ipv6_only.is_none()
        && socket.key.local.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        && canonical_ip(local.ip()).is_ipv4()
        && endpoint_score(&socket.key, Some(false), local, remote).is_some()
}

/// SOCK_DIAG exposes IPV6_V6ONLY without opening another process's descriptor.
/// Only wildcard IPv6 sockets need it; a denied/unsupported query leaves IPv4
/// attribution unknown. The kernel filters by state (listeners for TCP,
/// unconnected sockets for UDP), and both elapsed time and retained response
/// data are bounded. `budget` starts once the request is sent.
fn read_ipv6_modes(
    protocol: Protocol,
    states: u32,
    wanted: &HashSet<SocketKey>,
    modes: &mut HashMap<SocketKey, bool>,
    budget: Duration,
) -> DiagOutcome {
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
        return DiagOutcome::Rejected;
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = [0_u8; 72];
    request[0..4].copy_from_slice(&72_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = libc::AF_INET6 as u8;
    request[17] = if protocol == Protocol::Tcp { 6 } else { 17 };
    request[20..24].copy_from_slice(&states.to_ne_bytes());
    request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = loop {
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
        if sent >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break sent;
        }
    };
    if sent != request.len() as isize {
        return DiagOutcome::Rejected;
    }
    // The first query can autoload diag modules synchronously inside
    // sendto(), so the receive deadline only starts now.
    let deadline = Instant::now() + budget;
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
        match unsafe { libc::poll(&mut ready, 1, timeout) } {
            0 => return DiagOutcome::Incomplete,
            ready if ready < 0 => {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return DiagOutcome::Incomplete;
            }
            _ => {}
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
        if length < 0 {
            let error = std::io::Error::last_os_error().kind();
            if matches!(
                error,
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return DiagOutcome::Incomplete;
        }
        if length == 0 || length as usize > buffer.len() || sender.nl_pid != 0 {
            return DiagOutcome::Incomplete;
        }
        if let Some(outcome) =
            parse_diag_datagram(&buffer[..length as usize], protocol, wanted, modes)
        {
            return outcome;
        }
    }
    DiagOutcome::Incomplete
}

/// Records the wanted sockets of one netlink datagram. `None` means the dump
/// continues in a later datagram.
fn parse_diag_datagram(
    mut messages: &[u8],
    protocol: Protocol,
    wanted: &HashSet<SocketKey>,
    modes: &mut HashMap<SocketKey, bool>,
) -> Option<DiagOutcome> {
    while messages.len() >= 16 {
        let length = u32::from_ne_bytes(messages[..4].try_into().unwrap()) as usize;
        if length < 16 || length > messages.len() {
            return Some(DiagOutcome::Incomplete);
        }
        let kind = u16::from_ne_bytes(messages[4..6].try_into().unwrap());
        let sequence = u32::from_ne_bytes(messages[8..12].try_into().unwrap());
        if sequence != 1 {
            return Some(DiagOutcome::Incomplete);
        }
        match kind {
            2 => return Some(DiagOutcome::Rejected), // NLMSG_ERROR
            3 => return Some(DiagOutcome::Complete), // NLMSG_DONE
            20 => {
                if let Some((key, only)) = parse_ipv6_mode(&messages[16..length], protocol)
                    && wanted.contains(&key)
                {
                    modes.insert(key, only);
                }
            }
            _ => {}
        }
        let aligned = (length + 3) & !3;
        messages = messages.get(aligned..).unwrap_or_default();
    }
    None
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

    fn resolved_pid(resolution: Resolution<'_>) -> Option<u32> {
        match resolution {
            Resolution::Owned(socket) => Some(socket.owner().unwrap().identity.pid),
            Resolution::Process(_)
            | Resolution::Pending
            | Resolution::Missing
            | Resolution::Unattributed => None,
        }
    }

    fn inventory_with(sockets: Vec<Socket>) -> Inventory {
        let mut inventory = Inventory::new();
        inventory.sockets = sockets;
        inventory.rebuild_index();
        inventory
    }

    #[test]
    fn ambiguous_and_shared_sockets_do_not_get_a_pid() {
        let local = "192.0.2.1:443".parse().unwrap();
        let remote = "198.51.100.2:23456".parse().unwrap();
        let mut inventory = inventory_with(
            [1, 2]
                .map(|inode| {
                    owned_socket(key("0.0.0.0:443", "0.0.0.0:0", inode), inode as u32, true)
                })
                .into(),
        );
        assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
        let shared_owner = inventory.sockets[1].owners[0].clone();
        inventory.sockets.truncate(1);
        inventory.sockets[0].owners.push(shared_owner);
        inventory.rebuild_index();
        assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
    }

    #[test]
    fn retained_connected_socket_cannot_steal_rebound_wildcard_traffic() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for current in [true, false] {
                let mut sockets = vec![
                    owned_socket(key("192.0.2.1:53000", "198.51.100.2:53001", 1), 101, false),
                    owned_socket(key("0.0.0.0:53000", "0.0.0.0:0", 2), 102, current),
                ];
                for socket in &mut sockets {
                    socket.key.protocol = protocol;
                }
                let mut inventory = inventory_with(sockets);
                let local = "192.0.2.1:53000".parse().unwrap();
                let remote = "198.51.100.2:53001".parse().unwrap();
                assert!(resolved_pid(inventory.resolve(protocol, local, remote)).is_none());
                // Once the conflicting incarnation expires, attribution resumes.
                inventory.sockets.remove(0);
                inventory.rebuild_index();
                assert_eq!(
                    resolved_pid(inventory.resolve(protocol, local, remote)),
                    Some(102)
                );
            }
        }
    }

    #[test]
    fn closed_tcp_connection_keeps_owner_despite_open_listener() {
        let local = "192.0.2.1:443".parse().unwrap();
        let remote = "198.51.100.2:50000".parse().unwrap();
        let mut listener = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true);
        listener.state = "LISTEN".to_string();
        let retained = owned_socket(key("192.0.2.1:443", "198.51.100.2:50000", 2), 2, false);
        let inventory = inventory_with(vec![listener.clone(), retained]);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
            Some(2)
        );
        // UDP has no listen state: a rebound wildcard socket can receive the
        // same datagrams, so overlapping incarnations stay unattributed.
        let mut sockets = vec![
            owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true),
            owned_socket(key("192.0.2.1:443", "198.51.100.2:50000", 2), 2, false),
        ];
        for socket in &mut sockets {
            socket.key.protocol = Protocol::Udp;
        }
        let inventory = inventory_with(sockets);
        assert!(resolved_pid(inventory.resolve(Protocol::Udp, local, remote)).is_none());
    }

    #[test]
    fn busy_ports_use_the_exact_endpoint_index() {
        let mut sockets = vec![owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 1), 1, true)];
        for client in 0..10_000_u32 {
            let remote = format!(
                "198.51.{}.{}:{}",
                client / 250,
                client % 250,
                40_000 + client % 1000
            );
            sockets.push(owned_socket(
                key("192.0.2.1:443", &remote, 10 + client as u64),
                10 + client,
                true,
            ));
        }
        let inventory = inventory_with(sockets);
        // Only the listener needs a per-port scan; connections are looked up directly.
        assert_eq!(inventory.by_port[&(Protocol::Tcp, 443)].len(), 1);
        let local = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            resolved_pid(inventory.resolve(
                Protocol::Tcp,
                local,
                "198.51.0.7:40007".parse().unwrap()
            )),
            Some(17)
        );
        // Unknown peers still fall back to the wildcard listener.
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, "203.0.113.9:1".parse().unwrap())),
            Some(1)
        );
    }

    #[test]
    fn closing_remnant_does_not_hide_retained_owner() {
        let local = "192.0.2.1:50000".parse().unwrap();
        let remote = "198.51.100.2:443".parse().unwrap();
        let retained = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 7), 70, false);
        let mut remnant = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 0), 0, true);
        remnant.owners.clear();
        remnant.state = "TIME-WAIT".to_string();
        let mut inventory = inventory_with(vec![retained.clone(), remnant.clone()]);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
            Some(70)
        );
        // An ownerless remnant alone stays unattributed.
        inventory.sockets.remove(0);
        inventory.rebuild_index();
        assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
        // A queued, not yet accepted connection is a real competing incarnation.
        remnant.state = "ESTABLISHED".to_string();
        let inventory = inventory_with(vec![retained, remnant]);
        assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
    }

    #[test]
    fn accept_queue_entry_does_not_compete_with_the_accepted_socket() {
        let local = "127.0.0.1:8080".parse().unwrap();
        let remote = "127.0.0.1:50000".parse().unwrap();
        let queued_at = Instant::now();
        let mut queued = owned_socket(key("127.0.0.1:8080", "127.0.0.1:50000", 0), 0, false);
        queued.owners.clear();
        queued.state = "ESTABLISHED".to_string();
        queued.observed = queued_at;
        let mut accepted = owned_socket(key("127.0.0.1:8080", "127.0.0.1:50000", 7), 70, true);
        accepted.observed = queued_at + Duration::from_millis(250);
        let mut listener = owned_socket(key("127.0.0.1:8080", "0.0.0.0:0", 1), 1, true);
        listener.state = "LISTEN".to_string();
        let inventory = inventory_with(vec![listener.clone(), queued.clone(), accepted.clone()]);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
            Some(70)
        );
        // Still the same connection after the accepted socket closed, too.
        accepted.current = false;
        let inventory = inventory_with(vec![listener.clone(), queued.clone(), accepted.clone()]);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)),
            Some(70)
        );
        // A queue entry seen after an older connection closed is a different
        // incarnation, and stays unattributed.
        queued.observed = accepted.observed + Duration::from_millis(250);
        let inventory = inventory_with(vec![listener, queued, accepted]);
        assert!(resolved_pid(inventory.resolve(Protocol::Tcp, local, remote)).is_none());
    }

    #[test]
    fn unscanned_new_sockets_are_pending_not_lost() {
        let mut socket = owned_socket(key("192.0.2.1:50000", "198.51.100.2:443", 9), 0, true);
        socket.owners.clear();
        let mut inventory = inventory_with(vec![
            socket.clone(),
            owned_socket(key("0.0.0.0:50000", "0.0.0.0:0", 1), 1, true),
        ]);
        let local = "192.0.2.1:50000".parse().unwrap();
        let remote = "198.51.100.2:443".parse().unwrap();
        assert!(matches!(
            inventory.resolve(Protocol::Tcp, local, remote),
            Resolution::Pending
        ));
        // Once scanned without an owner, the socket is simply unattributed.
        inventory.owner_keys.insert(9, socket.key);
        assert!(matches!(
            inventory.resolve(Protocol::Tcp, local, remote),
            Resolution::Unattributed
        ));
    }

    #[test]
    fn new_sockets_trigger_a_prompt_owner_rescan() {
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut inventory = Inventory::new();
        inventory.refresh();
        let own_pid = std::process::id();
        let owner_of = |inventory: &Inventory, listener: &std::net::TcpListener| {
            let local = listener.local_addr().unwrap();
            resolved_pid(inventory.resolve(Protocol::Tcp, local, "127.0.0.1:9".parse().unwrap()))
        };
        assert_eq!(owner_of(&inventory, &first), Some(own_pid));
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // Well inside the periodic full-rescan period, but past the minimum gap.
        inventory.last_scan = None;
        inventory.last_owner_scan = Some(Instant::now() - Duration::from_millis(300));
        inventory.owner_scan_cost = Duration::ZERO;
        inventory.refresh();
        assert_eq!(owner_of(&inventory, &second), Some(own_pid));
    }

    #[test]
    fn exited_or_reused_pids_lose_cached_ownership() {
        let stat = fs::read_to_string("/proc/self/stat").unwrap();
        let alive = Owner {
            identity: ProcessIdentity {
                pid: std::process::id(),
                start_time: start_time(&stat).unwrap(),
            },
            user: "test".to_string(),
            name: "test".to_string(),
        };
        let mut reused = alive.clone();
        reused.identity.start_time += 1;
        let mut owners =
            HashMap::from([(1, vec![alive.clone(), reused]), (2, vec![alive.clone()])]);
        assert!(remove_exited_owners(&mut owners));
        assert_eq!(owners[&1], vec![alive.clone()]);
        assert_eq!(owners[&2], vec![alive]);
        assert!(!remove_exited_owners(&mut owners));
    }

    #[test]
    fn ipv6_wildcard_modes_are_cached_per_socket() {
        let Ok(listener) = std::net::TcpListener::bind("[::]:0") else {
            return; // No IPv6 in this environment.
        };
        let port = listener.local_addr().unwrap().port();
        let mut inventory = Inventory::new();
        inventory.refresh();
        let key = inventory
            .sockets
            .iter()
            .find(|socket| socket.current && socket.key.local.port() == port)
            .map(|socket| socket.key.clone())
            .unwrap();
        let Some(&mode) = inventory.ipv6_modes.get(&key) else {
            return; // SOCK_DIAG unavailable; unknown must stay unknown.
        };
        inventory.last_scan = None;
        inventory.refresh();
        assert_eq!(inventory.ipv6_modes.get(&key), Some(&mode));
        assert!(inventory.ipv6_attempts.is_empty());
        drop(listener);
        inventory.last_scan = None;
        inventory.refresh();
        assert!(
            !inventory.ipv6_modes.contains_key(&key),
            "closed sockets leave the cache"
        );
    }

    #[test]
    fn socket_diagnostics_request_only_needed_states() {
        assert_eq!(state_mask("LISTEN", Protocol::Tcp), 1 << 10);
        assert_eq!(state_mask("CLOSE", Protocol::Tcp), 1 << 7);
        assert_eq!(state_mask("BOUND", Protocol::Udp), 1 << 7);
        assert_eq!(state_mask("CONNECTED", Protocol::Udp), 1 << 1);
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
    fn ipv4_to_an_ipv6_wildcard_of_unknown_mode_waits() {
        let mut socket = owned_socket(key("[::]:53000", "[::]:0", 1), 101, true);
        socket.key.protocol = Protocol::Udp;
        let mut inventory = inventory_with(vec![socket]);
        let local = "127.0.0.1:53000".parse().unwrap();
        let remote = "127.0.0.1:53001".parse().unwrap();
        assert!(matches!(
            inventory.resolve(Protocol::Udp, local, remote),
            Resolution::Pending
        ));
        inventory.sockets[0].ipv6_only = Some(false);
        assert_eq!(
            resolved_pid(inventory.resolve(Protocol::Udp, local, remote)),
            Some(101)
        );
        // An IPv6-only wildcard can never own it.
        inventory.sockets[0].ipv6_only = Some(true);
        assert!(matches!(
            inventory.resolve(Protocol::Udp, local, remote),
            Resolution::Missing
        ));
        // IPv6 packets and closed sockets never wait for the mode.
        inventory.sockets[0].ipv6_only = None;
        assert_eq!(
            resolved_pid(inventory.resolve(
                Protocol::Udp,
                "[::1]:53000".parse().unwrap(),
                "[::1]:53001".parse().unwrap()
            )),
            Some(101)
        );
        inventory.sockets[0].current = false;
        assert!(matches!(
            inventory.resolve(Protocol::Udp, local, remote),
            Resolution::Missing
        ));
    }

    #[test]
    fn endpoints_without_any_socket_are_missing() {
        let inventory = inventory_with(vec![owned_socket(
            key("127.0.0.1:8080", "0.0.0.0:0", 1),
            1,
            true,
        )]);
        assert!(matches!(
            inventory.resolve(
                Protocol::Tcp,
                "127.0.0.1:9090".parse().unwrap(),
                "127.0.0.1:50000".parse().unwrap()
            ),
            Resolution::Missing
        ));
    }

    #[test]
    fn reuseport_sockets_of_one_process_credit_that_process() {
        let local = "192.0.2.1:443".parse().unwrap();
        let remote = "198.51.100.2:23456".parse().unwrap();
        let mut sockets: Vec<_> = [1, 2]
            .map(|inode| owned_socket(key("0.0.0.0:443", "0.0.0.0:0", inode), 7, true))
            .into();
        let inventory = inventory_with(sockets.clone());
        match inventory.resolve(Protocol::Tcp, local, remote) {
            Resolution::Process(socket) => assert_eq!(socket.owner().unwrap().identity.pid, 7),
            _ => panic!("tied sockets of one process credit the process"),
        }
        // A socket still awaiting its owner scan may belong to someone else.
        sockets[1].owners.clear();
        let inventory = inventory_with(sockets.clone());
        assert!(matches!(
            inventory.resolve(Protocol::Tcp, local, remote),
            Resolution::Pending
        ));
        // Different processes, or a reused PID, stay unattributed.
        sockets[1] = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 2), 8, true);
        let inventory = inventory_with(sockets.clone());
        assert!(matches!(
            inventory.resolve(Protocol::Tcp, local, remote),
            Resolution::Unattributed
        ));
        sockets[1] = owned_socket(key("0.0.0.0:443", "0.0.0.0:0", 2), 7, true);
        sockets[1].owners[0].identity.start_time += 1;
        let inventory = inventory_with(sockets);
        assert!(matches!(
            inventory.resolve(Protocol::Tcp, local, remote),
            Resolution::Unattributed
        ));
    }

    #[test]
    fn incomplete_diag_dumps_retry_promptly_then_back_off() {
        let start = Instant::now();
        let mut attempt = None;
        for _ in 0..DIAG_PROMPT_RETRIES - 1 {
            let next = DiagAttempt::next(attempt.as_ref(), DiagOutcome::Incomplete, start);
            assert!(next.due(start), "a timed-out dump is retried next refresh");
            attempt = Some(next);
        }
        let exhausted = DiagAttempt::next(attempt.as_ref(), DiagOutcome::Incomplete, start);
        assert!(!exhausted.due(start + Duration::from_millis(250)));
        assert!(exhausted.due(start + DIAG_RETRY));
        for outcome in [DiagOutcome::Complete, DiagOutcome::Rejected] {
            let answered = DiagAttempt::next(None, outcome, start);
            assert!(!answered.due(start + Duration::from_millis(250)));
            assert!(answered.due(start + DIAG_RETRY));
        }
    }

    fn netlink_message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut message = Vec::new();
        message.extend_from_slice(&(length as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&0_u16.to_ne_bytes());
        message.extend_from_slice(&sequence.to_ne_bytes());
        message.extend_from_slice(&0_u32.to_ne_bytes());
        message.extend_from_slice(payload);
        message.resize((length + 3) & !3, 0);
        message
    }

    #[test]
    fn diag_dumps_distinguish_complete_rejected_and_partial_replies() {
        let mut socket = vec![0; 80];
        socket[0] = libc::AF_INET6 as u8;
        socket[4..6].copy_from_slice(&53000_u16.to_be_bytes());
        socket[68..72].copy_from_slice(&123_u32.to_ne_bytes());
        socket[72..74].copy_from_slice(&5_u16.to_ne_bytes());
        socket[74..76].copy_from_slice(&11_u16.to_ne_bytes());
        let wanted = HashSet::from([SocketKey {
            inode: 123,
            protocol: Protocol::Udp,
            local: "[::]:53000".parse().unwrap(),
            remote: "[::]:0".parse().unwrap(),
        }]);
        let mut modes = HashMap::new();
        let partial = netlink_message(20, 1, &socket);
        assert_eq!(
            parse_diag_datagram(&partial, Protocol::Udp, &wanted, &mut modes),
            None,
            "the dump continues in the next datagram"
        );
        assert_eq!(modes.values().copied().collect::<Vec<_>>(), vec![false]);
        let mut done = partial.clone();
        done.extend(netlink_message(3, 1, &[0; 4]));
        assert_eq!(
            parse_diag_datagram(&done, Protocol::Udp, &wanted, &mut modes),
            Some(DiagOutcome::Complete)
        );
        assert_eq!(
            parse_diag_datagram(
                &netlink_message(2, 1, &[0; 20]),
                Protocol::Udp,
                &wanted,
                &mut modes
            ),
            Some(DiagOutcome::Rejected)
        );
        for broken in [netlink_message(20, 2, &socket), partial[..20].to_vec()] {
            assert_eq!(
                parse_diag_datagram(&broken, Protocol::Udp, &wanted, &mut modes),
                Some(DiagOutcome::Incomplete)
            );
        }
    }

    #[test]
    fn live_diag_query_finishes_within_its_budget() {
        let Ok(socket) = std::net::UdpSocket::bind("[::]:0") else {
            return; // No IPv6 in this environment.
        };
        let port = socket.local_addr().unwrap().port();
        let mut inventory = Inventory::new();
        inventory.refresh();
        let Some(key) = inventory
            .sockets
            .iter()
            .find(|socket| socket.current && socket.key.local.port() == port)
            .map(|socket| socket.key.clone())
        else {
            return;
        };
        let mut modes = HashMap::new();
        let outcome = read_ipv6_modes(
            Protocol::Udp,
            1 << 7,
            &HashSet::from([key.clone()]),
            &mut modes,
            Duration::from_secs(2),
        );
        // Some sandboxes deny SOCK_DIAG; a granted query must complete.
        assert_ne!(outcome, DiagOutcome::Incomplete);
        if outcome == DiagOutcome::Complete {
            assert!(modes.contains_key(&key));
        }
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
    fn owner_closing_during_a_scan_is_kept_for_one_scan() {
        let closing = owned_socket(key("127.0.0.1:40000", "127.0.0.1:8080", 7), 7, true);
        let reused = owned_socket(key("127.0.0.1:40002", "127.0.0.1:8080", 8), 8, true);
        let moved = owned_socket(key("127.0.0.1:40004", "127.0.0.1:8080", 9), 9, true);
        let current = vec![closing.clone(), reused.clone(), moved.clone()];
        let previous: HashMap<_, _> = current
            .iter()
            .map(|socket| (socket.key.inode, socket.owners.clone()))
            .collect();
        let mut previous_keys: HashMap<_, _> = current
            .iter()
            .map(|socket| (socket.key.inode, socket.key.clone()))
            .collect();
        // Inode 8 was a different endpoint pair at the previous scan.
        previous_keys.insert(8, key("127.0.0.1:39999", "127.0.0.1:8080", 8));
        // The descriptor of inode 9 now belongs to another process.
        let mut owners = HashMap::from([(9, owned_socket(moved.key.clone(), 90, true).owners)]);
        let carried = carry_closing_owners(
            &current,
            &mut owners,
            &previous,
            &previous_keys,
            &HashSet::new(),
        );
        assert_eq!(carried, HashSet::from([7]));
        assert_eq!(owners[&7], closing.owners);
        assert!(!owners.contains_key(&8));
        assert_eq!(owners[&9][0].identity.pid, 90);

        // A socket still listed without any owner at the next scan is dropped.
        let mut next = HashMap::new();
        let again =
            carry_closing_owners(&current[..1], &mut next, &owners, &previous_keys, &carried);
        assert!(again.is_empty());
        assert!(next.is_empty());
    }

    #[test]
    fn process_and_user_labels_cannot_inject_terminal_controls() {
        assert_eq!(sanitize_label("evil\u{1b}[31m\n\tname"), "evil?[31m??name");
        assert_eq!(sanitize_label("unicode-äöü\u{7f}"), "unicode-äöü?");
        assert_eq!(sanitize_label(&"x".repeat(1024)).len(), 128);
    }
}
