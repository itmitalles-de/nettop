//! Bounded process-context evidence. Packet bytes always come from libpcap.
use super::{
    capture::TimedBytes,
    events::Event,
    packet::Protocol,
    sockets::{Inventory, Owner, ProcessIdentity, Socket, SocketKey, canonical_ip},
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

const RETAIN: u64 = 3_000_000_000;
const SLOP: u64 = 1_000_000; // pcap realtime conversion / microsecond timestamps
const MAX_RECORDS: usize = 32_768;
const MAX_NAMESPACES: usize = 128;
const MAX_CANDIDATES: usize = 128;
type Tuple = (u64, Protocol, u16, SocketAddr);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    namespace: u64,
    socket: u64,
    owner: ProcessIdentity,
    process_started_ns: u64,
    protocol: Protocol,
    local: SocketAddr,
    remote: SocketAddr,
}
#[derive(Clone, Copy)]
struct Window {
    first: u64,
    last: u64,
    directions: u8,
}
#[derive(Default)]
struct Lifetime {
    first: Option<u64>,
    seen: u64,
    actor: Option<(u32, u64)>,
    conflict: bool,
    binding: Option<(SocketAddr, u64)>,
}
struct Binding {
    socket: Option<u64>,
    inode: u64,
    local: SocketAddr,
    first: u64,
    last: u64,
}
struct Record {
    socket: Socket,
    closed_conflict: bool,
    lifetime: Option<Window>,
    seen: u64,
    closed: Option<u64>,
    windows: Vec<Window>,
}
#[derive(Default)]
pub(super) struct Owners {
    records: HashMap<Key, Record>,
    // Reservations from different CPUs can reach the ring in an order that
    // differs from event timestamps. A CLOSE must survive a later-drained SEND.
    closed: HashMap<(u64, u64), u64>,
    lifetimes: HashMap<(u64, u64), Lifetime>,
    unsafe_until: u64,
    quarantine_reason: Option<String>,
    limited: bool,
    updated_at: u64,
    bindings_limited: bool,
    windows: usize,
    namespaces: HashSet<u64>,
    addresses: HashSet<(u64, IpAddr)>,
    // None marks an overfull tuple. Never drop only the conflicting owners.
    tuples: HashMap<Tuple, Option<Vec<Key>>>,
    bindings: HashMap<(u64, u16), Option<Vec<Binding>>>,
}
pub(super) enum Match {
    Owned(Socket),
    Observed(Socket),
    Missing,
    Ambiguous,
}

impl Owners {
    fn invalidate(&mut self, now: u64, reason: &'static str) {
        self.records.clear();
        self.closed.clear();
        self.lifetimes.clear();
        self.windows = 0;
        self.namespaces.clear();
        self.addresses.clear();
        self.tuples.clear();
        self.bindings.clear();
        self.bindings_limited = false;
        self.unsafe_until = self.unsafe_until.max(now.saturating_add(RETAIN));
        self.quarantine_reason = Some(reason.into());
    }

    pub fn update(&mut self, events: Vec<Event>, lost: u64, now: u64, inventory: &Inventory) {
        self.limited = false;
        self.updated_at = now;
        self.records.retain(|_, record| {
            record
                .windows
                .retain(|window| now.saturating_sub(window.last) <= RETAIN);
            !record.windows.is_empty()
                && now.saturating_sub(record.closed.unwrap_or(record.seen)) <= RETAIN
        });
        self.closed
            .retain(|_, closed| now.saturating_sub(*closed) <= RETAIN);
        self.lifetimes
            .retain(|_, lifetime| now.saturating_sub(lifetime.seen) <= RETAIN);
        self.windows = self
            .records
            .values()
            .map(|record| record.windows.len())
            .sum();
        if lost > 0 {
            self.invalidate(now, "socket events lost");
        }
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks <= 0 {
            self.invalidate(now, "process clock unavailable");
            return;
        }
        for event in events {
            if event.socket_id == 0
                || event.netns == 0
                || event.timestamp_ns == 0
                || now.saturating_sub(event.timestamp_ns) > RETAIN
            {
                continue;
            }
            let socket_identity = (u64::from(event.netns), event.socket_id);
            if event.kind == 7 {
                // TCP clone happens before accept and may run in a kernel
                // receive context. It proves birth, never a process identity.
                if event.protocol != 6
                    || event.started_ns == 0
                    || event.started_ns > event.timestamp_ns
                    || event.started_ns <= self.unsafe_until
                {
                    continue;
                }
                if self.lifetimes.len() >= MAX_RECORDS
                    && !self.lifetimes.contains_key(&socket_identity)
                {
                    self.limited = true;
                    self.invalidate(now, "socket identity limit reached");
                    continue;
                }
                let lifetime = self.lifetimes.entry(socket_identity).or_default();
                lifetime.seen = lifetime.seen.max(event.timestamp_ns);
                lifetime.first = Some(
                    lifetime
                        .first
                        .map_or(event.started_ns, |first| first.min(event.started_ns)),
                );
                continue;
            }
            if !matches!(event.kind, 1..=6) {
                continue;
            }
            if event.flags & 1 != 0 {
                self.invalidate(now, "kernel or io_uring actor cannot be identified");
                continue;
            }
            if event.tgid == 0
                || event.process_start_ns == 0
                || event.reserved != 0
                || event.flags & !2 != 0
                || event.started_ns == 0
                || event.started_ns > event.timestamp_ns
                || event.started_ns <= self.unsafe_until
            {
                continue;
            }
            if self.lifetimes.len() >= MAX_RECORDS && !self.lifetimes.contains_key(&socket_identity)
            {
                self.limited = true;
                self.invalidate(now, "socket identity limit reached");
                continue;
            }
            let lifetime = self.lifetimes.entry(socket_identity).or_default();
            lifetime.seen = lifetime.seen.max(event.timestamp_ns);
            let actor = (event.tgid, event.process_start_ns);
            if lifetime.actor.is_some_and(|previous| previous != actor) {
                lifetime.conflict = true;
            }
            lifetime.actor.get_or_insert(actor);
            // A successful bind/accept/send/connect proves the socket existed
            // from this point. A receive alone cannot backdate ownership to
            // when an already-queued packet arrived.
            if matches!(event.kind, 1 | 3 | 5 | 6) {
                lifetime.first = Some(
                    lifetime
                        .first
                        .map_or(event.started_ns, |first| first.min(event.started_ns)),
                );
            }
            if event.kind == 6
                && event.protocol == 17
                && let Some(local) = address(event.family, event.local_addr, event.local_port)
                && local.port() != 0
            {
                lifetime.binding = Some((local, event.inode));
            }
            if event.kind == 4 {
                if self.closed.len() >= MAX_RECORDS && !self.closed.contains_key(&socket_identity) {
                    self.limited = true;
                    self.invalidate(now, "socket identity limit reached");
                    continue;
                }
                let closed = self
                    .closed
                    .entry(socket_identity)
                    .or_insert(event.timestamp_ns);
                *closed = (*closed).min(event.timestamp_ns);
                continue;
            }
            if event.flags & 2 != 0 {
                continue;
            }
            let protocol = match event.protocol {
                6 => Protocol::Tcp,
                17 => Protocol::Udp,
                _ => continue,
            };
            let Some(local) = address(event.family, event.local_addr, event.local_port) else {
                continue;
            };
            let Some(remote) = address(event.family, event.remote_addr, event.remote_port) else {
                continue;
            };
            if local.port() == 0 || remote.port() == 0 || remote.ip().is_unspecified() {
                continue;
            }
            let identity = ProcessIdentity {
                pid: event.tgid,
                start_time: ((u128::from(event.process_start_ns) * ticks as u128) / 1_000_000_000)
                    as u64,
            };
            let key = Key {
                namespace: u64::from(event.netns),
                socket: event.socket_id,
                owner: identity,
                process_started_ns: event.process_start_ns,
                protocol,
                local,
                remote,
            };
            if self.records.len() >= MAX_RECORDS && !self.records.contains_key(&key) {
                self.limited = true;
                self.invalidate(now, "socket identity limit reached");
                continue;
            }
            let name = String::from_utf8_lossy(
                &event.comm[..event
                    .comm
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(event.comm.len())],
            )
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
            let owner = Owner {
                identity,
                user: inventory
                    .users
                    .get(&event.uid)
                    .cloned()
                    .unwrap_or_else(|| event.uid.to_string()),
                name,
            };
            let record = self.records.entry(key).or_insert_with(|| Record {
                socket: Socket {
                    key: SocketKey {
                        namespace: u64::from(event.netns),
                        inode: event.inode,
                        protocol,
                        local,
                        remote,
                    },
                    state: "OBSERVED".into(),
                    uid: event.uid,
                    owners: vec![owner],
                    observed: Instant::now(),
                    current: false,
                    ipv6_only: None,
                },
                closed_conflict: false,
                lifetime: None,
                seen: event.timestamp_ns,
                closed: self.closed.get(&socket_identity).copied(),
                windows: Vec::new(),
            });
            record.seen = record.seen.max(event.timestamp_ns);
            let window = Window {
                first: event.started_ns,
                last: event.timestamp_ns,
                directions: match event.kind {
                    1 => 1,
                    2 => 2,
                    3 => 3,
                    _ => 0,
                },
            };
            // Append in O(1); coalesce once per batch below, not once per
            // event, so one hot socket cannot cause quadratic update work.
            record.windows.push(window);
            self.windows += 1;
            if self.windows > MAX_RECORDS {
                self.limited = true;
                self.invalidate(now, "socket event window limit reached");
            }
        }
        self.rebuild(now, inventory);
    }

    fn rebuild(&mut self, now: u64, inventory: &Inventory) {
        self.namespaces.clear();
        self.addresses.clear();
        self.tuples.clear();
        self.bindings.clear();
        self.bindings_limited = false;
        self.windows = 0;
        for (key, record) in &mut self.records {
            let socket_id = (key.namespace, key.socket);
            record.closed = self.closed.get(&socket_id).copied();
            if let Some(closed) = record.closed
                && let Some(lifetime) = self.lifetimes.get(&socket_id)
                && let Some(first) = lifetime.first
                && first <= closed
            {
                // Last-reference release occurs after all active socket calls.
                // A closed socket with exactly one observed actor provides a
                // bounded lifetime, including packets queued before recv.
                record.closed_conflict = lifetime.conflict;
                record.lifetime = Some(Window {
                    first,
                    last: closed,
                    directions: if lifetime.conflict { 0 } else { 3 },
                });
            }
            record
                .windows
                .sort_unstable_by_key(|window| (window.directions, window.first, window.last));
            // Only genuinely overlapping syscall intervals are merged. A
            // first..last envelope would invent evidence in inherited-FD gaps.
            record.windows.dedup_by(|next, previous| {
                if previous.directions == next.directions && next.first <= previous.last {
                    previous.last = previous.last.max(next.last);
                    true
                } else {
                    false
                }
            });
            self.windows += record.windows.len();
            self.namespaces.insert(key.namespace);
            if !key.local.ip().is_unspecified() {
                self.addresses.insert((key.namespace, key.local.ip()));
            }
            let candidates = self
                .tuples
                .entry((key.namespace, key.protocol, key.local.port(), key.remote))
                .or_insert_with(|| Some(Vec::new()));
            if let Some(keys) = candidates {
                if keys.len() >= MAX_CANDIDATES {
                    self.limited = true;
                    *candidates = None;
                } else {
                    keys.push(key.clone());
                }
            }
        }
        for (&(namespace, socket), lifetime) in &self.lifetimes {
            if let Some((local, inode)) = lifetime.binding {
                self.bindings_limited |= !Self::index_binding(
                    &mut self.bindings,
                    namespace,
                    Binding {
                        socket: Some(socket),
                        inode,
                        local,
                        first: lifetime.first.unwrap_or(0),
                        last: self
                            .closed
                            .get(&(namespace, socket))
                            .copied()
                            .unwrap_or(u64::MAX),
                    },
                );
            }
        }
        // A socket bound before tracing started has no BIND event. Existing
        // inventory evidence must also block lifetime-only guesses among UDP
        // SO_REUSEPORT members, even if their queued packet was never read.
        for socket in inventory
            .sockets
            .iter()
            .filter(|socket| socket.key.protocol == Protocol::Udp)
        {
            self.bindings_limited |= !Self::index_binding(
                &mut self.bindings,
                socket.key.namespace,
                Binding {
                    socket: None,
                    inode: socket.key.inode,
                    local: socket.key.local,
                    first: 0,
                    last: u64::MAX,
                },
            );
        }
        self.limited |= self.bindings_limited || self.bindings.values().any(Option::is_none);
        if self.namespaces.len() > MAX_NAMESPACES {
            self.limited = true;
            self.invalidate(now, "socket namespace limit reached");
        }
    }

    fn index_binding(
        index: &mut HashMap<(u64, u16), Option<Vec<Binding>>>,
        namespace: u64,
        binding: Binding,
    ) -> bool {
        let key = (namespace, binding.local.port());
        if index.len() >= MAX_RECORDS && !index.contains_key(&key) {
            return false;
        }
        let candidates = index
            .entry((namespace, binding.local.port()))
            .or_insert_with(|| Some(Vec::new()));
        if let Some(bindings) = candidates {
            if bindings.len() >= MAX_CANDIDATES {
                *candidates = None;
            } else {
                bindings.push(binding);
            }
        }
        true
    }

    fn competing_udp_binding(
        &self,
        key: &Key,
        record: &Record,
        local: SocketAddr,
        window: TimedBytes,
    ) -> bool {
        if self.bindings_limited {
            return true;
        }
        let Some(candidates) = self.bindings.get(&(key.namespace, local.port())) else {
            return false;
        };
        let Some(candidates) = candidates else {
            return true;
        };
        candidates.iter().any(|binding| {
            binding.socket != Some(key.socket)
                && !(binding.inode != 0 && binding.inode == record.socket.key.inode)
                && (binding.local.ip().is_unspecified() || binding.local.ip() == local.ip())
                && window.last.saturating_add(SLOP) >= binding.first
                && window.first <= binding.last.saturating_add(SLOP)
        })
    }

    pub fn limited(&self) -> bool {
        self.limited
    }

    pub fn suppressed(&self) -> bool {
        self.suppression_reason().is_some()
    }

    pub fn describe_loss(&mut self, details: String) {
        if self.quarantine_reason.as_deref() == Some("socket events lost") && !details.is_empty() {
            self.quarantine_reason = Some(format!("socket events lost: {details}"));
        }
    }

    pub fn suppression_reason(&self) -> Option<&str> {
        if self.unsafe_until > self.updated_at {
            self.quarantine_reason.as_deref()
        } else if self.limited() {
            Some("socket evidence index limit reached")
        } else {
            None
        }
    }

    pub fn namespaces(&self) -> HashSet<u64> {
        self.namespaces.clone()
    }

    pub fn has_address(&self, namespace: u64, address: IpAddr) -> bool {
        self.addresses.contains(&(namespace, canonical_ip(address)))
    }

    pub fn resolve(
        &self,
        namespace: u64,
        protocol: Protocol,
        local: SocketAddr,
        remote: SocketAddr,
        receive: bool,
        window: TimedBytes,
    ) -> Match {
        if window.bytes == 0
            || window.first == 0
            || window.last < window.first
            || window.first <= self.unsafe_until
        {
            return Match::Ambiguous;
        }
        let local = SocketAddr::new(canonical_ip(local.ip()), local.port());
        let remote = SocketAddr::new(canonical_ip(remote.ip()), remote.port());
        let mut candidate: Option<(&Key, &Record)> = None;
        let mut contained = false;
        let mut veto_observed = false;
        let mut examined = 0;
        let Some(candidates) = self
            .tuples
            .get(&(namespace, protocol, local.port(), remote))
        else {
            return Match::Missing;
        };
        let Some(candidates) = candidates else {
            return Match::Ambiguous;
        };
        for key in candidates {
            if !key.local.ip().is_unspecified() && key.local.ip() != local.ip() {
                continue;
            }
            let record = &self.records[key];
            let lifetime_receive_conflict = receive
                && protocol == Protocol::Udp
                && self.competing_udp_binding(key, record, local, window);
            for direction in 0..=3 {
                // Windows are sorted and coalesced independently by direction.
                // Binary search avoids rescanning a busy socket's full history
                // for every captured packet; suspiciously dense matches stop.
                let from = record
                    .windows
                    .partition_point(|observed| observed.directions < direction);
                let to = record
                    .windows
                    .partition_point(|observed| observed.directions <= direction);
                let windows = &record.windows[from..to];
                let from = windows
                    .partition_point(|observed| observed.last.saturating_add(SLOP) < window.first);
                let to = windows
                    .partition_point(|observed| observed.first <= window.last.saturating_add(SLOP));
                let to = to.max(from);
                let lifetime = record.lifetime.map(|mut observed| {
                    if lifetime_receive_conflict {
                        observed.directions = 0;
                    }
                    observed
                });
                let lifetime = lifetime
                    .as_ref()
                    .filter(|observed| observed.directions == direction);
                examined += to - from + usize::from(lifetime.is_some());
                if examined > MAX_CANDIDATES {
                    return Match::Ambiguous;
                }
                for observed in windows[from..to].iter().chain(lifetime) {
                    let end = record.closed.unwrap_or(observed.last).min(observed.last);
                    // Clock uncertainty widens conflicts, never positive evidence.
                    if observed.first > end
                        || window.last.saturating_add(SLOP) < observed.first
                        || window.first > end.saturating_add(SLOP)
                    {
                        continue;
                    }
                    if record.closed_conflict {
                        return Match::Ambiguous;
                    }
                    veto_observed |= lifetime_receive_conflict || record.closed.is_some();
                    if let Some((previous, _)) = candidate {
                        if previous.owner != key.owner
                            || previous.socket != key.socket
                            || previous.process_started_ns != key.process_started_ns
                        {
                            return Match::Ambiguous;
                        }
                    } else {
                        candidate = Some((key, record));
                    }
                    if window.first >= observed.first
                        && window.last <= end
                        && observed.directions & if receive { 2 } else { 1 } != 0
                    {
                        contained = true;
                    }
                }
            }
        }
        match candidate {
            Some((_, record)) if contained => Match::Owned(record.socket.clone()),
            Some((_, record)) if !veto_observed => Match::Observed(record.socket.clone()),
            Some(_) => Match::Ambiguous,
            None => Match::Missing,
        }
    }
}
fn address(family: u16, bytes: [u8; 16], port: u16) -> Option<SocketAddr> {
    let ip = match i32::from(family) {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(bytes)),
        _ => return None,
    };
    Some(SocketAddr::new(canonical_ip(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(pid: u32, id: u64, start: u64, end: u64) -> Event {
        Event {
            tgid: pid,
            socket_id: id,
            started_ns: start,
            timestamp_ns: end,
            process_start_ns: 1_000_000_000,
            netns: 1,
            family: libc::AF_INET as u16,
            protocol: 17,
            local_port: 1234,
            remote_port: 80,
            kind: 1,
            local_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            remote_addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..Event::default()
        }
    }
    fn resolve(owners: &Owners, first: u64, last: u64) -> Match {
        owners.resolve(
            1,
            Protocol::Udp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            false,
            TimedBytes {
                bytes: 42,
                first,
                last,
            },
        )
    }
    #[test]
    fn closed_before_poll_is_still_owned() {
        let mut o = Owners::default();
        let e = event(7, 8, 10_000_000, 11_000_000);
        let close = Event {
            kind: 4,
            timestamp_ns: 12_000_000,
            ..e
        };
        o.update(vec![e, close], 0, 20_000_000, &Inventory::new());
        assert!(
            matches!(resolve(&o,10_500_000,10_600_000),Match::Owned(s) if s.owner().unwrap().identity.pid==7)
        );
        assert!(matches!(
            resolve(&o, 14_000_000, 15_000_000),
            Match::Missing
        ));
    }
    #[test]
    fn reuse_spanning_batch_and_lost_events_are_not_guessed() {
        let mut o = Owners::default();
        let a = event(7, 8, 10_000_000, 11_000_000);
        let close = Event {
            kind: 4,
            timestamp_ns: 12_000_000,
            ..a
        };
        let b = event(9, 10, 20_000_000, 21_000_000);
        o.update(vec![a, close, b], 0, 22_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&o, 10_000_000, 21_000_000),
            Match::Ambiguous
        ));
        assert!(
            matches!(resolve(&o,20_500_000,21_000_000),Match::Owned(s) if s.owner().unwrap().identity.pid==9)
        );
        o.update(vec![], 1, 22_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&o, 23_000_000, 24_000_000),
            Match::Ambiguous
        ));
    }
    #[test]
    fn a_prior_actor_does_not_own_future_packets_or_unobserved_gaps() {
        let mut owners = Owners::default();
        let first = event(7, 8, 10_000_000, 11_000_000);
        let later = Event {
            started_ns: 20_000_000,
            timestamp_ns: 21_000_000,
            ..first
        };
        owners.update(vec![first, later], 0, 22_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 10_500_000, 10_600_000),
            Match::Owned(_)
        ));
        assert!(matches!(
            resolve(&owners, 15_000_000, 16_000_000),
            Match::Missing
        ));
        assert!(matches!(
            resolve(&owners, 10_500_000, 20_500_000),
            Match::Observed(_)
        ));
        assert!(matches!(
            resolve(&owners, 25_000_000, 26_000_000),
            Match::Missing
        ));
        // A timestamp just outside a syscall is uncertain, never expanded
        // into positive evidence by the pcap clock tolerance.
        assert!(matches!(
            resolve(&owners, 9_500_000, 10_500_000),
            Match::Observed(_)
        ));
        assert!(matches!(
            resolve(&owners, 20_500_000, 21_500_000),
            Match::Observed(_)
        ));
    }

    #[test]
    fn overlapping_shared_or_inherited_socket_actors_conflict() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let inheritor = Event {
            tgid: 9,
            started_ns: 12_000_000,
            timestamp_ns: 16_000_000,
            ..first
        };
        for events in [vec![first, inheritor], vec![inheritor, first]] {
            let mut owners = Owners::default();
            owners.update(events, 0, 20_000_000, &Inventory::new());
            assert!(matches!(
                resolve(&owners, 12_500_000, 13_000_000),
                Match::Ambiguous
            ));
            assert!(matches!(
                resolve(&owners, 10_000_000, 16_000_000),
                Match::Ambiguous
            ));
        }
    }

    #[test]
    fn pid_reuse_conflicts_even_within_one_proc_clock_tick() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let reused = Event {
            process_start_ns: first.process_start_ns + 1,
            ..first
        };
        let mut owners = Owners::default();
        owners.update(vec![first, reused], 0, 20_000_000, &Inventory::new());
        assert_eq!(owners.records.len(), 2);
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Ambiguous
        ));
    }

    #[test]
    fn namespaces_keep_identical_tuples_and_socket_ids_separate() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let other = Event {
            netns: 2,
            tgid: 9,
            ..first
        };
        let mut owners = Owners::default();
        owners.update(vec![first, other], 0, 20_000_000, &Inventory::new());
        assert_eq!(owners.namespaces(), HashSet::from([1, 2]));
        assert!(owners.has_address(1, "127.0.0.1".parse().unwrap()));
        assert!(!owners.has_address(3, "127.0.0.1".parse().unwrap()));
        assert!(
            matches!(resolve(&owners, 12_000_000, 13_000_000), Match::Owned(socket) if socket.owner().unwrap().identity.pid == 7)
        );
        let closed = Event {
            kind: 4,
            timestamp_ns: 11_000_000,
            ..other
        };
        owners.update(vec![closed], 0, 20_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Owned(_)
        ));
    }

    #[test]
    fn reordered_close_tombstones_also_handle_unknown_udp_peers() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let close = Event {
            kind: 4,
            flags: 2,
            timestamp_ns: 12_000_000,
            remote_port: 0,
            ..first
        };
        for events in [vec![first, close], vec![close, first]] {
            let mut owners = Owners::default();
            owners.update(events, 0, 20_000_000, &Inventory::new());
            assert!(matches!(
                resolve(&owners, 10_500_000, 11_000_000),
                Match::Owned(_)
            ));
            assert!(matches!(
                resolve(&owners, 14_000_000, 15_000_000),
                Match::Missing
            ));
        }
    }

    #[test]
    fn direction_and_malformed_windows_are_not_guessed() {
        let receive = Event {
            kind: 2,
            ..event(7, 8, 10_000_000, 15_000_000)
        };
        let mut owners = Owners::default();
        owners.update(vec![receive], 0, 20_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Observed(_)
        ));
        assert!(matches!(
            resolve(&owners, 13_000_000, 12_000_000),
            Match::Ambiguous
        ));
        assert!(matches!(resolve(&owners, 0, 13_000_000), Match::Ambiguous));
        assert!(matches!(
            owners.resolve(
                1,
                Protocol::Udp,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
                true,
                TimedBytes {
                    bytes: 42,
                    first: 12_000_000,
                    last: 13_000_000
                }
            ),
            Match::Owned(_)
        ));
    }

    #[test]
    fn losses_and_unreliable_actors_quarantine_even_later_drain_batches() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let mut owners = Owners::default();
        owners.update(vec![first], 1, 20_000_000, &Inventory::new());
        owners.describe_loss("kernel read=1".into());
        assert!(owners.suppressed());
        assert!(!owners.limited());
        assert!(owners.records.is_empty());
        let during = Event {
            started_ns: 21_000_000,
            timestamp_ns: 23_000_000,
            ..first
        };
        owners.update(vec![during], 0, 24_000_000, &Inventory::new());
        assert_eq!(
            owners.suppression_reason(),
            Some("socket events lost: kernel read=1")
        );
        assert!(owners.records.is_empty());
        let after = Event {
            started_ns: 4_000_000_000,
            timestamp_ns: 4_010_000_000,
            ..first
        };
        owners.update(vec![after], 0, 4_020_000_000, &Inventory::new());
        assert_eq!(owners.suppression_reason(), None);
        assert!(matches!(
            resolve(&owners, 4_005_000_000, 4_006_000_000),
            Match::Owned(_)
        ));
        let worker = Event { flags: 1, ..after };
        owners.update(vec![worker], 0, 4_020_000_000, &Inventory::new());
        assert!(owners.suppressed());
        assert!(owners.records.is_empty());
        assert!(matches!(
            resolve(&owners, 4_025_000_000, 4_026_000_000),
            Match::Ambiguous
        ));
    }

    #[test]
    fn record_overflow_preserves_uncertainty_instead_of_evicting_conflicts() {
        let mut owners = Owners::default();
        let events = (1..=MAX_RECORDS as u64 + 1)
            .map(|id| event(7, id, 10_000_000, 15_000_000))
            .collect();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert!(owners.records.is_empty());
        assert_eq!(owners.windows, 0);
        assert!(owners.limited() && owners.suppressed());
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Ambiguous
        ));
    }

    #[test]
    fn expired_and_unknown_events_cannot_resurrect_old_ownership() {
        let first = event(7, 8, 10_000_000, 15_000_000);
        let mut owners = Owners::default();
        owners.update(vec![first], 0, 4_000_000_000, &Inventory::new());
        assert!(owners.records.is_empty());
        owners.update(
            vec![Event { kind: 7, ..first }],
            0,
            20_000_000,
            &Inventory::new(),
        );
        assert!(owners.records.is_empty());
        let flags = Event { flags: 4, ..first };
        owners.update(vec![flags], 0, 20_000_000, &Inventory::new());
        assert!(owners.records.is_empty());
    }
    #[test]
    fn accept_does_not_attribute_pre_accept_packets_to_the_accepting_actor() {
        let mut owners = Owners::default();
        let accepted = Event {
            kind: 5,
            started_ns: 15_000_000,
            timestamp_ns: 15_000_000,
            protocol: 6,
            ..event(7, 8, 10_000_000, 15_000_000)
        };
        owners.update(vec![accepted], 0, 20_000_000, &Inventory::new());
        let result = owners.resolve(
            1,
            Protocol::Tcp,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            true,
            TimedBytes {
                bytes: 42,
                first: 14_000_000,
                last: 15_000_000,
            },
        );
        assert!(matches!(result, Match::Observed(_)));
        assert_eq!(owners.records.len(), 1);
    }
    #[test]
    fn indices_expire_with_evidence_and_bound_namespace_and_tuple_floods() {
        let mut owners = Owners::default();
        let first = event(7, 8, 10_000_000, 15_000_000);
        owners.update(vec![first], 0, 20_000_000, &Inventory::new());
        assert_eq!(owners.tuples.len(), 1);
        assert!(owners.has_address(1, "127.0.0.1".parse().unwrap()));
        owners.update(vec![], 0, 4_000_000_000, &Inventory::new());
        assert!(owners.tuples.is_empty() && owners.namespaces().is_empty());
        assert!(!owners.has_address(1, "127.0.0.1".parse().unwrap()));

        let events = (1..=MAX_NAMESPACES as u32 + 1)
            .map(|namespace| Event {
                netns: namespace,
                ..first
            })
            .collect();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert!(owners.records.is_empty() && owners.namespaces().is_empty());
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Ambiguous
        ));

        let mut owners = Owners::default();
        let events = (1..=MAX_CANDIDATES as u64 + 1)
            .map(|id| Event {
                socket_id: id,
                ..first
            })
            .collect();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert_eq!(owners.tuples.values().next(), Some(&None));
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Ambiguous
        ));
    }

    #[test]
    fn window_index_preserves_directions_and_merges_only_overlaps() {
        let mut owners = Owners::default();
        let first = event(7, 8, 10_000_000, 15_000_000);
        let overlapping = Event {
            started_ns: 14_000_000,
            timestamp_ns: 19_000_000,
            ..first
        };
        let recv = Event {
            kind: 2,
            started_ns: 11_000_000,
            timestamp_ns: 20_000_000,
            ..first
        };
        owners.update(
            vec![overlapping, recv, first],
            0,
            22_000_000,
            &Inventory::new(),
        );
        assert_eq!(owners.windows, 2);
        assert!(matches!(
            resolve(&owners, 12_000_000, 18_000_000),
            Match::Owned(_)
        ));
        assert!(matches!(
            resolve(&owners, 18_000_000, 20_000_000),
            Match::Observed(_)
        ));

        let later = Event {
            started_ns: 25_000_000,
            timestamp_ns: 26_000_000,
            ..first
        };
        owners.update(vec![later], 0, 27_000_000, &Inventory::new());
        assert_eq!(owners.windows, 3);
        assert!(matches!(
            resolve(&owners, 22_000_000, 23_000_000),
            Match::Missing
        ));
    }

    #[test]
    fn many_unrelated_tuples_do_not_enter_a_packet_lookup() {
        let mut owners = Owners::default();
        let first = event(7, 8, 10_000_000, 15_000_000);
        let events = (1..=8192)
            .map(|port| Event {
                local_port: port,
                socket_id: u64::from(port),
                ..first
            })
            .collect();
        owners.update(events, 0, 20_000_000, &Inventory::new());
        assert_eq!(owners.tuples.len(), 8192);
        let tuple = (1, Protocol::Udp, 1234, "127.0.0.1:80".parse().unwrap());
        assert_eq!(owners.tuples[&tuple].as_ref().unwrap().len(), 1);
        assert!(matches!(
            resolve(&owners, 12_000_000, 13_000_000),
            Match::Owned(_)
        ));
    }
    #[test]
    fn closed_single_actor_lifetime_covers_queued_receive_and_syscall_gaps() {
        let mut owners = Owners::default();
        let recv = Event {
            kind: 2,
            ..event(7, 8, 20_000_000, 21_000_000)
        };
        let bind = Event {
            kind: 6,
            flags: 2,
            remote_port: 0,
            started_ns: 10_000_000,
            timestamp_ns: 11_000_000,
            ..recv
        };
        let close = Event {
            kind: 4,
            flags: 2,
            remote_port: 0,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..recv
        };
        let lookup = |owners: &Owners| {
            owners.resolve(
                1,
                Protocol::Udp,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
                true,
                TimedBytes {
                    bytes: 42,
                    first: 15_000_000,
                    last: 16_000_000,
                },
            )
        };
        owners.update(vec![bind, recv], 0, 25_000_000, &Inventory::new());
        assert!(matches!(lookup(&owners), Match::Missing));
        owners.update(vec![close], 0, 35_000_000, &Inventory::new());
        assert!(matches!(lookup(&owners), Match::Owned(_)));
        assert!(matches!(
            resolve(&owners, 25_000_000, 26_000_000),
            Match::Owned(_)
        ));
        assert!(matches!(
            resolve(&owners, 8_000_000, 9_000_000),
            Match::Ambiguous
        ));
        assert!(matches!(
            resolve(&owners, 32_000_000, 33_000_000),
            Match::Missing
        ));
    }

    #[test]
    fn different_binder_or_closer_prevents_closed_lifetime_ownership() {
        let send = event(7, 8, 20_000_000, 21_000_000);
        let bind = Event {
            kind: 6,
            flags: 2,
            remote_port: 0,
            started_ns: 10_000_000,
            timestamp_ns: 11_000_000,
            ..send
        };
        let close = Event {
            kind: 4,
            flags: 2,
            remote_port: 0,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..send
        };
        for events in [
            vec![Event { tgid: 9, ..bind }, send, close],
            vec![
                bind,
                send,
                Event {
                    process_start_ns: close.process_start_ns + 1,
                    ..close
                },
            ],
            vec![close, send, Event { tgid: 9, ..bind }],
        ] {
            let mut owners = Owners::default();
            owners.update(events, 0, 35_000_000, &Inventory::new());
            assert!(matches!(
                resolve(&owners, 20_500_000, 20_600_000),
                Match::Ambiguous
            ));
            assert!(matches!(
                resolve(&owners, 25_000_000, 26_000_000),
                Match::Ambiguous
            ));
        }
    }

    #[test]
    fn close_without_an_observed_begin_cannot_backdate_queued_receive() {
        let recv = Event {
            kind: 2,
            ..event(7, 8, 20_000_000, 21_000_000)
        };
        let close = Event {
            kind: 4,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..recv
        };
        let mut owners = Owners::default();
        owners.update(vec![recv, close], 0, 35_000_000, &Inventory::new());
        assert!(matches!(
            resolve(&owners, 15_000_000, 16_000_000),
            Match::Missing
        ));
        assert!(
            owners
                .records
                .values()
                .all(|record| record.lifetime.is_none())
        );
    }
    #[test]
    fn udp_reuseport_bind_without_recv_vetoes_lifetime_only_rx() {
        let first = event(7, 8, 20_000_000, 21_000_000);
        let bind = Event {
            kind: 6,
            flags: 2,
            remote_port: 0,
            started_ns: 10_000_000,
            timestamp_ns: 11_000_000,
            ..first
        };
        let recv = Event { kind: 2, ..first };
        let competing = Event {
            socket_id: 9,
            tgid: 9,
            started_ns: 12_000_000,
            timestamp_ns: 13_000_000,
            ..bind
        };
        let close = Event {
            kind: 4,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..first
        };
        let mut owners = Owners::default();
        owners.update(
            vec![bind, recv, competing, close],
            0,
            35_000_000,
            &Inventory::new(),
        );
        let lookup = |first, last| {
            owners.resolve(
                1,
                Protocol::Udp,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
                true,
                TimedBytes {
                    bytes: 42,
                    first,
                    last,
                },
            )
        };
        assert!(matches!(lookup(15_000_000, 16_000_000), Match::Ambiguous));
        // Direct evidence of the actual receiving call is still decisive.
        assert!(matches!(lookup(20_500_000, 20_600_000), Match::Owned(_)));
        assert!(matches!(
            resolve(&owners, 15_000_000, 16_000_000),
            Match::Owned(_)
        ));
    }

    #[test]
    fn preexisting_udp_inventory_binding_vetoes_queued_rx_to_another_inode() {
        let first = event(7, 8, 20_000_000, 21_000_000);
        let close = Event {
            kind: 4,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..first
        };
        let mut owners = Owners::default();
        let mut inventory = Inventory::new();
        owners.update(vec![first, close], 0, 35_000_000, &inventory);
        let mut competing = owners.records.values().next().unwrap().socket.clone();
        competing.key.inode = 99;
        competing.key.remote = "0.0.0.0:0".parse().unwrap();
        inventory.sockets.push(competing);
        owners.update(vec![], 0, 36_000_000, &inventory);
        assert!(matches!(
            owners.resolve(
                1,
                Protocol::Udp,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
                true,
                TimedBytes {
                    bytes: 42,
                    first: 25_000_000,
                    last: 26_000_000
                }
            ),
            Match::Ambiguous
        ));
    }

    #[test]
    fn actorless_tcp_birth_requires_accept_and_close_before_queued_rx_is_owned() {
        let accepted = Event {
            protocol: 6,
            kind: 5,
            started_ns: 20_000_000,
            timestamp_ns: 20_000_000,
            ..event(7, 8, 20_000_000, 21_000_000)
        };
        let birth = Event {
            kind: 7,
            flags: 2,
            tgid: 0,
            process_start_ns: 0,
            started_ns: 10_000_000,
            timestamp_ns: 10_000_000,
            local_addr: [0; 16],
            remote_addr: [0; 16],
            ..accepted
        };
        let close = Event {
            kind: 4,
            started_ns: 30_000_000,
            timestamp_ns: 30_000_000,
            ..accepted
        };
        let mut owners = Owners::default();
        let lookup = |owners: &Owners| {
            owners.resolve(
                1,
                Protocol::Tcp,
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
                true,
                TimedBytes {
                    bytes: 42,
                    first: 15_000_000,
                    last: 16_000_000,
                },
            )
        };
        owners.update(vec![birth], 0, 19_000_000, &Inventory::new());
        assert!(matches!(lookup(&owners), Match::Missing));
        owners.update(vec![accepted], 0, 25_000_000, &Inventory::new());
        assert!(matches!(lookup(&owners), Match::Missing));
        owners.update(vec![close], 0, 35_000_000, &Inventory::new());
        assert!(
            matches!(lookup(&owners), Match::Owned(socket) if socket.owner().unwrap().identity.pid == 7)
        );
    }
}
