//! Optional event/namespace/NAT attribution; never an alternate byte source.
use super::{
    LocalView,
    capture::{TimedBytes, monotonic_ns},
    conntrack::{self, Conntrack},
    event_owners::{self, Owners},
    events::Events,
    links, loopback_path,
    packet::{Direction, Flow},
    published_port_proxy, socket_endpoints,
    sockets::{Inventory, ProcessIdentity, Resolution, Socket},
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const MAX_OWNER_INODES: usize = 32_768;

#[derive(Clone, Copy, PartialEq, Eq)]
enum InodeOwner {
    Single(ProcessIdentity),
    Ambiguous,
}

#[derive(Default)]
struct OwnerIndex {
    entries: HashMap<(u64, u64), InodeOwner>,
    limited: bool,
}

impl OwnerIndex {
    fn refresh(&mut self, inventory: &Inventory) {
        self.entries.clear();
        self.limited = false;
        for socket in inventory.sockets.iter().filter(|socket| socket.current) {
            let evidence = match socket.owners.as_slice() {
                [] => continue,
                [owner] => InodeOwner::Single(owner.identity),
                _ => InodeOwner::Ambiguous,
            };
            let key = (socket.key.namespace, socket.key.inode);
            if self.entries.len() >= MAX_OWNER_INODES && !self.entries.contains_key(&key) {
                // Never drop a contradictory holder just to keep the table
                // bounded. Suppress event-only certainty for this refresh.
                self.entries.clear();
                self.limited = true;
                break;
            }
            self.entries
                .entry(key)
                .and_modify(|known| {
                    if *known != evidence {
                        *known = InodeOwner::Ambiguous;
                    }
                })
                .or_insert(evidence);
        }
    }

    fn vetoes(&self, socket: &Socket) -> bool {
        self.limited
            || self
                .entries
                .get(&(socket.key.namespace, socket.key.inode))
                .is_some_and(|evidence| match evidence {
                    InodeOwner::Ambiguous => true,
                    InodeOwner::Single(identity) => {
                        Some(*identity) != socket.owner().map(|owner| owner.identity)
                    }
                })
    }
}

pub(super) struct Extended {
    events: Option<Events>,
    conntrack: Option<Conntrack>,
    owners: Owners,
    sampled_owners: OwnerIndex,
    errors: Vec<String>,
    conntrack_lost: u64,
    pub issues: Vec<String>,
    pub unconfirmed: Cell<bool>,
    veth: HashSet<u32>,
    links_at: Instant,
    links_error: Option<String>,
    pub pending: Vec<Pending>,
}
pub(super) struct Pending {
    pub flow: Flow,
    pub bytes: TimedBytes,
    pub since: Instant,
}
pub(super) enum Result {
    /// Socket, receive direction, duplicate observation, exact socket known.
    Owned(Vec<(Socket, bool, bool, bool)>, Vec<(bool, bool)>),
    Pending,
    Unknown,
}
impl Extended {
    pub fn available(&self) -> bool {
        self.events.is_some() || self.conntrack.is_some()
    }

    pub fn start() -> Self {
        let mut errors = Vec::new();
        let events = Events::start()
            .map_err(|e| errors.push(format!("socket events: {e:#}")))
            .ok();
        let conntrack = Conntrack::start()
            .map_err(|e| errors.push(format!("conntrack: {e:#}")))
            .ok();
        Self {
            events,
            conntrack,
            owners: Owners::default(),
            sampled_owners: OwnerIndex::default(),
            conntrack_lost: 0,
            issues: errors.clone(),
            unconfirmed: Cell::new(false),
            errors,
            veth: HashSet::new(),
            links_at: Instant::now() - Duration::from_secs(3),
            links_error: None,
            pending: Vec::new(),
        }
    }
    pub fn refresh(&mut self, inventory: &Inventory) {
        self.issues.clone_from(&self.errors);
        self.sampled_owners.refresh(inventory);
        if self.sampled_owners.limited {
            self.issues
                .push("socket owner index full; uncertain owners withheld".into());
        }
        if let Some(events) = &self.events {
            let batch = events.drain();
            if let Some(error) = batch.error {
                self.issues.push(format!("socket events: {error}"));
            }
            if batch.lost > 0 {
                self.issues.push(format!(
                    "{} socket events lost; uncertain owners withheld",
                    batch.lost
                ));
            }
            self.owners
                .update(batch.events, batch.lost, monotonic_ns(), inventory);
            if self.owners.suppressed() {
                self.issues
                    .push("socket event evidence incomplete; uncertain owners withheld".into());
            }
        }
        if let Some(ct) = &self.conntrack {
            let view = ct.snapshot();
            if let Some(error) = view.error {
                self.issues.push(format!("conntrack: {error}"));
            } else if !view.ready {
                self.issues
                    .push("conntrack: initial synchronization pending".into());
            }
            if view.lost > self.conntrack_lost {
                self.issues.push(format!(
                    "conntrack: {} synchronization failures",
                    view.lost - self.conntrack_lost
                ));
            }
            self.conntrack_lost = view.lost;
        }
        if self.links_at.elapsed() >= Duration::from_secs(2) {
            match links::veth_indexes() {
                Ok(v) => {
                    self.veth = v;
                    self.links_error = None;
                }
                Err(e) => {
                    self.veth.clear();
                    self.links_error = Some(format!("veth discovery: {e}"));
                }
            }
            self.links_at = Instant::now();
        }
        if let Some(error) = &self.links_error {
            self.issues.push(error.clone());
        }
    }
    pub fn resolve(
        &self,
        flow: &Flow,
        bytes: TimedBytes,
        inventory: &Inventory,
        view: &LocalView,
        allow_partial: bool,
    ) -> Result {
        let Some((source, destination)) = socket_endpoints(flow, false) else {
            return Result::Unknown;
        };
        let translation = self
            .conntrack
            .as_ref()
            .map(|c| c.snapshot().translate(flow.protocol, source, destination));
        self.resolve_with_translation(flow, bytes, inventory, view, allow_partial, translation)
    }

    fn resolve_with_translation(
        &self,
        flow: &Flow,
        bytes: TimedBytes,
        inventory: &Inventory,
        view: &LocalView,
        allow_partial: bool,
        translation: Option<conntrack::Outcome>,
    ) -> Result {
        let Some((source, destination)) = socket_endpoints(flow, false) else {
            return Result::Unknown;
        };
        if matches!(translation, Some(conntrack::Outcome::Ambiguous)) {
            return Result::Unknown;
        }
        let (sender, receiver) = match translation {
            Some(conntrack::Outcome::Translated(t)) => (
                (t.before.source, t.before.destination),
                (t.after.destination, t.after.source),
            ),
            _ => ((source, destination), (destination, source)),
        };
        // Without a current conntrack answer, raw endpoints might be the
        // pre-DNAT address of an unrelated local wildcard listener. A positive
        // socket event can stand on its own; sampled sockets cannot prove that
        // a packet was delivered before/after NAT.
        let sampled_endpoints_proven = matches!(
            translation,
            Some(conntrack::Outcome::Unchanged | conntrack::Outcome::Translated(_))
        );
        let host = inventory.host_namespace();
        let mut namespaces = self.owners.namespaces();
        namespaces.extend(inventory.namespaces().keys().copied());
        let mut results = Vec::new();
        let mut unresolved = Vec::new();
        let mut uncertain = false;
        for (receive, (local, remote)) in [(false, sender), (true, receiver)] {
            let candidates: Vec<_> =
                namespaces
                    .iter()
                    .copied()
                    .filter(|ns| {
                        if *ns == host {
                            view.is_local(local.ip())
                        } else {
                            !loopback_path(flow, view)
                                && !local.ip().is_loopback()
                                && (inventory.namespaces().get(ns).is_some_and(|n| {
                                    n.id == *ns && n.addresses.contains(&local.ip())
                                }) || self.owners.has_address(*ns, local.ip()))
                        }
                    })
                    .collect();
            if candidates.len() > 1 {
                // Ambiguity at one endpoint must not erase certain evidence
                // for the other endpoint. Only suppress the unknown copy from
                // All when every possible namespace identifies it as duplicate.
                let lower = candidates
                    .iter()
                    .all(|namespace| self.lower(*namespace, host, flow, local.ip(), view, receive));
                unresolved.push((receive, lower));
                continue;
            }
            let Some(namespace) = candidates.first().copied() else {
                continue;
            };
            let evidence =
                self.owners
                    .resolve(namespace, flow.protocol, local, remote, receive, bytes);
            let socket = match evidence {
                event_owners::Match::Owned(s) => {
                    // Existing shared/contradictory descriptor evidence vetoes
                    // a single actor event, rather than silently choosing it.
                    if self.sampled_owners.vetoes(&s) {
                        None
                    } else {
                        Some((s, true))
                    }
                }
                event_owners::Match::Ambiguous => {
                    uncertain = true;
                    None
                }
                event_owners::Match::Observed(observed) => {
                    // Events identify one possible actor but do not cover this
                    // packet's timestamp. Current descriptor evidence can
                    // corroborate that exact still-open socket, never a reused
                    // inode, a different process or an unproven NAT endpoint.
                    match inventory.resolve_in(namespace, flow.protocol, local, remote) {
                        Resolution::Owned(socket)
                            if sampled_endpoints_proven
                                && socket.current
                                && socket.key.namespace == observed.key.namespace
                                && socket.key.inode != 0
                                && socket.key.inode == observed.key.inode
                                && socket.owner().map(|owner| owner.identity)
                                    == observed.owner().map(|owner| owner.identity)
                                && !self.sampled_owners.vetoes(&observed) =>
                        {
                            Some((socket.clone(), true))
                        }
                        _ => {
                            uncertain = true;
                            None
                        }
                    }
                }
                event_owners::Match::Missing if !sampled_endpoints_proven => {
                    uncertain = true;
                    None
                }
                event_owners::Match::Missing => {
                    match inventory.resolve_in(namespace, flow.protocol, local, remote) {
                        Resolution::Owned(s) if !published_port_proxy(flow, s, view) => {
                            Some((s.clone(), true))
                        }
                        Resolution::Process(s) if !published_port_proxy(flow, s, view) => {
                            Some((s.clone(), false))
                        }
                        Resolution::Pending | Resolution::Missing => {
                            uncertain = true;
                            None
                        }
                        _ => None,
                    }
                }
            };
            let lower = self.lower(namespace, host, flow, local.ip(), view, receive);
            if let Some((socket, connection_known)) = socket {
                results.push((socket, receive, lower, connection_known));
            } else {
                unresolved.push((receive, lower));
            }
        }
        if allow_partial
            && !unresolved.is_empty()
            && matches!(translation, Some(conntrack::Outcome::Missing))
        {
            self.unconfirmed.set(true);
        }
        if uncertain && !allow_partial {
            Result::Pending
        } else if !results.is_empty() || !unresolved.is_empty() {
            Result::Owned(results, unresolved)
        } else if uncertain
            || matches!(
                translation,
                Some(conntrack::Outcome::Missing | conntrack::Outcome::Unavailable)
            )
        {
            Result::Pending
        } else {
            Result::Unknown
        }
    }
    fn lower(
        &self,
        namespace: u64,
        host: u64,
        flow: &Flow,
        local: std::net::IpAddr,
        view: &LocalView,
        receive: bool,
    ) -> bool {
        if namespace == host {
            view.lower_observation(flow.interface_index, local)
        } else {
            !(self.veth.contains(&flow.interface_index)
                && matches!(
                    (receive, flow.direction),
                    (true, Direction::Outgoing) | (false, Direction::Incoming)
                ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{
        events::Event,
        packet::Protocol,
        sockets::{Owner, ProcessIdentity, SocketKey},
    };
    use std::net::{Ipv4Addr, SocketAddr};

    fn extended() -> Extended {
        Extended {
            events: None,
            conntrack: None,
            owners: Owners::default(),
            sampled_owners: OwnerIndex::default(),
            errors: Vec::new(),
            conntrack_lost: 0,
            issues: Vec::new(),
            unconfirmed: Cell::new(false),
            veth: HashSet::from([100, 101]),
            links_at: Instant::now(),
            links_error: None,
            pending: Vec::new(),
        }
    }
    fn packet(source: &str, destination: &str, index: u32, direction: Direction) -> Flow {
        let source: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        Flow {
            source: source.ip(),
            destination: destination.ip(),
            source_port: Some(source.port()),
            destination_port: Some(destination.port()),
            protocol: Protocol::Udp,
            interface_index: index,
            direction,
        }
    }
    fn bytes() -> TimedBytes {
        TimedBytes {
            bytes: 1024,
            first: 15_000_000,
            last: 15_000_000,
        }
    }
    fn view() -> LocalView {
        let mut view = LocalView::default();
        view.addresses.insert("192.0.2.1".parse().unwrap());
        view.loopback.insert(1);
        view
    }
    fn listener(inventory: &Inventory, inode: u64) -> Socket {
        Socket {
            key: SocketKey {
                namespace: inventory.host_namespace(),
                inode,
                protocol: Protocol::Udp,
                local: "0.0.0.0:8080".parse().unwrap(),
                remote: "0.0.0.0:0".parse().unwrap(),
            },
            state: "BOUND".into(),
            uid: 1000,
            owners: vec![Owner {
                identity: ProcessIdentity {
                    pid: 42,
                    start_time: 100,
                },
                user: "test".into(),
                name: "unrelated-service".into(),
            }],
            observed: Instant::now(),
            current: true,
            ipv6_only: None,
        }
    }
    fn actor(namespace: u64, id: u64, local: &str, remote: &str, receive: bool) -> Event {
        let local: SocketAddr = local.parse().unwrap();
        let remote: SocketAddr = remote.parse().unwrap();
        let mut local_addr = [0; 16];
        let mut remote_addr = [0; 16];
        local_addr[..4]
            .copy_from_slice(&local.ip().to_string().parse::<Ipv4Addr>().unwrap().octets());
        remote_addr[..4].copy_from_slice(
            &remote
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .unwrap()
                .octets(),
        );
        Event {
            netns: namespace.try_into().unwrap(),
            inode: id,
            socket_id: id,
            tgid: id as u32,
            process_start_ns: 1_000_000_000,
            started_ns: 10_000_000,
            timestamp_ns: 20_000_000,
            family: libc::AF_INET as u16,
            protocol: 17,
            local_addr,
            remote_addr,
            local_port: local.port(),
            remote_port: remote.port(),
            kind: if receive { 2 } else { 1 },
            ..Event::default()
        }
    }

    #[test]
    fn missing_or_lost_conntrack_cannot_credit_a_pre_dnat_host_listener() {
        let mut inventory = Inventory::new();
        inventory.sockets.push(listener(&inventory, 10));
        inventory.rebuild_index();
        let extended = extended();
        let flow = packet(
            "198.51.100.2:40000",
            "192.0.2.1:8080",
            2,
            Direction::Incoming,
        );
        for state in [
            None,
            Some(conntrack::Outcome::Missing),
            Some(conntrack::Outcome::Unavailable),
        ] {
            assert!(matches!(
                extended.resolve_with_translation(
                    &flow,
                    bytes(),
                    &inventory,
                    &view(),
                    false,
                    state
                ),
                Result::Pending
            ));
            let Result::Owned(owners, unknown) =
                extended.resolve_with_translation(&flow, bytes(), &inventory, &view(), true, state)
            else {
                panic!("expired bytes must remain unknown");
            };
            assert!(owners.is_empty());
            assert_eq!(unknown, vec![(true, false)]);
        }
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("confirmed local traffic should resolve");
        };
        assert_eq!(owners.len(), 1);
        assert!(owners[0].3);
        assert!(unknown.is_empty());
    }

    #[test]
    fn queued_receive_needs_matching_current_descriptor_and_conntrack() {
        let mut inventory = Inventory::new();
        inventory.sockets.push(listener(&inventory, 42));
        inventory.rebuild_index();
        let mut extended = extended();
        extended.owners.update(
            vec![actor(
                inventory.host_namespace(),
                42,
                "192.0.2.1:8080",
                "198.51.100.2:40000",
                true,
            )],
            0,
            21_000_000,
            &inventory,
        );
        extended.sampled_owners.refresh(&inventory);
        let flow = packet(
            "198.51.100.2:40000",
            "192.0.2.1:8080",
            2,
            Direction::Incoming,
        );
        let queued = TimedBytes {
            bytes: 1024,
            first: 9_500_000,
            last: 9_500_000,
        };
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            queued,
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("current descriptor must corroborate the observed actor");
        };
        assert_eq!(owners.len(), 1);
        assert!(unknown.is_empty());
        assert!(matches!(
            extended.resolve_with_translation(
                &flow,
                queued,
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unavailable),
            ),
            Result::Pending
        ));
        inventory.sockets[0].owners[0].identity.pid = 99;
        extended.sampled_owners.refresh(&inventory);
        assert!(matches!(
            extended.resolve_with_translation(
                &flow,
                queued,
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unchanged),
            ),
            Result::Pending
        ));
    }

    #[test]
    fn reuseport_ties_credit_the_process_without_inventing_a_connection() {
        let mut inventory = Inventory::new();
        inventory.sockets = vec![listener(&inventory, 10), listener(&inventory, 11)];
        inventory.rebuild_index();
        let flow = packet(
            "198.51.100.2:40000",
            "192.0.2.1:8080",
            2,
            Direction::Incoming,
        );
        let Result::Owned(owners, _) = extended().resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("process should be certain");
        };
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].0.owner().unwrap().identity.pid, 42);
        assert!(!owners[0].3);
    }

    #[test]
    fn container_to_container_observations_count_each_boundary_once() {
        let inventory = Inventory::new();
        let mut extended = extended();
        extended.owners.update(
            vec![
                actor(
                    inventory.host_namespace() + 1,
                    200,
                    "172.18.0.2:40000",
                    "172.18.0.3:8080",
                    false,
                ),
                actor(
                    inventory.host_namespace() + 2,
                    300,
                    "172.18.0.3:8080",
                    "172.18.0.2:40000",
                    true,
                ),
            ],
            0,
            21_000_000,
            &inventory,
        );
        for (index, direction, sender_lower, receiver_lower) in [
            (100, Direction::Incoming, false, true),
            (101, Direction::Outgoing, true, false),
            (2, Direction::Incoming, true, true),
        ] {
            let flow = packet("172.18.0.2:40000", "172.18.0.3:8080", index, direction);
            let Result::Owned(owners, unknown) = extended.resolve_with_translation(
                &flow,
                bytes(),
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unchanged),
            ) else {
                panic!("event evidence should resolve");
            };
            assert_eq!(owners.len(), 2);
            assert_eq!((owners[0].1, owners[0].2), (false, sender_lower));
            assert_eq!((owners[1].1, owners[1].2), (true, receiver_lower));
            assert!(unknown.is_empty());
        }
    }

    #[test]
    fn dnat_uses_receiver_translated_endpoints_and_preserves_selected_physical_link() {
        let inventory = Inventory::new();
        let mut extended = extended();
        extended.owners.update(
            vec![actor(
                inventory.host_namespace() + 1,
                200,
                "172.18.0.2:80",
                "198.51.100.2:40000",
                true,
            )],
            0,
            21_000_000,
            &inventory,
        );
        let flow = packet(
            "198.51.100.2:40000",
            "192.0.2.1:8080",
            2,
            Direction::Incoming,
        );
        let translation = conntrack::Translation {
            before: conntrack::Tuple {
                protocol: Protocol::Udp,
                source: "198.51.100.2:40000".parse().unwrap(),
                destination: "192.0.2.1:8080".parse().unwrap(),
            },
            after: conntrack::Tuple {
                protocol: Protocol::Udp,
                source: "198.51.100.2:40000".parse().unwrap(),
                destination: "172.18.0.2:80".parse().unwrap(),
            },
            zones: (0, 0),
        };
        let Result::Owned(owners, _) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Translated(translation)),
        ) else {
            panic!("container event should resolve through DNAT");
        };
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].0.owner().unwrap().identity.pid, 200);
        assert!(owners[0].1 && owners[0].2);
    }

    #[test]
    fn ambiguous_namespace_addresses_and_nonlocal_wildcards_are_not_guessed() {
        let mut inventory = Inventory::new();
        inventory.sockets.push(listener(&inventory, 10));
        inventory.rebuild_index();
        let mut extended = extended();
        let flow = packet(
            "198.51.100.2:40000",
            "172.18.0.2:8080",
            100,
            Direction::Outgoing,
        );
        assert!(matches!(
            extended.resolve_with_translation(
                &flow,
                bytes(),
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unchanged)
            ),
            Result::Unknown
        ));
        extended.owners.update(
            vec![
                actor(
                    inventory.host_namespace() + 1,
                    200,
                    "172.18.0.2:8080",
                    "198.51.100.2:40000",
                    true,
                ),
                actor(
                    inventory.host_namespace() + 2,
                    300,
                    "172.18.0.2:8080",
                    "198.51.100.3:40000",
                    true,
                ),
            ],
            0,
            21_000_000,
            &inventory,
        );
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            false,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("ambiguous receiver must remain unknown");
        };
        assert!(owners.is_empty());
        assert_eq!(unknown, vec![(true, false)]);
    }

    #[test]
    fn partial_loopback_ownership_keeps_the_other_endpoints_bytes_after_defer() {
        let inventory = Inventory::new();
        let mut extended = extended();
        extended.owners.update(
            vec![actor(
                inventory.host_namespace(),
                200,
                "127.0.0.1:40000",
                "127.0.0.1:8080",
                false,
            )],
            0,
            21_000_000,
            &inventory,
        );
        let flow = packet("127.0.0.1:40000", "127.0.0.1:8080", 1, Direction::Incoming);
        assert!(matches!(
            extended.resolve_with_translation(
                &flow,
                bytes(),
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unchanged)
            ),
            Result::Pending
        ));
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            true,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("partial result expected after timeout");
        };
        assert_eq!(owners.len(), 1);
        assert!(!owners[0].1);
        assert_eq!(unknown, vec![(true, false)]);
    }

    #[test]
    fn ambiguous_receiver_does_not_erase_certain_sender_evidence() {
        let inventory = Inventory::new();
        let mut extended = extended();
        let host = inventory.host_namespace();
        extended.owners.update(
            vec![
                actor(host, 200, "127.0.0.1:40000", "127.0.0.1:8080", false),
                actor(host, 300, "127.0.0.1:8080", "127.0.0.1:40000", true),
                actor(host, 301, "127.0.0.1:8080", "127.0.0.1:40000", true),
            ],
            0,
            21_000_000,
            &inventory,
        );
        let flow = packet("127.0.0.1:40000", "127.0.0.1:8080", 1, Direction::Incoming);
        assert!(matches!(
            extended.resolve_with_translation(
                &flow,
                bytes(),
                &inventory,
                &view(),
                false,
                Some(conntrack::Outcome::Unchanged)
            ),
            Result::Pending
        ));
        let Result::Owned(owners, unknown) = extended.resolve_with_translation(
            &flow,
            bytes(),
            &inventory,
            &view(),
            true,
            Some(conntrack::Outcome::Unchanged),
        ) else {
            panic!("certain sender must survive receiver ambiguity");
        };
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].0.owner().unwrap().identity.pid, 200);
        assert!(!owners[0].1);
        assert_eq!(unknown, vec![(true, false)]);
    }
    #[test]
    fn owner_index_combines_current_holders_and_clears_stale_vetoes() {
        let mut inventory = Inventory::new();
        let socket = listener(&inventory, 42);
        let mut index = OwnerIndex::default();
        inventory.sockets.push(socket.clone());
        index.refresh(&inventory);
        assert!(!index.vetoes(&socket));
        let mut conflicting = socket.clone();
        conflicting.owners[0].identity.start_time += 1;
        inventory.sockets.push(conflicting.clone());
        index.refresh(&inventory);
        assert!(index.vetoes(&socket) && index.vetoes(&conflicting));
        inventory.sockets[1].current = false;
        index.refresh(&inventory);
        assert!(!index.vetoes(&socket));
        assert!(index.vetoes(&conflicting));
        inventory.sockets[1].current = true;
        inventory.sockets[1].key.namespace += 1;
        index.refresh(&inventory);
        assert!(!index.vetoes(&socket));
        inventory.sockets.clear();
        index.refresh(&inventory);
        assert!(!index.vetoes(&conflicting));
    }

    #[test]
    fn owner_index_rejects_shared_descriptors_and_overflow_without_guessing() {
        let mut inventory = Inventory::new();
        let socket = listener(&inventory, 42);
        let mut shared = socket.clone();
        shared.owners.push(Owner {
            identity: ProcessIdentity {
                pid: 99,
                start_time: 100,
            },
            ..shared.owners[0].clone()
        });
        inventory.sockets.push(shared);
        let mut index = OwnerIndex::default();
        index.refresh(&inventory);
        assert!(index.vetoes(&socket));
        inventory.sockets = (0..=MAX_OWNER_INODES as u64)
            .map(|inode| {
                let mut value = socket.clone();
                value.key.inode = inode;
                value
            })
            .collect();
        index.refresh(&inventory);
        assert!(index.limited && index.entries.is_empty());
        assert!(index.vetoes(&socket));
    }
}
