//! Real Linux kernel counters and best-effort, header-only process attribution.

#[path = "capture.rs"]
mod capture;
#[path = "packet.rs"]
mod packet;
#[path = "sockets.rs"]
mod sockets;

use crate::i18n::Lang;
use crate::model::{CaptureNote, CaptureStatus, ConnectionRow, Interface, ProcessRow, Snapshot};
use anyhow::{Context, Result, bail};
use packet::{Direction, Flow};
use sockets::{Inventory, Owner, ProcessIdentity, Resolution, Socket, SocketKey, canonical_ip};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_PROCESS_COUNTERS: usize = 16_384;
const MAX_CONNECTION_COUNTERS: usize = 32_768;
/// Each link can have a lower-device entry besides its own (see `Link`).
const MAX_INTERFACE_COUNTERS: usize = 512;
const COUNTER_RETENTION: Duration = Duration::from_secs(300);
const RECENT_TRAFFIC: Duration = Duration::from_secs(3);
/// Captured flows are matched to sockets on this cadence, independent of the
/// UI refresh interval, so closed and short-lived sockets are still known.
const ATTRIBUTION_TICK: Duration = Duration::from_millis(250);
const MAX_ATTRIBUTION_WAIT: Duration = Duration::from_millis(500);
/// Flows whose socket awaits its first owner scan are retried until that scan
/// can have run: at least one second, longer while the cost-dependent owner
/// scan gap is longer, and never past the periodic full rescan.
const MAX_DEFERRED: usize = 4_096;
const MIN_DEFER: Duration = Duration::from_secs(1);
const MAX_DEFER: Duration = Duration::from_secs(6);
/// Bridge, bond and VLAN membership is reread at most this often by the
/// background worker, and whenever the set of links changes.
const TOPOLOGY_REFRESH: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
struct KernelInterface {
    info: Interface,
    index: u32,
    addresses: Vec<IpAddr>,
    loopback: bool,
    topology: LinkTopology,
}

/// Stacked-device relations from sysfs: a bridge port or bond slave has a
/// master; VLAN, macvlan and bond devices are uppers of their lower links.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinkTopology {
    master: bool,
    uppers: Vec<u32>,
}

/// The capture link of counted bytes. `lower` marks an observation on a
/// bridge port, bond slave or VLAN parent of host traffic that the upper
/// device also captures. All-interface totals skip those duplicates;
/// selecting that link still shows them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Link {
    index: u32,
    lower: bool,
}

impl Link {
    fn plain(index: u32) -> Self {
        Self {
            index,
            lower: false,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Bytes {
    rx: u64,
    tx: u64,
}

impl Bytes {
    fn add(&mut self, other: Self) {
        self.rx = self.rx.saturating_add(other.rx);
        self.tx = self.tx.saturating_add(other.tx);
    }
}

struct Counter {
    bytes: Bytes,
    last_seen: Instant,
}

impl Counter {
    fn new(now: Instant) -> Self {
        Self {
            bytes: Bytes::default(),
            last_seen: now,
        }
    }

    fn add(&mut self, bytes: Bytes, now: Instant) {
        self.bytes.add(bytes);
        self.last_seen = now;
    }
}

struct ProcessCounter {
    owner: Owner,
    counter: Counter,
}

struct ConnectionCounter {
    socket: Socket,
    counter: Counter,
}

type ProcessCounterKey = (Link, ProcessIdentity);
type ConnectionCounterKey = (Link, SocketKey, ProcessIdentity);

/// Bytes attributed since the previous snapshot; rates divide these by the
/// snapshot interval.
#[derive(Default)]
struct Deltas {
    processes: HashMap<ProcessCounterKey, Bytes>,
    connections: HashMap<ConnectionCounterKey, Bytes>,
    unknown: HashMap<Link, Bytes>,
}

/// Capture problems observed since the previous snapshot.
#[derive(Default)]
struct IntervalStatus {
    dropped: u64,
    overflow: u64,
    unsupported: u64,
    truncated: u64,
}

#[derive(Default)]
struct Counters {
    processes: HashMap<ProcessCounterKey, ProcessCounter>,
    connections: HashMap<ConnectionCounterKey, ConnectionCounter>,
    unattributed: HashMap<Link, Counter>,
    /// A counter bound rejected bytes since the previous snapshot.
    limit_hit: bool,
}

/// Bytes of one flow direction awaiting a retry, merged across passes.
struct Deferred {
    bytes: u64,
    since: Instant,
}

/// Socket inventory, capture session and counters. Shared between snapshot
/// requests and the background attribution worker.
struct Attribution {
    inventory: Inventory,
    capture: Option<capture::Capture>,
    counters: Counters,
    deltas: Deltas,
    status: IntervalStatus,
    capture_error: Option<String>,
    deferred: HashMap<(Flow, bool), Deferred>,
    worker_error: Option<String>,
}

fn lock(shared: &Mutex<Attribution>) -> MutexGuard<'_, Attribution> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stops and joins the background attribution thread on drop.
struct Worker {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    /// Started from the sampling thread, so it inherits exactly that thread's
    /// capabilities and NO_NEW_PRIVS: in the helper only the /proc read
    /// capabilities, never the capture capability.
    fn start(shared: Arc<Mutex<Attribution>>) -> Result<Self> {
        let (stop, stopped) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("nettop-attrib".to_string())
            .spawn(move || {
                let mut wait = ATTRIBUTION_TICK;
                let mut topology = TopologyCache::default();
                loop {
                    match stopped.recv_timeout(wait) {
                        Err(RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                    let started = Instant::now();
                    let interfaces = local_interfaces(&mut topology);
                    lock(&shared).tick(&interfaces);
                    // Back off on hosts where one pass is expensive.
                    wait = (started.elapsed() * 4).clamp(ATTRIBUTION_TICK, MAX_ATTRIBUTION_WAIT);
                }
            })
            .context("starting socket attribution worker")?;
        Ok(Self {
            stop: Some(stop),
            handle: Some(handle),
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A collector owns one capture worker; dropping it closes its own pcap session.
pub struct Collector {
    started: Instant,
    last_sample: Instant,
    previous_interfaces: HashMap<String, (u32, u64, u64)>,
    /// Why capture is off from the start, if it is.
    capture_note: Option<CaptureNote>,
    /// The worker starts on the first snapshot, from the sampling thread.
    start_worker: bool,
    // Declared before `shared` so the worker stops before the capture closes.
    worker: Option<Worker>,
    shared: Arc<Mutex<Attribution>>,
}

impl Collector {
    pub fn new(capture_enabled: bool) -> Result<Self> {
        let started = Instant::now();
        let mut inventory = Inventory::new();
        inventory.refresh();
        let interfaces = read_interfaces()?;
        let previous_interfaces = interfaces
            .iter()
            .map(|interface| {
                (
                    interface.info.name.clone(),
                    (
                        interface.index,
                        interface.info.rx_bytes,
                        interface.info.tx_bytes,
                    ),
                )
            })
            .collect();
        let last_sample = Instant::now();
        let (capture, capture_note) = if capture_enabled {
            match capture::Capture::start() {
                Ok(capture) => (Some(capture), None),
                Err(error) => {
                    let note = match error.downcast_ref::<capture::StartError>() {
                        Some(known) => known.0.clone(),
                        None => CaptureNote::Unavailable {
                            detail: format!("{error:#}"),
                        },
                    };
                    (None, Some(note))
                }
            }
        } else {
            (None, Some(CaptureNote::Disabled))
        };
        let start_worker = capture.is_some();
        Ok(Self {
            started,
            last_sample,
            previous_interfaces,
            capture_note,
            start_worker,
            worker: None,
            shared: Arc::new(Mutex::new(Attribution::new(inventory, capture))),
        })
    }

    /// `None` means all captured interfaces, including virtual links. The status
    /// warns about duplicate observations across host bridges and veth devices.
    pub fn sample(&mut self, interface: Option<&str>) -> Result<Snapshot> {
        if std::mem::take(&mut self.start_worker) {
            // Started once; on failure, attribution falls back to snapshots.
            match Worker::start(Arc::clone(&self.shared)) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => lock(&self.shared).worker_error = Some(format!("{error:#}")),
            }
        }
        let mut interfaces = read_interfaces()?;
        // Hot unplug is an empty scope, never a silent switch to all devices.
        // The CLI validates an explicit initial selection itself.
        let selected = interface.map(|name| {
            interfaces
                .iter()
                .find(|candidate| candidate.info.name == name)
                .map_or(u32::MAX, |candidate| candidate.index)
        });
        let missing_interface = selected == Some(u32::MAX);
        let mut state = lock(&self.shared);
        // Attribute everything captured up to now; the background worker has
        // already handled earlier packets against then-current sockets.
        state.tick(&interfaces);
        let now = Instant::now();
        let interval = now
            .duration_since(self.last_sample)
            .as_secs_f64()
            .max(0.001);
        for current in &mut interfaces {
            if let Some(&(old_index, rx, tx)) = self.previous_interfaces.get(&current.info.name)
                && old_index == current.index
            {
                current.info.rx_rate = counter_rate(current.info.rx_bytes, rx, interval);
                current.info.tx_rate = counter_rate(current.info.tx_bytes, tx, interval);
            }
        }
        self.previous_interfaces = interfaces
            .iter()
            .map(|current| {
                (
                    current.info.name.clone(),
                    (current.index, current.info.rx_bytes, current.info.tx_bytes),
                )
            })
            .collect();
        self.last_sample = now;
        state.prune(now, &interfaces);
        let deltas = std::mem::take(&mut state.deltas);
        let problems = std::mem::take(&mut state.status);
        let counter_limit = std::mem::take(&mut state.counters.limit_hit);

        let mut status = CaptureStatus {
            active: state.capture.is_some(),
            notes: self.capture_note.iter().cloned().collect(),
            ..CaptureStatus::default()
        };
        if let Some(capture) = &state.capture {
            // Per-interval values: a past burst must not taint later snapshots.
            status.dropped = problems.dropped.saturating_add(problems.overflow);
            status.notes = vec![if interface.is_some() && !capture.interface_indexes {
                status.active = false;
                CaptureNote::NoInterfaceIndexes
            } else if interface.is_none() {
                CaptureNote::AllInterfaces
            } else {
                CaptureNote::Sampled
            }];
            if problems.dropped > 0 {
                status.notes.push(CaptureNote::PcapMissed {
                    packets: problems.dropped,
                });
            }
            if problems.overflow > 0 {
                status.notes.push(CaptureNote::FlowLimit {
                    packets: problems.overflow,
                });
            }
            if problems.unsupported > 0 || problems.truncated > 0 {
                status.notes.push(CaptureNote::Unreadable {
                    unsupported: problems.unsupported,
                    truncated: problems.truncated,
                });
            }
            if let Some(error) = &state.worker_error {
                status.notes.push(CaptureNote::AttributionAtRefresh {
                    error: error.clone(),
                });
            }
            if let Some(error) = &state.capture_error {
                status.active = false;
                status.notes = vec![CaptureNote::Stopped {
                    error: error.clone(),
                }];
            }
        }
        if state.inventory.restricted {
            status.notes.push(CaptureNote::OwnersInaccessible);
        }
        if state.inventory.limited || counter_limit {
            status.notes.push(CaptureNote::CounterLimit);
        }
        if missing_interface {
            status.active = false;
            status.notes = vec![CaptureNote::InterfaceMissing {
                name: interface.unwrap_or_default().to_string(),
            }];
        }
        status.message = Lang::En.capture_status(&status, true).unwrap_or_default();
        let (processes, connections) =
            state.rows(selected, &interfaces, now, interval, &deltas, status.active);
        drop(state);
        Ok(Snapshot {
            elapsed: now.duration_since(self.started).as_secs_f64(),
            interfaces: interfaces
                .into_iter()
                .map(|interface| interface.info)
                .collect(),
            processes,
            connections,
            capture: status,
        })
    }
}

impl Attribution {
    fn new(inventory: Inventory, capture: Option<capture::Capture>) -> Self {
        Self {
            inventory,
            capture,
            counters: Counters::default(),
            deltas: Deltas::default(),
            status: IntervalStatus::default(),
            capture_error: None,
            deferred: HashMap::new(),
            worker_error: None,
        }
    }

    /// Drains the flows captured so far, then refreshes sockets and attributes
    /// the flows while the sockets that carried them are still current or
    /// briefly retained. Draining first keeps the socket tables at least as new
    /// as every packet matched against them; otherwise a socket created
    /// between a refresh and a later drain would have no candidate.
    fn tick(&mut self, interfaces: &[KernelInterface]) {
        let Some(capture) = &self.capture else {
            self.inventory.refresh();
            return;
        };
        let batch = capture.drain();
        let drained = Instant::now();
        self.inventory.refresh();
        let view = LocalView::new(interfaces);
        let now = Instant::now();
        self.status.dropped = self.status.dropped.saturating_add(batch.dropped);
        self.status.overflow = self.status.overflow.saturating_add(batch.overflow);
        self.status.unsupported = self.status.unsupported.saturating_add(batch.unsupported);
        self.status.truncated = self.status.truncated.saturating_add(batch.truncated);
        if batch.error.is_some() {
            self.capture_error = batch.error;
        }
        for ((flow, receive), deferred) in std::mem::take(&mut self.deferred) {
            self.attribute(&flow, receive, deferred.bytes, deferred.since, now, &view);
        }
        for (flow, bytes) in batch.flows {
            let (rx, tx) = traffic_sides(&flow, &view);
            for receive in [false, true] {
                if (receive && rx) || (!receive && tx) {
                    self.attribute(&flow, receive, bytes, drained, now, &view);
                }
            }
        }
        for ((index, direction), untracked) in batch.untracked {
            let bytes = match direction {
                _ if view.loopback.contains(&index) => Bytes {
                    rx: untracked.bytes,
                    tx: untracked.bytes,
                },
                Direction::Incoming => Bytes {
                    rx: untracked.bytes,
                    tx: 0,
                },
                Direction::Outgoing => Bytes {
                    rx: 0,
                    tx: untracked.bytes,
                },
                Direction::Unknown => Bytes::default(),
            };
            self.counters
                .record_unknown(Link::plain(index), bytes, now, &mut self.deltas.unknown);
        }
    }

    /// How long a flow may wait for its socket's owner: until the next owner
    /// scan can have run. Retrying deferred flows is a hash lookup each, so a
    /// longer wait costs bounded memory (`MAX_DEFERRED`), not extra scans.
    fn max_defer(&self) -> Duration {
        (self.inventory.owner_scan_gap() + 2 * MAX_ATTRIBUTION_WAIT).clamp(MIN_DEFER, MAX_DEFER)
    }

    /// `since` is when the bytes were first drained from the capture.
    fn attribute(
        &mut self,
        flow: &Flow,
        receive: bool,
        bytes: u64,
        since: Instant,
        now: Instant,
        view: &LocalView,
    ) {
        let increment = if receive {
            Bytes { rx: bytes, tx: 0 }
        } else {
            Bytes { rx: 0, tx: bytes }
        };
        let endpoints = local_socket_endpoints(flow, receive, view);
        let link = Link {
            index: flow.interface_index,
            lower: endpoints
                .is_some_and(|(local, _)| view.lower_observation(flow.interface_index, local.ip())),
        };
        let resolution = endpoints.map_or(Resolution::Unattributed, |(local, remote)| {
            self.inventory.resolve(flow.protocol, local, remote)
        });
        let defer = match resolution {
            Resolution::Owned(socket) if !published_port_proxy(flow, socket, view) => {
                if self
                    .counters
                    .record_owned(link, socket, true, increment, now, &mut self.deltas)
                {
                    return;
                }
                false
            }
            // Tied sockets of one process (SO_REUSEPORT): the process is
            // known, the individual socket is not.
            Resolution::Process(socket) if !published_port_proxy(flow, socket, view) => {
                if self
                    .counters
                    .record_owned(link, socket, false, increment, now, &mut self.deltas)
                {
                    return;
                }
                false
            }
            // The socket exists, but its owner or IPv6 mode is not known yet.
            Resolution::Pending => true,
            // No socket of a local endpoint matched. A table read before the
            // bytes were drained can lack a just-created socket; retry once
            // the tables are newer. Nonlocal traffic never gets here.
            Resolution::Missing => self
                .inventory
                .refreshed_at()
                .is_none_or(|refreshed| refreshed <= since),
            _ => false,
        };
        if defer && now.saturating_duration_since(since) < self.max_defer() {
            let key = (flow.clone(), receive);
            if let Some(waiting) = self.deferred.get_mut(&key) {
                waiting.bytes = waiting.bytes.saturating_add(bytes);
                waiting.since = waiting.since.min(since);
                return;
            }
            if self.deferred.len() < MAX_DEFERRED {
                self.deferred.insert(key, Deferred { bytes, since });
                return;
            }
        }
        self.counters
            .record_unknown(link, increment, now, &mut self.deltas.unknown);
    }

    fn prune(&mut self, now: Instant, interfaces: &[KernelInterface]) {
        let current_sockets: HashSet<_> = self
            .inventory
            .sockets
            .iter()
            .filter(|socket| socket.current)
            .filter_map(|socket| {
                socket
                    .owner()
                    .map(|owner| (socket.key.clone(), owner.identity))
            })
            .collect();
        let current_processes: HashSet<_> = current_sockets
            .iter()
            .map(|(_, identity)| *identity)
            .collect();
        let links: HashSet<_> = interfaces.iter().map(|interface| interface.index).collect();
        self.counters.processes.retain(|(_, identity), entry| {
            current_processes.contains(identity)
                || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
        });
        self.counters
            .connections
            .retain(|(_, key, identity), entry| {
                current_sockets.contains(&(key.clone(), *identity))
                    || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
            });
        self.counters.unattributed.retain(|link, entry| {
            links.contains(&link.index) || now.duration_since(entry.last_seen) <= COUNTER_RETENTION
        });
    }

    fn rows(
        &self,
        selected: Option<u32>,
        interfaces: &[KernelInterface],
        now: Instant,
        interval: f64,
        deltas: &Deltas,
        rates_available: bool,
    ) -> (Vec<ProcessRow>, Vec<ConnectionRow>) {
        let mut processes: HashMap<ProcessIdentity, ProcessRow> = HashMap::new();
        let mut connections: HashMap<(SocketKey, Option<ProcessIdentity>), ConnectionRow> =
            HashMap::new();
        let mut unknown = ProcessRow {
            pid: None,
            user: "-".to_string(),
            name: "[unattributed]".to_string(),
            ..ProcessRow::default()
        };
        let scope = selected.map(|selected| {
            interfaces
                .iter()
                .find(|interface| interface.index == selected)
        });
        for socket in self
            .inventory
            .sockets
            .iter()
            .filter(|socket| socket.current)
        {
            if !socket_in_scope(socket, scope) {
                continue;
            }
            let owner = socket.owner();
            connections.insert(
                (socket.key.clone(), owner.map(|owner| owner.identity)),
                connection_row(socket, &self.inventory),
            );
            if let Some(owner) = owner {
                processes
                    .entry(owner.identity)
                    .or_insert_with(|| process_row(owner))
                    .connections += 1;
            } else {
                unknown.connections += 1;
            }
        }
        for (&(link, identity), entry) in &self.counters.processes {
            if !link_in_scope(link, selected) {
                continue;
            }
            // Traffic within this interval stays visible even when the
            // sockets closed more than RECENT_TRAFFIC before a long sample.
            if !processes.contains_key(&identity)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas.processes.contains_key(&(link, identity))
            {
                continue;
            }
            let row = processes
                .entry(identity)
                .or_insert_with(|| process_row(&entry.owner));
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.processes.get(&(link, identity)) {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for ((link, socket_key, identity), entry) in &self.counters.connections {
            if !link_in_scope(*link, selected) {
                continue;
            }
            let key = (socket_key.clone(), Some(*identity));
            if !connections.contains_key(&key)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas
                    .connections
                    .contains_key(&(*link, socket_key.clone(), *identity))
            {
                continue;
            }
            let row = connections.entry(key).or_insert_with(|| {
                let mut row = connection_row(&entry.socket, &self.inventory);
                row.state = "RECENT/CLOSED".to_string();
                row
            });
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available
                && let Some(bytes) = deltas
                    .connections
                    .get(&(*link, socket_key.clone(), *identity))
            {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for (&link, counter) in &self.counters.unattributed {
            if !link_in_scope(link, selected) {
                continue;
            }
            unknown.rx_bytes = unknown.rx_bytes.saturating_add(counter.bytes.rx);
            unknown.tx_bytes = unknown.tx_bytes.saturating_add(counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.unknown.get(&link) {
                unknown.rx_rate += bytes.rx as f64 / interval;
                unknown.tx_rate += bytes.tx as f64 / interval;
            }
        }
        let mut rows: Vec<_> = processes.into_values().collect();
        if unknown.connections > 0 || unknown.rx_bytes > 0 || unknown.tx_bytes > 0 {
            rows.push(unknown);
        }
        rows.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        let mut connections: Vec<_> = connections.into_values().collect();
        connections.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| a.pid.cmp(&b.pid))
                .then_with(|| a.local.cmp(&b.local))
        });
        (rows, connections)
    }
}

impl Counters {
    /// Clones the owner or socket only when a counter is created or its view
    /// changed, never per packet batch. Without `connection`, only the
    /// process is credited.
    fn record_owned(
        &mut self,
        link: Link,
        socket: &Socket,
        connection: bool,
        bytes: Bytes,
        now: Instant,
        deltas: &mut Deltas,
    ) -> bool {
        let Some(owner) = socket.owner() else {
            return false;
        };
        let process_key = (link, owner.identity);
        let connection_key = (link, socket.key.clone(), owner.identity);
        if (self.processes.len() >= MAX_PROCESS_COUNTERS
            && !self.processes.contains_key(&process_key))
            || (connection
                && self.connections.len() >= MAX_CONNECTION_COUNTERS
                && !self.connections.contains_key(&connection_key))
        {
            self.limit_hit = true;
            return false;
        }
        let process = self
            .processes
            .entry(process_key)
            .or_insert_with(|| ProcessCounter {
                owner: owner.clone(),
                counter: Counter::new(now),
            });
        if process.owner != *owner {
            process.owner = owner.clone();
        }
        process.counter.add(bytes, now);
        deltas.processes.entry(process_key).or_default().add(bytes);
        if !connection {
            return true;
        }
        let connection = self
            .connections
            .entry(connection_key.clone())
            .or_insert_with(|| ConnectionCounter {
                socket: socket.clone(),
                counter: Counter::new(now),
            });
        if connection.socket.current != socket.current
            || connection.socket.state != socket.state
            || connection.socket.owners != socket.owners
        {
            connection.socket = socket.clone();
        }
        connection.counter.add(bytes, now);
        deltas
            .connections
            .entry(connection_key)
            .or_default()
            .add(bytes);
        true
    }

    fn record_unknown(
        &mut self,
        link: Link,
        bytes: Bytes,
        now: Instant,
        delta: &mut HashMap<Link, Bytes>,
    ) {
        if self.unattributed.len() >= MAX_INTERFACE_COUNTERS
            && !self.unattributed.contains_key(&link)
        {
            self.limit_hit = true;
            return;
        }
        self.unattributed
            .entry(link)
            .or_insert_with(|| Counter::new(now))
            .add(bytes, now);
        delta.entry(link).or_default().add(bytes);
    }
}

fn counter_rate(current: u64, previous: u64, interval: f64) -> f64 {
    current.saturating_sub(previous) as f64 / interval
}

/// All-interface views skip lower-device duplicates of host traffic.
fn link_in_scope(link: Link, selected: Option<u32>) -> bool {
    selected.map_or(!link.lower, |selected| selected == link.index)
}

/// `scope` is `None` for all interfaces, `Some(None)` for a vanished one.
fn socket_in_scope(socket: &Socket, scope: Option<Option<&KernelInterface>>) -> bool {
    let Some(selected) = scope else {
        return true;
    };
    let Some(interface) = selected else {
        return false;
    };
    let ip = canonical_ip(socket.key.local.ip());
    // A wildcard is a kernel-wide binding and can serve the selected interface.
    ip.is_unspecified() || interface_has_ip(interface, ip)
}

fn interface_has_ip(interface: &KernelInterface, ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    (interface.loopback && ip.is_loopback())
        || interface
            .addresses
            .iter()
            .any(|address| canonical_ip(*address) == ip)
}

/// Host addresses and link relations, built once per attribution pass so
/// per-flow checks are set lookups rather than scans of every interface.
#[derive(Default)]
struct LocalView {
    addresses: HashSet<IpAddr>,
    loopback: HashSet<u32>,
    /// Links whose host traffic is also captured on an upper device.
    lower: HashMap<u32, LowerLink>,
}

struct LowerLink {
    /// Bridge ports and bond slaves hand every locally delivered packet to
    /// their master, and transmit what the master sends.
    enslaved: bool,
    own: HashSet<IpAddr>,
    /// Addresses of (transitive) upper devices such as VLANs or macvlans.
    upper: HashSet<IpAddr>,
}

impl LocalView {
    fn new(interfaces: &[KernelInterface]) -> Self {
        let mut view = Self::default();
        let by_index: HashMap<u32, &KernelInterface> = interfaces
            .iter()
            .map(|interface| (interface.index, interface))
            .collect();
        for interface in interfaces {
            view.addresses
                .extend(interface.addresses.iter().map(|ip| canonical_ip(*ip)));
            if interface.loopback {
                view.loopback.insert(interface.index);
            }
            let topology = &interface.topology;
            if !topology.master && topology.uppers.is_empty() {
                continue;
            }
            let mut upper = HashSet::new();
            let mut pending = topology.uppers.clone();
            let mut seen = HashSet::from([interface.index]);
            // Stacks are shallow (VLAN on bond on ports); bound malformed loops.
            while let Some(index) = pending.pop() {
                if !seen.insert(index) || seen.len() > 16 {
                    continue;
                }
                if let Some(device) = by_index.get(&index) {
                    upper.extend(device.addresses.iter().map(|ip| canonical_ip(*ip)));
                    pending.extend(&device.topology.uppers);
                }
            }
            view.lower.insert(
                interface.index,
                LowerLink {
                    enslaved: topology.master,
                    own: interface
                        .addresses
                        .iter()
                        .map(|ip| canonical_ip(*ip))
                        .collect(),
                    upper,
                },
            );
        }
        view
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        (!self.loopback.is_empty() && ip.is_loopback()) || self.addresses.contains(&ip)
    }

    /// Host traffic for `local` seen on link `index` that its upper device
    /// also captures, so all-interface totals would count it twice.
    fn lower_observation(&self, index: u32, local: IpAddr) -> bool {
        let local = canonical_ip(local);
        self.lower.get(&index).is_some_and(|link| {
            link.enslaved || (link.upper.contains(&local) && !link.own.contains(&local))
        })
    }
}

/// Traffic between two local endpoints, observed once on a loopback link.
fn loopback_path(flow: &Flow, view: &LocalView) -> bool {
    view.loopback.contains(&flow.interface_index)
        || (flow.interface_index == 0
            && view.is_local(flow.source)
            && view.is_local(flow.destination))
}

fn traffic_sides(flow: &Flow, view: &LocalView) -> (bool, bool) {
    if loopback_path(flow, view) {
        // On loopback, libpcap drops the outgoing copy and keeps the incoming
        // one; that single observation belongs to both the sender's TX and
        // the receiver's RX, never twice to either endpoint.
        return (true, true);
    }
    match flow.direction {
        Direction::Incoming => (true, false),
        Direction::Outgoing => (false, true),
        Direction::Unknown => (view.is_local(flow.destination), view.is_local(flow.source)),
    }
}

fn socket_endpoints(flow: &Flow, receive: bool) -> Option<(SocketAddr, SocketAddr)> {
    let source = SocketAddr::new(canonical_ip(flow.source), flow.source_port?);
    let destination = SocketAddr::new(canonical_ip(flow.destination), flow.destination_port?);
    Some(if receive {
        (destination, source)
    } else {
        (source, destination)
    })
}

fn local_socket_endpoints(
    flow: &Flow,
    receive: bool,
    view: &LocalView,
) -> Option<(SocketAddr, SocketAddr)> {
    let (local, remote) = socket_endpoints(flow, receive)?;
    // Captured interface direction is not proof of a local socket endpoint.
    // Bridges, forwarding and container links also expose nonlocal traffic;
    // matching it to a wildcard listener merely by port assigns the wrong PID.
    // Multicast/broadcast receiver membership is not known from /proc, so leave
    // those receive bytes unattributed too. Sender attribution remains possible.
    view.is_local(local.ip()).then_some((local, remote))
}

/// Docker publishes ports by DNAT in PREROUTING, but AF_PACKET observes packets
/// before translation, so forwarded container traffic still carries the host
/// port of docker-proxy's wildcard listener. With Docker's NAT rules that proxy
/// only serves loopback connections, and its accepted connections match
/// exactly. Do not credit wildcard-only matches from other links to it; the
/// bytes stay unattributed instead of naming the wrong process.
fn published_port_proxy(flow: &Flow, socket: &Socket, view: &LocalView) -> bool {
    let remote = socket.key.remote;
    remote.ip().is_unspecified()
        && remote.port() == 0
        && socket
            .owner()
            .is_some_and(|owner| owner.name == "docker-proxy")
        && !loopback_path(flow, view)
}

fn process_row(owner: &Owner) -> ProcessRow {
    ProcessRow {
        pid: Some(owner.identity.pid),
        user: owner.user.clone(),
        name: owner.name.clone(),
        ..ProcessRow::default()
    }
}

fn connection_row(socket: &Socket, inventory: &Inventory) -> ConnectionRow {
    let owner = socket.owner();
    ConnectionRow {
        pid: owner.map(|owner| owner.identity.pid),
        user: owner
            .map(|owner| owner.user.clone())
            .unwrap_or_else(|| inventory.user(socket.uid)),
        process: owner.map(|owner| owner.name.clone()).unwrap_or_else(|| {
            if socket.owners.len() > 1 {
                "[shared]".to_string()
            } else {
                "[unknown]".to_string()
            }
        }),
        protocol: socket.key.protocol.label().to_string(),
        local: socket.key.local.to_string(),
        remote: socket.key.remote.to_string(),
        state: socket.state.clone(),
        ..ConnectionRow::default()
    }
}

fn read_interfaces() -> Result<Vec<KernelInterface>> {
    let contents = fs::read_to_string("/proc/net/dev")
        .context("reading Linux network counters (/proc/net/dev)")?;
    let mut addresses = interface_addresses();
    let mut interfaces = Vec::new();
    for line in contents.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let values: Vec<_> = values
            .split_ascii_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect();
        if values.len() != 16 {
            continue;
        }
        // An interface that vanished since /proc/net/dev was read has no
        // index; skip it rather than merging it with others under index 0.
        let Some(index) = interface_index(name) else {
            continue;
        };
        let path = format!("/sys/class/net/{name}");
        let read = |file: &str| {
            fs::read_to_string(format!("{path}/{file}"))
                .ok()
                .map(|value| value.trim().to_string())
        };
        let link = addresses.remove(&index).unwrap_or_default();
        let interface_ips = link.addresses;
        let address = interface_ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or(interface_ips.first())
            .map(ToString::to_string);
        let loopback = link.loopback || read("type").is_some_and(|value| value == "772");
        interfaces.push(KernelInterface {
            info: Interface {
                name: name.to_string(),
                state: read("operstate").unwrap_or_else(|| "unknown".to_string()),
                address,
                speed_mbps: read("speed")
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|speed| *speed > 0)
                    .map(|speed| speed as u64),
                mtu: read("mtu").and_then(|value| value.parse().ok()),
                is_virtual: fs::canonicalize(&path)
                    .is_ok_and(|path| path.to_string_lossy().contains("/virtual/")),
                rx_bytes: values[0],
                rx_packets: values[1],
                tx_bytes: values[8],
                tx_packets: values[9],
                errors: values[2].saturating_add(values[10]),
                dropped: values[3].saturating_add(values[11]),
                ..Interface::default()
            },
            index,
            addresses: interface_ips,
            loopback,
            topology: LinkTopology::default(),
        });
    }
    if interfaces.is_empty() {
        bail!("/proc/net/dev contains no network interfaces");
    }
    let mut topology = read_topology(
        interfaces
            .iter()
            .map(|interface| (interface.index, interface.info.name.as_str())),
    );
    for interface in &mut interfaces {
        interface.topology = topology.remove(&interface.index).unwrap_or_default();
    }
    interfaces.sort_by(|a, b| a.info.name.cmp(&b.info.name));
    Ok(interfaces)
}

fn interface_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// IPv4 alias addresses carry their label ("eth0:1") as the name; Linux
/// interface names never contain ':' so the base name identifies the device.
fn base_interface_name(label: &str) -> &str {
    label.split_once(':').map_or(label, |(name, _)| name)
}

#[derive(Debug, Default)]
struct LinkAddresses {
    name: String,
    addresses: Vec<IpAddr>,
    loopback: bool,
}

/// Addresses and loopback flags keyed by interface index, so alias labels and
/// renamed devices still map to the link that owns them.
fn interface_addresses() -> HashMap<u32, LinkAddresses> {
    let mut result: HashMap<u32, LinkAddresses> = HashMap::new();
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return result;
    }
    let mut entries = Vec::new();
    // AF_PACKET entries carry each link's kernel index, avoiding one
    // if_nametoindex socket per device on every background tick.
    let mut indexes: HashMap<String, Option<u32>> = HashMap::new();
    let mut current = head;
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_name.is_null() {
            let label = unsafe { CStr::from_ptr(interface.ifa_name) }.to_string_lossy();
            let name = base_interface_name(&label).to_string();
            let address = interface.ifa_addr;
            if !address.is_null() && unsafe { (*address).sa_family as i32 } == libc::AF_PACKET {
                let link = unsafe { &*(address as *const libc::sockaddr_ll) };
                if link.sll_ifindex > 0 {
                    indexes.insert(name.clone(), Some(link.sll_ifindex as u32));
                }
            }
            let loopback = interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
            entries.push((name, loopback, socket_ip(address)));
        }
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    for (name, loopback, ip) in entries {
        let index = *indexes
            .entry(name.clone())
            .or_insert_with_key(|name| interface_index(name));
        let Some(index) = index else {
            continue;
        };
        let link = result.entry(index).or_default();
        if link.name.is_empty() {
            link.name = name;
        }
        link.loopback |= loopback;
        if let Some(ip) = ip
            && !link.addresses.contains(&ip)
        {
            link.addresses.push(ip);
        }
    }
    result
}

fn socket_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            let address = unsafe { &*(address as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Masters and uppers of each link from sysfs: `master` and `upper_*`
/// entries (bridge/bond membership, VLAN, macvlan and other stacked devices).
fn read_topology<'a>(
    links: impl Iterator<Item = (u32, &'a str)> + Clone,
) -> HashMap<u32, LinkTopology> {
    let indexes: HashMap<&str, u32> = links.clone().map(|(index, name)| (name, index)).collect();
    links
        .filter_map(|(index, name)| {
            let path = format!("/sys/class/net/{name}");
            let master = fs::symlink_metadata(format!("{path}/master")).is_ok();
            let uppers: Vec<u32> = fs::read_dir(&path)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let entry = entry.file_name();
                    let upper = entry.to_str()?.strip_prefix("upper_")?;
                    indexes.get(upper).copied()
                })
                .collect();
            (master || !uppers.is_empty()).then_some((index, LinkTopology { master, uppers }))
        })
        .collect()
}

/// The worker rereads sysfs topology only periodically or when links change.
#[derive(Default)]
struct TopologyCache {
    links: Vec<(u32, String)>,
    topology: HashMap<u32, LinkTopology>,
    read: Option<Instant>,
}

impl TopologyCache {
    fn get(&mut self, mut links: Vec<(u32, String)>) -> &HashMap<u32, LinkTopology> {
        links.sort();
        let now = Instant::now();
        if links != self.links
            || self
                .read
                .is_none_or(|read| now.saturating_duration_since(read) >= TOPOLOGY_REFRESH)
        {
            self.topology =
                read_topology(links.iter().map(|(index, name)| (*index, name.as_str())));
            self.links = links;
            self.read = Some(now);
        }
        &self.topology
    }
}

/// The address view the background worker needs for attribution, without
/// the per-device counter reads of a full snapshot.
fn local_interfaces(cache: &mut TopologyCache) -> Vec<KernelInterface> {
    let links = interface_addresses();
    let topology = cache.get(
        links
            .iter()
            .map(|(index, link)| (*index, link.name.clone()))
            .collect(),
    );
    links
        .into_iter()
        .map(|(index, link)| KernelInterface {
            info: Interface {
                name: link.name,
                ..Interface::default()
            },
            index,
            addresses: link.addresses,
            loopback: link.loopback,
            topology: topology.get(&index).cloned().unwrap_or_default(),
        })
        .collect()
}

/// Prefer the lowest-metric default route, then a physical link, then loopback.
pub fn default_interface() -> Option<String> {
    let mut routes = Vec::new();
    if let Ok(contents) = fs::read_to_string("/proc/net/route") {
        for line in contents.lines().skip(1) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() >= 8
                && fields[1] == "00000000"
                && u32::from_str_radix(fields[3], 16).is_ok_and(|flags| flags & 1 == 1)
                && let Ok(metric) = fields[6].parse::<u32>()
            {
                routes.push((metric, fields[0].to_string()));
            }
        }
    }
    if let Ok(contents) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in contents.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() >= 10
                && fields[0] == "00000000000000000000000000000000"
                && fields[1] == "00"
                && u32::from_str_radix(fields[8], 16).is_ok_and(|flags| flags & 1 == 1)
                && let Ok(metric) = u32::from_str_radix(fields[5], 16)
            {
                routes.push((metric, fields[9].to_string()));
            }
        }
    }
    routes.sort();
    let interfaces = read_interfaces().ok()?;
    let available: HashSet<_> = interfaces
        .iter()
        .map(|interface| interface.info.name.as_str())
        .collect();
    if let Some((_, name)) = routes
        .into_iter()
        .find(|(_, name)| available.contains(name.as_str()))
    {
        return Some(name);
    }
    interfaces
        .iter()
        .find(|interface| !interface.info.is_virtual && interface.info.state == "up")
        .or_else(|| {
            interfaces
                .iter()
                .find(|interface| interface.info.state == "up")
        })
        .or_else(|| interfaces.iter().find(|interface| interface.loopback))
        .map(|interface| interface.info.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::Protocol;

    fn interface(index: u32, loopback: bool, address: &str) -> KernelInterface {
        KernelInterface {
            info: Interface::default(),
            index,
            addresses: vec![address.parse().unwrap()],
            loopback,
            topology: LinkTopology::default(),
        }
    }

    fn flow(direction: Direction, interface_index: u32) -> Flow {
        Flow {
            source: "127.0.0.1".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            source_port: Some(12345),
            destination_port: Some(8080),
            protocol: Protocol::Tcp,
            direction,
            interface_index,
        }
    }

    #[test]
    fn reset_counters_never_produce_wrapped_or_negative_rates() {
        assert_eq!(counter_rate(100, 200, 1.0), 0.0);
        assert_eq!(counter_rate(300, 100, 0.5), 400.0);
    }

    #[test]
    fn loopback_has_sender_tx_and_receiver_rx_exactly_once() {
        let interfaces = vec![interface(1, true, "127.0.0.1")];
        let packet = flow(Direction::Outgoing, 1);
        assert_eq!(
            traffic_sides(&packet, &LocalView::new(&interfaces)),
            (true, true)
        );
        assert_eq!(socket_endpoints(&packet, false).unwrap().0.port(), 12345);
        assert_eq!(socket_endpoints(&packet, true).unwrap().0.port(), 8080);
    }

    #[test]
    fn interface_selection_uses_capture_ifindex_not_ip_guesses() {
        assert!(link_in_scope(Link::plain(42), Some(42)));
        assert!(!link_in_scope(Link::plain(43), Some(42)));
        assert!(!link_in_scope(Link::plain(0), Some(42)));
        assert!(link_in_scope(Link::plain(43), None));
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        assert_eq!(
            traffic_sides(&flow(Direction::Outgoing, 2), &LocalView::new(&interfaces)),
            (false, true)
        );
        assert_eq!(
            traffic_sides(&flow(Direction::Incoming, 2), &LocalView::new(&interfaces)),
            (true, false)
        );
    }

    #[test]
    fn closed_sockets_with_traffic_this_interval_stay_listed() {
        let start = Instant::now();
        let mut attribution = Attribution::new(Inventory::new(), None);
        let socket = Socket {
            key: SocketKey {
                inode: 321,
                protocol: Protocol::Tcp,
                local: "192.0.2.1:23456".parse().unwrap(),
                remote: "198.51.100.2:443".parse().unwrap(),
            },
            state: "ESTABLISHED".to_string(),
            uid: 1000,
            observed: start,
            current: false,
            ipv6_only: None,
            owners: vec![Owner {
                identity: ProcessIdentity {
                    pid: 43,
                    start_time: 1,
                },
                user: "test".to_string(),
                name: "brief".to_string(),
            }],
        };
        let mut deltas = Deltas::default();
        assert!(attribution.counters.record_owned(
            Link::plain(1),
            &socket,
            true,
            Bytes { rx: 10, tx: 20 },
            start,
            &mut deltas
        ));
        // A long refresh interval samples well after the socket closed.
        let sample = start + RECENT_TRAFFIC + Duration::from_secs(10);
        let (processes, connections) = attribution.rows(None, &[], sample, 20.0, &deltas, true);
        let row = processes.iter().find(|row| row.name == "brief").unwrap();
        assert_eq!((row.rx_bytes, row.tx_bytes), (10, 20));
        assert_eq!(connections.len(), 1);
        let (processes, connections) =
            attribution.rows(None, &[], sample, 20.0, &Deltas::default(), true);
        assert!(processes.iter().all(|row| row.name != "brief"));
        assert!(connections.is_empty());
    }

    #[test]
    fn kernel_interface_snapshot_matches_proc_totals() {
        let interfaces = read_interfaces().unwrap();
        assert!(
            interfaces
                .iter()
                .any(|interface| interface.info.name == "lo" && interface.loopback)
        );
        assert!(interfaces.iter().all(|interface| interface.index > 0));
        assert!(default_interface().is_some());
    }

    #[test]
    fn reused_pids_and_interface_scopes_keep_distinct_counters() {
        let now = Instant::now();
        let mut attribution = Attribution::new(Inventory::new(), None);
        let mut socket = Socket {
            key: SocketKey {
                inode: 123,
                protocol: Protocol::Tcp,
                local: "192.0.2.1:12345".parse().unwrap(),
                remote: "198.51.100.2:443".parse().unwrap(),
            },
            state: "ESTABLISHED".to_string(),
            uid: 1000,
            observed: now,
            current: true,
            ipv6_only: None,
            owners: vec![Owner {
                identity: ProcessIdentity {
                    pid: 42,
                    start_time: 1,
                },
                user: "test".to_string(),
                name: "first".to_string(),
            }],
        };
        let mut deltas = Deltas::default();
        assert!(attribution.counters.record_owned(
            Link::plain(1),
            &socket,
            true,
            Bytes { rx: 0, tx: 100 },
            now,
            &mut deltas
        ));
        socket.owners[0].identity.start_time = 2;
        socket.owners[0].name = "second".to_string();
        assert!(attribution.counters.record_owned(
            Link::plain(1),
            &socket,
            true,
            Bytes { rx: 0, tx: 50 },
            now,
            &mut deltas
        ));
        assert!(attribution.counters.record_owned(
            Link::plain(2),
            &socket,
            true,
            Bytes { rx: 0, tx: 200 },
            now,
            &mut deltas
        ));
        let (selected, _) = attribution.rows(Some(1), &[], now, 1.0, &deltas, true);
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected
                .iter()
                .find(|row| row.name == "second")
                .unwrap()
                .tx_bytes,
            50
        );
        let (all, _) = attribution.rows(None, &[], now, 1.0, &deltas, true);
        assert_eq!(
            all.iter()
                .find(|row| row.name == "second")
                .unwrap()
                .tx_bytes,
            250
        );
        assert_eq!(
            all.iter().find(|row| row.name == "first").unwrap().tx_bytes,
            100
        );
        attribution.inventory.sockets.push(socket);
        let after_idle = now + COUNTER_RETENTION + Duration::from_secs(1);
        attribution.prune(after_idle, &[]);
        assert_eq!(
            attribution.counters.processes.len(),
            2,
            "open owner totals survive idle on both interfaces"
        );
        assert_eq!(
            attribution.counters.connections.len(),
            2,
            "open socket totals survive idle"
        );
        assert!(
            attribution
                .counters
                .processes
                .keys()
                .all(|(_, identity)| identity.start_time == 2)
        );
        attribution.inventory.sockets.clear();
        attribution.prune(after_idle, &[]);
        assert!(attribution.counters.processes.is_empty());
        assert!(attribution.counters.connections.is_empty());
    }

    #[test]
    fn vanished_interface_is_empty_and_preserves_other_kernel_devices() {
        let mut collector = Collector::new(false).unwrap();
        let snapshot = collector
            .sample(Some("nettop-test-interface-does-not-exist"))
            .unwrap();
        assert!(!snapshot.interfaces.is_empty());
        assert!(snapshot.processes.is_empty());
        assert!(snapshot.connections.is_empty());
        assert!(!snapshot.capture.active);
        assert!(snapshot.capture.message.starts_with("F2:"));
    }

    #[test]
    fn forwarded_packets_cannot_match_host_wildcard_sockets() {
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        let mut packet = flow(Direction::Incoming, 2);
        packet.source = "198.51.100.1".parse().unwrap();
        packet.destination = "203.0.113.2".parse().unwrap();
        assert_eq!(
            traffic_sides(&packet, &LocalView::new(&interfaces)),
            (true, false)
        );
        assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_none());
        packet.direction = Direction::Outgoing;
        assert!(local_socket_endpoints(&packet, false, &LocalView::new(&interfaces)).is_none());
        packet.destination = "192.0.2.1".parse().unwrap();
        assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_some());
        packet.destination = "224.0.0.251".parse().unwrap();
        assert!(local_socket_endpoints(&packet, true, &LocalView::new(&interfaces)).is_none());
        packet.source = "192.0.2.1".parse().unwrap();
        assert!(local_socket_endpoints(&packet, false, &LocalView::new(&interfaces)).is_some());
    }

    fn owned(local: &str, remote: &str, inode: u64, name: &str) -> Socket {
        Socket {
            key: SocketKey {
                inode,
                protocol: Protocol::Tcp,
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
            },
            state: "LISTEN".to_string(),
            uid: 0,
            observed: Instant::now(),
            current: true,
            ipv6_only: None,
            owners: vec![Owner {
                identity: ProcessIdentity {
                    pid: 4242,
                    start_time: 1,
                },
                user: "root".to_string(),
                name: name.to_string(),
            }],
        }
    }

    #[test]
    fn alias_labels_map_to_their_device() {
        assert_eq!(base_interface_name("eth0:1"), "eth0");
        assert_eq!(base_interface_name("eth0"), "eth0");
        let loopback = interface_index("lo").unwrap();
        let addresses = interface_addresses();
        let link = &addresses[&loopback];
        assert!(link.loopback);
        assert!(link.addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(interface_index("nettop-test-interface-does-not-exist").is_none());
        assert!(
            local_interfaces(&mut TopologyCache::default())
                .iter()
                .any(|interface| interface.index == loopback && interface.loopback)
        );
    }

    #[test]
    fn dnat_traffic_is_not_credited_to_docker_proxy_listener() {
        let interfaces = vec![
            interface(1, true, "127.0.0.1"),
            interface(2, false, "192.0.2.1"),
        ];
        let listener = owned("0.0.0.0:8080", "0.0.0.0:0", 1, "docker-proxy");
        let mut packet = flow(Direction::Incoming, 2);
        packet.destination = "192.0.2.1".parse().unwrap();
        assert!(published_port_proxy(
            &packet,
            &listener,
            &LocalView::new(&interfaces)
        ));
        // Loopback connections really reach the proxy.
        assert!(!published_port_proxy(
            &flow(Direction::Outgoing, 1),
            &listener,
            &LocalView::new(&interfaces)
        ));
        // Accepted proxy connections and other listeners keep attribution.
        let accepted = owned("192.0.2.1:8080", "198.51.100.1:5000", 2, "docker-proxy");
        assert!(!published_port_proxy(
            &packet,
            &accepted,
            &LocalView::new(&interfaces)
        ));
        let server = owned("0.0.0.0:8080", "0.0.0.0:0", 3, "nginx");
        assert!(!published_port_proxy(
            &packet,
            &server,
            &LocalView::new(&interfaces)
        ));
    }

    #[test]
    fn flows_without_a_socket_wait_for_a_newer_table_once() {
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        let view = LocalView::new(&interfaces);
        let mut inventory = Inventory::new();
        let table = Instant::now();
        inventory.set_refreshed_at(Some(table));
        let mut attribution = Attribution::new(inventory, None);
        let mut packet = flow(Direction::Incoming, 2);
        packet.source = "198.51.100.1".parse().unwrap();
        packet.destination = "192.0.2.1".parse().unwrap();
        // Drained after the latest table read: the socket may be newer.
        let drained = table + Duration::from_millis(10);
        attribution.attribute(&packet, true, 100, drained, drained, &view);
        assert_eq!(attribution.deferred.len(), 1);
        assert!(attribution.counters.unattributed.is_empty());
        // A table read after the drain still lacks it: give up.
        attribution
            .inventory
            .set_refreshed_at(Some(drained + Duration::from_millis(5)));
        let retry = drained + Duration::from_millis(20);
        attribution.deferred.clear();
        attribution.attribute(&packet, true, 100, drained, retry, &view);
        assert!(attribution.deferred.is_empty());
        assert_eq!(
            attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
            100
        );
        // Forwarded traffic never waits, whatever the table age.
        attribution.inventory.set_refreshed_at(None);
        packet.destination = "203.0.113.9".parse().unwrap();
        attribution.attribute(&packet, true, 100, retry, retry, &view);
        assert!(attribution.deferred.is_empty());
        assert_eq!(
            attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
            200
        );
    }

    #[test]
    fn deferral_outlasts_the_owner_scan_gap_within_bounds() {
        let attribution = Attribution::new(Inventory::new(), None);
        assert!(attribution.max_defer() >= MIN_DEFER);
        assert!(attribution.max_defer() >= attribution.inventory.owner_scan_gap());
        assert!(attribution.max_defer() <= MAX_DEFER);
    }

    #[test]
    fn reuseport_ties_credit_the_process_but_no_single_connection() {
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        let view = LocalView::new(&interfaces);
        let mut inventory = Inventory::new();
        inventory.sockets = [1, 2]
            .map(|inode| owned("0.0.0.0:8080", "0.0.0.0:0", inode, "server"))
            .into();
        inventory.rebuild_index();
        let mut attribution = Attribution::new(inventory, None);
        let mut packet = flow(Direction::Incoming, 2);
        packet.source = "198.51.100.1".parse().unwrap();
        packet.destination = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        attribution.attribute(&packet, true, 100, now, now, &view);
        assert!(attribution.counters.unattributed.is_empty());
        assert!(attribution.counters.connections.is_empty());
        let (processes, _) =
            attribution.rows(None, &interfaces, now, 1.0, &attribution.deltas, true);
        let row = processes.iter().find(|row| row.name == "server").unwrap();
        assert_eq!(row.rx_bytes, 100);
    }

    fn stacked(
        index: u32,
        address: Option<&str>,
        master: bool,
        uppers: Vec<u32>,
    ) -> KernelInterface {
        KernelInterface {
            info: Interface::default(),
            index,
            addresses: address.into_iter().map(|ip| ip.parse().unwrap()).collect(),
            loopback: false,
            topology: LinkTopology { master, uppers },
        }
    }

    #[test]
    fn lower_devices_do_not_double_host_traffic_in_all_mode() {
        // eth0 is a bridge port of br0; eth1 carries VLAN eth1.100 and its own
        // untagged address.
        let interfaces = vec![
            stacked(2, None, true, vec![3]),
            stacked(3, Some("192.0.2.1"), false, vec![]),
            stacked(4, Some("198.51.100.1"), false, vec![5]),
            stacked(5, Some("203.0.113.1"), false, vec![]),
        ];
        let view = LocalView::new(&interfaces);
        let host: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(view.lower_observation(2, host));
        assert!(!view.lower_observation(3, host));
        assert!(view.lower_observation(4, "203.0.113.1".parse().unwrap()));
        assert!(!view.lower_observation(4, "198.51.100.1".parse().unwrap()));
        assert!(!view.lower_observation(5, "203.0.113.1".parse().unwrap()));

        let mut inventory = Inventory::new();
        inventory.sockets = vec![owned("0.0.0.0:8080", "0.0.0.0:0", 1, "server")];
        inventory.rebuild_index();
        let mut attribution = Attribution::new(inventory, None);
        let now = Instant::now();
        for index in [2, 3] {
            let mut packet = flow(Direction::Incoming, index);
            packet.source = "192.0.2.50".parse().unwrap();
            packet.destination = host;
            attribution.attribute(&packet, true, 100, now, now, &view);
        }
        let rx = |selected| {
            let (rows, _) =
                attribution.rows(selected, &interfaces, now, 1.0, &attribution.deltas, true);
            rows.iter()
                .find(|row| row.name == "server")
                .map_or(0, |row| row.rx_bytes)
        };
        assert_eq!(rx(None), 100, "the bridge port copy is not added again");
        assert_eq!(rx(Some(2)), 100, "a selected bridge port still shows it");
        assert_eq!(rx(Some(3)), 100);
    }

    #[test]
    fn flows_of_unscanned_sockets_are_deferred_briefly() {
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        let mut socket = owned("192.0.2.1:8080", "198.51.100.1:5000", 9, "server");
        socket.owners.clear();
        socket.state = "ESTABLISHED".to_string();
        let mut inventory = Inventory::new();
        inventory.sockets = vec![socket];
        inventory.rebuild_index();
        let mut attribution = Attribution::new(inventory, None);
        let mut packet = flow(Direction::Incoming, 2);
        packet.source = "198.51.100.1".parse().unwrap();
        packet.source_port = Some(5000);
        packet.destination = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        let view = LocalView::new(&interfaces);
        attribution.attribute(&packet, true, 100, now, now, &view);
        attribution.attribute(&packet, true, 50, now, now, &view);
        assert_eq!(attribution.deferred.len(), 1, "one flow, merged");
        assert_eq!(attribution.deferred[&(packet.clone(), true)].bytes, 150);
        assert!(attribution.counters.unattributed.is_empty());
        // After the retry window the bytes are reported as unattributed.
        let later = now + attribution.max_defer();
        attribution.attribute(&packet, true, 100, now, later, &view);
        assert_eq!(attribution.deferred.len(), 1);
        assert_eq!(
            attribution.counters.unattributed[&Link::plain(2)].bytes.rx,
            100
        );
    }
}
