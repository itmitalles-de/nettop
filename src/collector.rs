//! Real Linux kernel counters and best-effort, header-only process attribution.

#[path = "capture.rs"]
mod capture;
#[path = "packet.rs"]
mod packet;
#[path = "sockets.rs"]
mod sockets;

use crate::model::{CaptureStatus, ConnectionRow, Interface, ProcessRow, Snapshot};
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
const MAX_INTERFACE_COUNTERS: usize = 256;
const COUNTER_RETENTION: Duration = Duration::from_secs(300);
const RECENT_TRAFFIC: Duration = Duration::from_secs(3);
/// Captured flows are matched to sockets on this cadence, independent of the
/// UI refresh interval, so closed and short-lived sockets are still known.
const ATTRIBUTION_TICK: Duration = Duration::from_millis(250);
const MAX_ATTRIBUTION_WAIT: Duration = Duration::from_millis(500);
/// Flows whose socket awaits its first owner scan are retried briefly.
const MAX_DEFERRED: usize = 4_096;
const MAX_DEFER: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
struct KernelInterface {
    info: Interface,
    index: u32,
    addresses: Vec<IpAddr>,
    loopback: bool,
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

type ProcessCounterKey = (u32, ProcessIdentity);
type ConnectionCounterKey = (u32, SocketKey, ProcessIdentity);

/// Bytes attributed since the previous snapshot; rates divide these by the
/// snapshot interval.
#[derive(Default)]
struct Deltas {
    processes: HashMap<ProcessCounterKey, Bytes>,
    connections: HashMap<ConnectionCounterKey, Bytes>,
    unknown: HashMap<u32, Bytes>,
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
    unattributed: HashMap<u32, Counter>,
    /// A counter bound rejected bytes since the previous snapshot.
    limit_hit: bool,
}

struct Deferred {
    flow: Flow,
    receive: bool,
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
    deferred: Vec<Deferred>,
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
                loop {
                    match stopped.recv_timeout(wait) {
                        Err(RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                    let started = Instant::now();
                    let interfaces = local_interfaces();
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
    capture_message: String,
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
        let (capture, capture_message) = if capture_enabled {
            match capture::Capture::start() {
                Ok(capture) => (Some(capture), String::new()),
                Err(error) => (None, error.to_string()),
            }
        } else {
            (
                None,
                "Capture disabled (--no-capture); interface counters and sockets only".to_string(),
            )
        };
        let start_worker = capture.is_some();
        Ok(Self {
            started,
            last_sample,
            previous_interfaces,
            capture_message,
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
            message: self.capture_message.clone(),
            dropped: 0,
        };
        if let Some(capture) = &state.capture {
            // Per-interval values: a past burst must not taint later snapshots.
            status.dropped = problems.dropped.saturating_add(problems.overflow);
            if interface.is_some() && !capture.interface_indexes {
                status.active = false;
                status.message = "Process rates unavailable: libpcap lacks SLL2 interface indexes; upgrade libpcap or use -i all".to_string();
            } else if interface.is_none() {
                status.message = "ALL interfaces: bridge/veth packets can repeat; process rates count captured IP bytes".to_string();
            } else {
                status.message = "Process rates: captured IP bytes; socket/PID owners sampled, brief sockets may be unattributed".to_string();
            }
            if problems.dropped > 0 {
                status
                    .message
                    .push_str(&format!("; pcap missed {} packets", problems.dropped));
            }
            if problems.overflow > 0 {
                status.message.push_str(&format!(
                    "; flow limit: {} packets unattributed",
                    problems.overflow
                ));
            }
            if problems.unsupported > 0 || problems.truncated > 0 {
                status.message.push_str(&format!(
                    "; non-IP/unsupported {} / unreadable headers {}",
                    problems.unsupported, problems.truncated
                ));
            }
            if let Some(error) = &state.worker_error {
                status
                    .message
                    .push_str(&format!("; attribution only at refresh: {error}"));
            }
            if let Some(error) = &state.capture_error {
                status.active = false;
                status.message = format!(
                    "Process capture stopped: {error}; interface counters remain available"
                );
            }
        }
        if state.inventory.restricted {
            status.message.push_str("; some /proc owners inaccessible");
        }
        if state.inventory.limited || counter_limit {
            status
                .message
                .push_str("; socket/owner counter limit reached");
        }
        if missing_interface {
            status.active = false;
            status.message = format!(
                "F2: choose interface; {} is unavailable",
                interface.unwrap_or_default()
            );
        }
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
            deferred: Vec::new(),
            worker_error: None,
        }
    }

    /// Refreshes sockets, then attributes the flows captured so far while the
    /// sockets that carried them are still current or briefly retained.
    fn tick(&mut self, interfaces: &[KernelInterface]) {
        self.inventory.refresh();
        let Some(capture) = &self.capture else {
            return;
        };
        let batch = capture.drain();
        let now = Instant::now();
        self.status.dropped = self.status.dropped.saturating_add(batch.dropped);
        self.status.overflow = self.status.overflow.saturating_add(batch.overflow);
        self.status.unsupported = self.status.unsupported.saturating_add(batch.unsupported);
        self.status.truncated = self.status.truncated.saturating_add(batch.truncated);
        if batch.error.is_some() {
            self.capture_error = batch.error;
        }
        for deferred in std::mem::take(&mut self.deferred) {
            self.attribute(
                &deferred.flow,
                deferred.receive,
                deferred.bytes,
                deferred.since,
                now,
                interfaces,
            );
        }
        for (flow, bytes) in batch.flows {
            let (rx, tx) = traffic_sides(&flow, interfaces);
            for receive in [false, true] {
                if (receive && rx) || (!receive && tx) {
                    self.attribute(&flow, receive, bytes, now, now, interfaces);
                }
            }
        }
        for ((index, direction), untracked) in batch.untracked {
            let loopback = interfaces
                .iter()
                .any(|candidate| candidate.index == index && candidate.loopback);
            let bytes = match direction {
                _ if loopback => Bytes {
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
                .record_unknown(index, bytes, now, &mut self.deltas.unknown);
        }
    }

    fn attribute(
        &mut self,
        flow: &Flow,
        receive: bool,
        bytes: u64,
        since: Instant,
        now: Instant,
        interfaces: &[KernelInterface],
    ) {
        let increment = if receive {
            Bytes { rx: bytes, tx: 0 }
        } else {
            Bytes { rx: 0, tx: bytes }
        };
        let resolution = local_socket_endpoints(flow, receive, interfaces)
            .map_or(Resolution::Unattributed, |(local, remote)| {
                self.inventory.resolve(flow.protocol, local, remote)
            });
        match resolution {
            Resolution::Owned(socket) if !published_port_proxy(flow, socket, interfaces) => {
                if self.counters.record_owned(
                    flow.interface_index,
                    socket,
                    increment,
                    now,
                    &mut self.deltas,
                ) {
                    return;
                }
            }
            // The socket exists but its owner scan is pending; retry next tick.
            Resolution::Pending
                if now.saturating_duration_since(since) < MAX_DEFER
                    && self.deferred.len() < MAX_DEFERRED =>
            {
                self.deferred.push(Deferred {
                    flow: flow.clone(),
                    receive,
                    bytes,
                    since,
                });
                return;
            }
            _ => {}
        }
        self.counters.record_unknown(
            flow.interface_index,
            increment,
            now,
            &mut self.deltas.unknown,
        );
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
        self.counters.unattributed.retain(|index, entry| {
            interfaces.iter().any(|interface| interface.index == *index)
                || now.duration_since(entry.last_seen) <= COUNTER_RETENTION
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
        for socket in self
            .inventory
            .sockets
            .iter()
            .filter(|socket| socket.current)
        {
            if !socket_in_scope(socket, selected, interfaces) {
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
        for (&(index, identity), entry) in &self.counters.processes {
            if !index_in_scope(index, selected) {
                continue;
            }
            // Traffic within this interval stays visible even when the
            // sockets closed more than RECENT_TRAFFIC before a long sample.
            if !processes.contains_key(&identity)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas.processes.contains_key(&(index, identity))
            {
                continue;
            }
            let row = processes
                .entry(identity)
                .or_insert_with(|| process_row(&entry.owner));
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.processes.get(&(index, identity)) {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for ((index, socket_key, identity), entry) in &self.counters.connections {
            if !index_in_scope(*index, selected) {
                continue;
            }
            let key = (socket_key.clone(), Some(*identity));
            if !connections.contains_key(&key)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
                && !deltas
                    .connections
                    .contains_key(&(*index, socket_key.clone(), *identity))
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
                && let Some(bytes) =
                    deltas
                        .connections
                        .get(&(*index, socket_key.clone(), *identity))
            {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for (&index, counter) in &self.counters.unattributed {
            if !index_in_scope(index, selected) {
                continue;
            }
            unknown.rx_bytes = unknown.rx_bytes.saturating_add(counter.bytes.rx);
            unknown.tx_bytes = unknown.tx_bytes.saturating_add(counter.bytes.tx);
            if rates_available && let Some(bytes) = deltas.unknown.get(&index) {
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
    /// changed, never per packet batch.
    fn record_owned(
        &mut self,
        index: u32,
        socket: &Socket,
        bytes: Bytes,
        now: Instant,
        deltas: &mut Deltas,
    ) -> bool {
        let Some(owner) = socket.owner() else {
            return false;
        };
        let process_key = (index, owner.identity);
        let connection_key = (index, socket.key.clone(), owner.identity);
        if (self.processes.len() >= MAX_PROCESS_COUNTERS
            && !self.processes.contains_key(&process_key))
            || (self.connections.len() >= MAX_CONNECTION_COUNTERS
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
        index: u32,
        bytes: Bytes,
        now: Instant,
        delta: &mut HashMap<u32, Bytes>,
    ) {
        if self.unattributed.len() >= MAX_INTERFACE_COUNTERS
            && !self.unattributed.contains_key(&index)
        {
            self.limit_hit = true;
            return;
        }
        self.unattributed
            .entry(index)
            .or_insert_with(|| Counter::new(now))
            .add(bytes, now);
        delta.entry(index).or_default().add(bytes);
    }
}

fn counter_rate(current: u64, previous: u64, interval: f64) -> f64 {
    current.saturating_sub(previous) as f64 / interval
}

fn index_in_scope(index: u32, selected: Option<u32>) -> bool {
    selected.is_none_or(|selected| selected == index)
}

fn socket_in_scope(socket: &Socket, selected: Option<u32>, interfaces: &[KernelInterface]) -> bool {
    let Some(selected) = selected else {
        return true;
    };
    let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.index == selected)
    else {
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

fn is_local_ip(interfaces: &[KernelInterface], ip: IpAddr) -> bool {
    interfaces
        .iter()
        .any(|interface| interface_has_ip(interface, ip))
}

/// Traffic between two local endpoints, observed once on a loopback link.
fn loopback_path(flow: &Flow, interfaces: &[KernelInterface]) -> bool {
    interfaces
        .iter()
        .any(|interface| interface.index == flow.interface_index && interface.loopback)
        || (flow.interface_index == 0
            && is_local_ip(interfaces, flow.source)
            && is_local_ip(interfaces, flow.destination))
}

fn traffic_sides(flow: &Flow, interfaces: &[KernelInterface]) -> (bool, bool) {
    let source_local = is_local_ip(interfaces, flow.source);
    let destination_local = is_local_ip(interfaces, flow.destination);
    if loopback_path(flow, interfaces) {
        // libpcap exposes one outgoing observation for loopback; it belongs to
        // both the sender TX and receiver RX, never twice to either endpoint.
        return (true, true);
    }
    match flow.direction {
        Direction::Incoming => (true, false),
        Direction::Outgoing => (false, true),
        Direction::Unknown => (destination_local, source_local),
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
    interfaces: &[KernelInterface],
) -> Option<(SocketAddr, SocketAddr)> {
    let (local, remote) = socket_endpoints(flow, receive)?;
    // Captured interface direction is not proof of a local socket endpoint.
    // Bridges, forwarding and container links also expose nonlocal traffic;
    // matching it to a wildcard listener merely by port assigns the wrong PID.
    // Multicast/broadcast receiver membership is not known from /proc, so leave
    // those receive bytes unattributed too. Sender attribution remains possible.
    is_local_ip(interfaces, local.ip()).then_some((local, remote))
}

/// Docker publishes ports by DNAT in PREROUTING, but AF_PACKET observes packets
/// before translation, so forwarded container traffic still carries the host
/// port of docker-proxy's wildcard listener. With Docker's NAT rules that proxy
/// only serves loopback connections, and its accepted connections match
/// exactly. Do not credit wildcard-only matches from other links to it; the
/// bytes stay unattributed instead of naming the wrong process.
fn published_port_proxy(flow: &Flow, socket: &Socket, interfaces: &[KernelInterface]) -> bool {
    let remote = socket.key.remote;
    remote.ip().is_unspecified()
        && remote.port() == 0
        && socket
            .owner()
            .is_some_and(|owner| owner.name == "docker-proxy")
        && !loopback_path(flow, interfaces)
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
        });
    }
    if interfaces.is_empty() {
        bail!("/proc/net/dev contains no network interfaces");
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
            .entry(name)
            .or_insert_with_key(|name| interface_index(name));
        let Some(index) = index else {
            continue;
        };
        let link = result.entry(index).or_default();
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

/// The address view the background worker needs for attribution, without
/// the per-device sysfs and counter reads of a full snapshot.
fn local_interfaces() -> Vec<KernelInterface> {
    interface_addresses()
        .into_iter()
        .map(|(index, link)| KernelInterface {
            info: Interface::default(),
            index,
            addresses: link.addresses,
            loopback: link.loopback,
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
        assert_eq!(traffic_sides(&packet, &interfaces), (true, true));
        assert_eq!(socket_endpoints(&packet, false).unwrap().0.port(), 12345);
        assert_eq!(socket_endpoints(&packet, true).unwrap().0.port(), 8080);
    }

    #[test]
    fn interface_selection_uses_capture_ifindex_not_ip_guesses() {
        assert!(index_in_scope(42, Some(42)));
        assert!(!index_in_scope(43, Some(42)));
        assert!(!index_in_scope(0, Some(42)));
        assert!(index_in_scope(43, None));
        let interfaces = vec![interface(2, false, "192.0.2.1")];
        assert_eq!(
            traffic_sides(&flow(Direction::Outgoing, 2), &interfaces),
            (false, true)
        );
        assert_eq!(
            traffic_sides(&flow(Direction::Incoming, 2), &interfaces),
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
            1,
            &socket,
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
            1,
            &socket,
            Bytes { rx: 0, tx: 100 },
            now,
            &mut deltas
        ));
        socket.owners[0].identity.start_time = 2;
        socket.owners[0].name = "second".to_string();
        assert!(attribution.counters.record_owned(
            1,
            &socket,
            Bytes { rx: 0, tx: 50 },
            now,
            &mut deltas
        ));
        assert!(attribution.counters.record_owned(
            2,
            &socket,
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
        assert_eq!(traffic_sides(&packet, &interfaces), (true, false));
        assert!(local_socket_endpoints(&packet, true, &interfaces).is_none());
        packet.direction = Direction::Outgoing;
        assert!(local_socket_endpoints(&packet, false, &interfaces).is_none());
        packet.destination = "192.0.2.1".parse().unwrap();
        assert!(local_socket_endpoints(&packet, true, &interfaces).is_some());
        packet.destination = "224.0.0.251".parse().unwrap();
        assert!(local_socket_endpoints(&packet, true, &interfaces).is_none());
        packet.source = "192.0.2.1".parse().unwrap();
        assert!(local_socket_endpoints(&packet, false, &interfaces).is_some());
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
            local_interfaces()
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
        assert!(published_port_proxy(&packet, &listener, &interfaces));
        // Loopback connections really reach the proxy.
        assert!(!published_port_proxy(
            &flow(Direction::Outgoing, 1),
            &listener,
            &interfaces
        ));
        // Accepted proxy connections and other listeners keep attribution.
        let accepted = owned("192.0.2.1:8080", "198.51.100.1:5000", 2, "docker-proxy");
        assert!(!published_port_proxy(&packet, &accepted, &interfaces));
        let server = owned("0.0.0.0:8080", "0.0.0.0:0", 3, "nginx");
        assert!(!published_port_proxy(&packet, &server, &interfaces));
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
        attribution.attribute(&packet, true, 100, now, now, &interfaces);
        assert_eq!(attribution.deferred.len(), 1);
        assert!(attribution.counters.unattributed.is_empty());
        // After the retry window the bytes are reported as unattributed.
        let later = now + MAX_DEFER;
        attribution.attribute(&packet, true, 100, now, later, &interfaces);
        assert_eq!(attribution.deferred.len(), 1);
        assert_eq!(attribution.counters.unattributed[&2].bytes.rx, 100);
    }
}
