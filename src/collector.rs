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
use sockets::{Inventory, Owner, ProcessIdentity, Socket, SocketKey, canonical_ip};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const MAX_PROCESS_COUNTERS: usize = 16_384;
const MAX_CONNECTION_COUNTERS: usize = 32_768;
const MAX_INTERFACE_COUNTERS: usize = 256;
const COUNTER_RETENTION: Duration = Duration::from_secs(300);
const RECENT_TRAFFIC: Duration = Duration::from_secs(3);

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

/// A collector owns one capture worker; dropping it closes its own pcap session.
pub struct Collector {
    started: Instant,
    last_sample: Instant,
    previous_interfaces: HashMap<String, (u32, u64, u64)>,
    inventory: Inventory,
    capture: Option<capture::Capture>,
    capture_message: String,
    processes: HashMap<ProcessCounterKey, ProcessCounter>,
    connections: HashMap<ConnectionCounterKey, ConnectionCounter>,
    unattributed: HashMap<u32, Counter>,
    counter_limit: bool,
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
        Ok(Self {
            started,
            last_sample,
            previous_interfaces,
            inventory,
            capture,
            capture_message,
            processes: HashMap::new(),
            connections: HashMap::new(),
            unattributed: HashMap::new(),
            counter_limit: false,
        })
    }

    /// `None` means all captured interfaces, including virtual links. The status
    /// warns about duplicate observations across host bridges and veth devices.
    pub fn sample(&mut self, interface: Option<&str>) -> Result<Snapshot> {
        self.inventory.refresh();
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
        self.prune(now, &interfaces);

        let mut process_delta: HashMap<ProcessCounterKey, Bytes> = HashMap::new();
        let mut connection_delta: HashMap<ConnectionCounterKey, Bytes> = HashMap::new();
        let mut unknown_delta: HashMap<u32, Bytes> = HashMap::new();
        let mut status = CaptureStatus {
            active: self.capture.is_some(),
            message: self.capture_message.clone(),
            dropped: 0,
        };
        if let Some(capture) = &self.capture {
            let indexes_available = capture.interface_indexes;
            let batch = capture.drain();
            status.dropped = batch.dropped.saturating_add(batch.overflow);
            if interface.is_some() && !indexes_available {
                status.active = false;
                status.message = "Process rates unavailable: libpcap lacks SLL2 interface indexes; upgrade libpcap or use -i all".to_string();
            } else if interface.is_none() {
                status.message = "ALL interfaces: bridge/veth packets can repeat; process rates count captured IP bytes".to_string();
            } else {
                status.message = "Process rates: captured IP bytes; socket/PID owners sampled, brief sockets may be unattributed".to_string();
            }
            for (flow, bytes) in batch.flows {
                let (rx, tx) = traffic_sides(&flow, &interfaces);
                for receive in [false, true] {
                    if (receive && !rx) || (!receive && !tx) {
                        continue;
                    }
                    let increment = if receive {
                        Bytes { rx: bytes, tx: 0 }
                    } else {
                        Bytes { rx: 0, tx: bytes }
                    };
                    let socket = local_socket_endpoints(&flow, receive, &interfaces)
                        .and_then(|(local, remote)| {
                            self.inventory.resolve(flow.protocol, local, remote)
                        })
                        .cloned();
                    let attributed = socket.as_ref().is_some_and(|socket| {
                        self.record_owned(
                            flow.interface_index,
                            socket,
                            increment,
                            now,
                            &mut process_delta,
                            &mut connection_delta,
                        )
                    });
                    if !attributed {
                        self.record_unknown(
                            flow.interface_index,
                            increment,
                            now,
                            &mut unknown_delta,
                        );
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
                self.record_unknown(index, bytes, now, &mut unknown_delta);
            }
            if batch.dropped > 0 {
                status
                    .message
                    .push_str(&format!("; pcap missed {} packets", batch.dropped));
            }
            if batch.overflow > 0 {
                status.message.push_str(&format!(
                    "; flow limit: {} packets unattributed",
                    batch.overflow
                ));
            }
            if batch.unsupported > 0 || batch.truncated > 0 {
                status.message.push_str(&format!(
                    "; non-IP/unsupported {} / unreadable headers {}",
                    batch.unsupported, batch.truncated
                ));
            }
            if let Some(error) = batch.error {
                status.active = false;
                status.message = format!(
                    "Process capture stopped: {error}; interface counters remain available"
                );
            }
        }
        if self.inventory.restricted {
            status.message.push_str("; some /proc owners inaccessible");
        }
        if self.inventory.limited || self.counter_limit {
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
        let (processes, connections) = self.rows(
            selected,
            &interfaces,
            now,
            interval,
            &process_delta,
            &connection_delta,
            &unknown_delta,
            status.active,
        );
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
        self.processes.retain(|(_, identity), entry| {
            current_processes.contains(identity)
                || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
        });
        self.connections.retain(|(_, key, identity), entry| {
            current_sockets.contains(&(key.clone(), *identity))
                || now.duration_since(entry.counter.last_seen) <= COUNTER_RETENTION
        });
        self.unattributed.retain(|index, entry| {
            interfaces.iter().any(|interface| interface.index == *index)
                || now.duration_since(entry.last_seen) <= COUNTER_RETENTION
        });
    }

    fn record_owned(
        &mut self,
        index: u32,
        socket: &Socket,
        bytes: Bytes,
        now: Instant,
        process_delta: &mut HashMap<ProcessCounterKey, Bytes>,
        connection_delta: &mut HashMap<ConnectionCounterKey, Bytes>,
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
            self.counter_limit = true;
            return false;
        }
        let process = self
            .processes
            .entry(process_key)
            .or_insert_with(|| ProcessCounter {
                owner: owner.clone(),
                counter: Counter::new(now),
            });
        process.owner = owner.clone();
        process.counter.add(bytes, now);
        process_delta.entry(process_key).or_default().add(bytes);
        let connection = self
            .connections
            .entry(connection_key.clone())
            .or_insert_with(|| ConnectionCounter {
                socket: socket.clone(),
                counter: Counter::new(now),
            });
        connection.socket = socket.clone();
        connection.counter.add(bytes, now);
        connection_delta
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
            self.counter_limit = true;
            return;
        }
        self.unattributed
            .entry(index)
            .or_insert_with(|| Counter::new(now))
            .add(bytes, now);
        delta.entry(index).or_default().add(bytes);
    }

    #[allow(clippy::too_many_arguments)]
    fn rows(
        &self,
        selected: Option<u32>,
        interfaces: &[KernelInterface],
        now: Instant,
        interval: f64,
        process_delta: &HashMap<ProcessCounterKey, Bytes>,
        connection_delta: &HashMap<ConnectionCounterKey, Bytes>,
        unknown_delta: &HashMap<u32, Bytes>,
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
        for (&(index, identity), entry) in &self.processes {
            if !index_in_scope(index, selected) {
                continue;
            }
            if !processes.contains_key(&identity)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
            {
                continue;
            }
            let row = processes
                .entry(identity)
                .or_insert_with(|| process_row(&entry.owner));
            row.rx_bytes = row.rx_bytes.saturating_add(entry.counter.bytes.rx);
            row.tx_bytes = row.tx_bytes.saturating_add(entry.counter.bytes.tx);
            if rates_available && let Some(bytes) = process_delta.get(&(index, identity)) {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for ((index, socket_key, identity), entry) in &self.connections {
            if !index_in_scope(*index, selected) {
                continue;
            }
            let key = (socket_key.clone(), Some(*identity));
            if !connections.contains_key(&key)
                && now.duration_since(entry.counter.last_seen) > RECENT_TRAFFIC
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
                && let Some(bytes) = connection_delta.get(&(*index, socket_key.clone(), *identity))
            {
                row.rx_rate += bytes.rx as f64 / interval;
                row.tx_rate += bytes.tx as f64 / interval;
            }
        }
        for (&index, counter) in &self.unattributed {
            if !index_in_scope(index, selected) {
                continue;
            }
            unknown.rx_bytes = unknown.rx_bytes.saturating_add(counter.bytes.rx);
            unknown.tx_bytes = unknown.tx_bytes.saturating_add(counter.bytes.tx);
            if rates_available && let Some(bytes) = unknown_delta.get(&index) {
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

fn traffic_sides(flow: &Flow, interfaces: &[KernelInterface]) -> (bool, bool) {
    let loopback = interfaces
        .iter()
        .any(|interface| interface.index == flow.interface_index && interface.loopback);
    let source_local = interfaces
        .iter()
        .any(|interface| interface_has_ip(interface, flow.source));
    let destination_local = interfaces
        .iter()
        .any(|interface| interface_has_ip(interface, flow.destination));
    if loopback || (flow.interface_index == 0 && source_local && destination_local) {
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
    interfaces
        .iter()
        .any(|interface| interface_has_ip(interface, local.ip()))
        .then_some((local, remote))
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
    let addresses = interface_addresses();
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
        let path = format!("/sys/class/net/{name}");
        let read = |file: &str| {
            fs::read_to_string(format!("{path}/{file}"))
                .ok()
                .map(|value| value.trim().to_string())
        };
        let index = read("ifindex")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let interface_ips = addresses.get(name).cloned().unwrap_or_default();
        let address = interface_ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or(interface_ips.first())
            .map(ToString::to_string);
        let loopback = read("type").is_some_and(|value| value == "772");
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

fn interface_addresses() -> HashMap<String, Vec<IpAddr>> {
    let mut result: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return result;
    }
    let mut current = head;
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_name.is_null() && !interface.ifa_addr.is_null() {
            let name = unsafe { CStr::from_ptr(interface.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let family = unsafe { (*interface.ifa_addr).sa_family as i32 };
            let ip = match family {
                libc::AF_INET => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
                    Some(IpAddr::V4(Ipv4Addr::from(
                        address.sin_addr.s_addr.to_ne_bytes(),
                    )))
                }
                libc::AF_INET6 => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in6) };
                    Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if let Some(ip) = ip {
                result.entry(name).or_default().push(ip);
            }
        }
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    result
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
        let mut collector = Collector {
            started: now,
            last_sample: now,
            previous_interfaces: HashMap::new(),
            inventory: Inventory::new(),
            capture: None,
            capture_message: String::new(),
            processes: HashMap::new(),
            connections: HashMap::new(),
            unattributed: HashMap::new(),
            counter_limit: false,
        };
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
        let mut process_delta = HashMap::new();
        let mut connection_delta = HashMap::new();
        let unknown_delta = HashMap::new();
        assert!(collector.record_owned(
            1,
            &socket,
            Bytes { rx: 0, tx: 100 },
            now,
            &mut process_delta,
            &mut connection_delta
        ));
        socket.owners[0].identity.start_time = 2;
        socket.owners[0].name = "second".to_string();
        assert!(collector.record_owned(
            1,
            &socket,
            Bytes { rx: 0, tx: 50 },
            now,
            &mut process_delta,
            &mut connection_delta
        ));
        assert!(collector.record_owned(
            2,
            &socket,
            Bytes { rx: 0, tx: 200 },
            now,
            &mut process_delta,
            &mut connection_delta
        ));
        let (selected, _) = collector.rows(
            Some(1),
            &[],
            now,
            1.0,
            &process_delta,
            &connection_delta,
            &unknown_delta,
            true,
        );
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected
                .iter()
                .find(|row| row.name == "second")
                .unwrap()
                .tx_bytes,
            50
        );
        let (all, _) = collector.rows(
            None,
            &[],
            now,
            1.0,
            &process_delta,
            &connection_delta,
            &unknown_delta,
            true,
        );
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
        collector.inventory.sockets.push(socket);
        let after_idle = now + COUNTER_RETENTION + Duration::from_secs(1);
        collector.prune(after_idle, &[]);
        assert_eq!(
            collector.processes.len(),
            2,
            "open owner totals survive idle on both interfaces"
        );
        assert_eq!(
            collector.connections.len(),
            2,
            "open socket totals survive idle"
        );
        assert!(
            collector
                .processes
                .keys()
                .all(|(_, identity)| identity.start_time == 2)
        );
        collector.inventory.sockets.clear();
        collector.prune(after_idle, &[]);
        assert!(collector.processes.is_empty());
        assert!(collector.connections.is_empty());
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
}
