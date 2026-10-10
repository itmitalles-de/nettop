//! An owned, non-promiscuous libpcap session with bounded in-memory aggregation.

use super::packet::{self, Direction, Flow, Fragment, FragmentKey, Packet, Protocol};
use crate::model::CaptureNote;
use anyhow::{Context, Result, anyhow, bail};
use libloading::Library;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SNAPLEN: i32 = 192;
const MAX_FLOWS: usize = 16_384;
const MAX_INTERFACES: usize = 256;
const MAX_FRAGMENTED_DATAGRAMS: usize = 4_096;
const FRAGMENT_LIFETIME: Duration = Duration::from_secs(2);

/// A capture start failure the UI can explain in its own language.
#[derive(Debug)]
pub(super) struct StartError(pub CaptureNote);

impl std::fmt::Display for StartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&crate::i18n::Lang::En.capture_note(&self.0))
    }
}

impl std::error::Error for StartError {}

#[repr(C)]
struct PcapHeader {
    timestamp: libc::timeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PcapStats {
    received: u32,
    dropped: u32,
    interface_dropped: u32,
}

type Pcap = libc::c_void;
type Setter = unsafe extern "C" fn(*mut Pcap, libc::c_int) -> libc::c_int;

struct Api {
    create: unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char) -> *mut Pcap,
    snaplen: Setter,
    promiscuous: Setter,
    timeout: Setter,
    buffer_size: Setter,
    immediate: Option<Setter>,
    activate: unsafe extern "C" fn(*mut Pcap) -> libc::c_int,
    set_datalink: Setter,
    datalink: unsafe extern "C" fn(*mut Pcap) -> libc::c_int,
    nonblock: unsafe extern "C" fn(*mut Pcap, libc::c_int, *mut libc::c_char) -> libc::c_int,
    next: unsafe extern "C" fn(*mut Pcap, *mut *const PcapHeader, *mut *const u8) -> libc::c_int,
    stats: unsafe extern "C" fn(*mut Pcap, *mut PcapStats) -> libc::c_int,
    error: unsafe extern "C" fn(*mut Pcap) -> *const libc::c_char,
    close: unsafe extern "C" fn(*mut Pcap),
    _library: Library,
}

impl Api {
    fn load() -> Result<Self> {
        let mut library = None;
        for name in ["libpcap.so.0.8", "libpcap.so.1", "libpcap.so"] {
            // Symbols are retained only while the owning Library remains alive.
            if let Ok(found) = unsafe { Library::new(name) } {
                library = Some(found);
                break;
            }
        }
        let library = library.ok_or(StartError(CaptureNote::LibpcapMissing))?;
        unsafe {
            Ok(Self {
                create: *library.get(b"pcap_create\0")?,
                snaplen: *library.get(b"pcap_set_snaplen\0")?,
                promiscuous: *library.get(b"pcap_set_promisc\0")?,
                timeout: *library.get(b"pcap_set_timeout\0")?,
                buffer_size: *library.get(b"pcap_set_buffer_size\0")?,
                immediate: library
                    .get::<Setter>(b"pcap_set_immediate_mode\0")
                    .ok()
                    .map(|symbol| *symbol),
                activate: *library.get(b"pcap_activate\0")?,
                set_datalink: *library.get(b"pcap_set_datalink\0")?,
                datalink: *library.get(b"pcap_datalink\0")?,
                nonblock: *library.get(b"pcap_setnonblock\0")?,
                next: *library.get(b"pcap_next_ex\0")?,
                stats: *library.get(b"pcap_stats\0")?,
                error: *library.get(b"pcap_geterr\0")?,
                close: *library.get(b"pcap_close\0")?,
                _library: library,
            })
        }
    }

    fn message(&self, handle: *mut Pcap) -> String {
        unsafe {
            let pointer = (self.error)(handle);
            if pointer.is_null() {
                "unknown libpcap error".to_string()
            } else {
                CStr::from_ptr(pointer).to_string_lossy().into_owned()
            }
        }
    }
}

struct Session {
    handle: *mut Pcap,
    api: Api,
    datalink: i32,
}

impl Session {
    fn open() -> Result<Self> {
        let api = Api::load()?;
        let mut error_buffer = [0 as libc::c_char; 256];
        let device = CString::new("any").unwrap();
        let handle = unsafe { (api.create)(device.as_ptr(), error_buffer.as_mut_ptr()) };
        if handle.is_null() {
            let message = unsafe { CStr::from_ptr(error_buffer.as_ptr()) }.to_string_lossy();
            return Err(StartError(CaptureNote::SetupNeeded {
                detail: message.into_owned(),
            })
            .into());
        }
        // A session owns the handle even if a configuration step fails.
        let mut session = Self {
            handle,
            api,
            datalink: 0,
        };
        unsafe {
            for (setter, value) in [
                (session.api.snaplen, SNAPLEN),
                (session.api.promiscuous, 0),
                (session.api.timeout, 100),
                (session.api.buffer_size, 1_048_576),
            ] {
                if setter(handle, value) != 0 {
                    bail!("{}", session.api.message(handle));
                }
            }
            if let Some(immediate) = session.api.immediate {
                let _ = immediate(handle, 1);
            }
            let activated = (session.api.activate)(handle);
            if activated < 0 {
                let detail = session.api.message(handle);
                return Err(StartError(if activated == -8 || activated == -11 {
                    CaptureNote::SetupNeeded { detail }
                } else {
                    CaptureNote::Unavailable { detail }
                })
                .into());
            }
            // SLL2 tags every frame with its interface, so interface selection
            // never relies on guessing from addresses or socket queue sizes.
            let _ = (session.api.set_datalink)(handle, 276);
            session.datalink = (session.api.datalink)(handle);
            if !matches!(session.datalink, 1 | 12 | 101 | 113 | 276) {
                bail!("unsupported libpcap link format {}", session.datalink);
            }
            if (session.api.nonblock)(handle, 1, error_buffer.as_mut_ptr()) < 0 {
                bail!("{}", session.api.message(handle));
            }
        }
        Ok(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.handle) };
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Untracked {
    pub bytes: u64,
    pub packets: u64,
}

/// Remembers the ports of recently seen first fragments so later fragments of
/// the same datagram can be attributed. Bounded in size and lifetime; only the
/// header fields that identify the datagram and its ports are retained.
#[derive(Default)]
struct Fragments {
    ports: HashMap<FragmentKey, (Protocol, u16, u16, Instant)>,
}

impl Fragments {
    fn apply(&mut self, packet: &mut Packet, now: Instant) {
        match packet.fragment {
            Some(Fragment::First(key)) => {
                let (Some(source), Some(destination)) =
                    (packet.flow.source_port, packet.flow.destination_port)
                else {
                    return;
                };
                if self.ports.len() >= MAX_FRAGMENTED_DATAGRAMS && !self.ports.contains_key(&key) {
                    self.expire(now);
                }
                if self.ports.len() < MAX_FRAGMENTED_DATAGRAMS || self.ports.contains_key(&key) {
                    self.ports
                        .insert(key, (packet.flow.protocol, source, destination, now));
                }
            }
            Some(Fragment::Later(key)) => {
                if let Some(&(protocol, source, destination, seen)) = self.ports.get(&key)
                    && now.saturating_duration_since(seen) <= FRAGMENT_LIFETIME
                {
                    packet.flow.protocol = protocol;
                    packet.flow.source_port = Some(source);
                    packet.flow.destination_port = Some(destination);
                }
            }
            None => {}
        }
    }

    fn expire(&mut self, now: Instant) {
        self.ports
            .retain(|_, entry| now.saturating_duration_since(entry.3) <= FRAGMENT_LIFETIME);
    }
}

/// pcap_stats reports cumulative 32-bit counters that wrap; only the change
/// since the previous reading belongs to the current interval.
fn dropped_since(previous: &PcapStats, current: &PcapStats) -> u64 {
    u64::from(current.dropped.wrapping_sub(previous.dropped))
        + u64::from(
            current
                .interface_dropped
                .wrapping_sub(previous.interface_dropped),
        )
}

/// Kernel-clock bounds for all packets aggregated under one tuple. A tuple
/// spanning two socket incarnations is deliberately not split by guesswork.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TimedBytes {
    pub bytes: u64,
    pub first: u64,
    pub last: u64,
}

impl TimedBytes {
    fn add(&mut self, bytes: u64, timestamp: u64) {
        if self.bytes == 0 {
            self.first = timestamp;
            self.last = timestamp;
        } else if timestamp == 0 || self.first == 0 {
            self.first = 0;
            self.last = 0;
        } else {
            self.first = self.first.min(timestamp);
            self.last = self.last.max(timestamp);
        }
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

pub(super) fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}

/// Tracks realtime/monotonic correspondence across pcap drains. Clock steps
/// invalidate timestamps for the maximum accepted packet age, so an old header
/// cannot be moved into another socket's lifetime by a new wall-clock offset.
struct TimestampClock {
    offset: i128,
    sampled: u64,
    invalid_until: u64,
}
impl TimestampClock {
    fn new() -> Self {
        let mut clock = Self {
            offset: 0,
            sampled: 0,
            invalid_until: 0,
        };
        clock.refresh();
        clock
    }
    fn observe(&mut self, mono: u64, realtime: i128, uncertainty: u64) {
        let offset = realtime - i128::from(mono);
        let elapsed = mono.saturating_sub(self.sampled);
        // Allow normal clock slewing plus sampling jitter; an abrupt offset
        // change causes conservative suppression, never best-guess remapping.
        if uncertainty > 10_000
            || (self.sampled != 0
                && (offset - self.offset).unsigned_abs() > u128::from(50_000 + elapsed / 1000))
        {
            self.invalid_until = mono.saturating_add(3_000_000_000);
        }
        self.offset = offset;
        self.sampled = mono;
    }
    fn refresh(&mut self) {
        let before = monotonic_ns();
        let mut real = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ok = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut real) } == 0;
        let after = monotonic_ns();
        if !ok {
            self.invalid_until = after.saturating_add(3_000_000_000);
            return;
        }
        self.observe(
            before + (after - before) / 2,
            i128::from(real.tv_sec) * 1_000_000_000 + i128::from(real.tv_nsec),
            after - before,
        );
    }
    fn convert(&self, timestamp: &libc::timeval) -> u64 {
        if self.sampled < self.invalid_until || !(0..1_000_000).contains(&timestamp.tv_usec) {
            return 0;
        }
        let realtime =
            i128::from(timestamp.tv_sec) * 1_000_000_000 + i128::from(timestamp.tv_usec) * 1000;
        let translated = realtime - self.offset;
        if translated <= 0
            || translated > i128::from(self.sampled) + 10_000
            || i128::from(self.sampled) - translated > 3_000_000_000
        {
            0
        } else {
            translated as u64
        }
    }
}

/// Captured flows plus the capture problems observed since the previous drain.
#[derive(Default)]
pub(super) struct Batch {
    pub flows: HashMap<Flow, TimedBytes>,
    /// Extended mode preserves individual header-only observations so a TCP
    /// handshake cannot widen a data packet beyond its actor syscall window.
    pub timed_flows: Vec<(Flow, TimedBytes)>,
    pub untracked: HashMap<(u32, Direction), Untracked>,
    pub dropped: u64,
    pub overflow: u64,
    pub unsupported: u64,
    pub truncated: u64,
    pub error: Option<String>,
    pub timestamp_invalid: u64,
}

impl Batch {
    fn push(&mut self, packet: Packet, timestamp: u64) {
        if cfg!(feature = "ebpf") && timestamp == 0 {
            self.timestamp_invalid = self.timestamp_invalid.saturating_add(1);
        }
        if cfg!(feature = "ebpf") && self.timed_flows.len() < MAX_FLOWS {
            self.timed_flows.push((
                packet.flow,
                TimedBytes {
                    bytes: packet.bytes,
                    first: timestamp,
                    last: timestamp,
                },
            ));
        } else if !cfg!(feature = "ebpf")
            && (self.flows.len() < MAX_FLOWS || self.flows.contains_key(&packet.flow))
        {
            let bytes = self.flows.entry(packet.flow).or_default();
            bytes.add(packet.bytes, timestamp);
        } else {
            self.overflow = self.overflow.saturating_add(1);
            let key = (packet.flow.interface_index, packet.flow.direction);
            if self.untracked.len() < MAX_INTERFACES || self.untracked.contains_key(&key) {
                let count = self.untracked.entry(key).or_default();
                count.bytes = count.bytes.saturating_add(packet.bytes);
                count.packets = count.packets.saturating_add(1);
            }
        }
    }
}

pub(super) struct Capture {
    buffer: Arc<Mutex<Batch>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    pub interface_indexes: bool,
}

impl Capture {
    pub(super) fn start() -> Result<Self> {
        let buffer = Arc::new(Mutex::new(Batch::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_buffer = Arc::clone(&buffer);
        let thread_stop = Arc::clone(&stop);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("nettop-capture".to_string())
            .spawn(move || {
                let mut clock = TimestampClock::new();
                let session = match Session::open() {
                    Ok(session) => session,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return;
                    }
                };
                // Capabilities belong to individual threads. Keep the open capture
                // descriptor, but remove the worker's inherited privileges before
                // publishing readiness or processing any packets.
                if let Err(error) = crate::privilege::drop_capture_privileges() {
                    let _ = sender.send(Err(error.context("dropping packet capture privileges")));
                    return;
                }
                if sender.send(Ok(session.datalink == 276)).is_err() {
                    return;
                }
                let mut stats_at = Instant::now();
                let mut previous_stats = PcapStats::default();
                let mut fragments = Fragments::default();
                let mut fragments_expired_at = Instant::now();
                while !thread_stop.load(Ordering::Relaxed) {
                    clock.refresh();
                    let mut packets = Vec::with_capacity(256);
                    let mut unsupported = 0_u64;
                    let mut truncated = 0_u64;
                    let mut failed = None;
                    for _ in 0..2048 {
                        let mut header = std::ptr::null();
                        let mut data = std::ptr::null();
                        let result =
                            unsafe { (session.api.next)(session.handle, &mut header, &mut data) };
                        if result == 0 {
                            break;
                        }
                        if result < 0 {
                            failed = Some(session.api.message(session.handle));
                            break;
                        }
                        if header.is_null() || data.is_null() {
                            truncated += 1;
                            continue;
                        }
                        let header = unsafe { &*header };
                        let captured = unsafe {
                            std::slice::from_raw_parts(
                                data,
                                (header.caplen as usize).min(SNAPLEN as usize),
                            )
                        };
                        match packet::parse(captured, header.len, session.datalink) {
                            Ok(packet) => packets.push((packet, header.timestamp)),
                            Err(packet::ParseError::Unsupported) => unsupported += 1,
                            Err(_) => truncated += 1,
                        }
                    }
                    clock.refresh();
                    let idle = packets.is_empty() && unsupported == 0 && truncated == 0;
                    let now = Instant::now();
                    for (packet, _) in &mut packets {
                        fragments.apply(packet, now);
                    }
                    if now.saturating_duration_since(fragments_expired_at) >= FRAGMENT_LIFETIME {
                        fragments.expire(now);
                        fragments_expired_at = now;
                    }
                    if let Ok(mut buffer) = thread_buffer.lock() {
                        for (packet, timestamp) in packets {
                            buffer.push(packet, clock.convert(&timestamp));
                        }
                        buffer.unsupported = buffer.unsupported.saturating_add(unsupported);
                        buffer.truncated = buffer.truncated.saturating_add(truncated);
                        if stats_at.elapsed() >= Duration::from_secs(1) {
                            let mut stats = PcapStats::default();
                            if unsafe { (session.api.stats)(session.handle, &mut stats) } == 0 {
                                buffer.dropped = buffer
                                    .dropped
                                    .saturating_add(dropped_since(&previous_stats, &stats));
                                previous_stats = stats;
                            }
                            stats_at = Instant::now();
                        }
                        if let Some(error) = failed.as_ref() {
                            buffer.error = Some(error.clone());
                        }
                    }
                    if failed.is_some() {
                        return;
                    }
                    if idle {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            })
            .context("starting packet capture worker")?;
        match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(interface_indexes)) => Ok(Self {
                buffer,
                stop,
                worker: Some(worker),
                interface_indexes,
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                stop.store(true, Ordering::Relaxed);
                let _ = worker.join();
                Err(anyhow!("starting packet capture: {error}"))
            }
        }
    }

    /// Takes flows and problem counters observed since the previous drain, so
    /// a startup burst does not keep reporting drops forever.
    pub(super) fn drain(&self) -> Batch {
        let Ok(mut buffer) = self.buffer.lock() else {
            return Batch {
                error: Some("capture worker lock failed".to_string()),
                ..Batch::default()
            };
        };
        Batch {
            flows: std::mem::take(&mut buffer.flows),
            timed_flows: std::mem::take(&mut buffer.timed_flows),
            untracked: std::mem::take(&mut buffer.untracked),
            dropped: std::mem::take(&mut buffer.dropped),
            overflow: std::mem::take(&mut buffer.overflow),
            unsupported: std::mem::take(&mut buffer.unsupported),
            truncated: std::mem::take(&mut buffer.truncated),
            error: buffer.error.clone(),
            timestamp_invalid: std::mem::take(&mut buffer.timestamp_invalid),
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn realtime_steps_cannot_move_packets_into_another_lifetime() {
        let mut c = TimestampClock {
            offset: 0,
            sampled: 0,
            invalid_until: 0,
        };
        c.observe(10_000_000_000, 100_000_000_000, 100);
        let packet = libc::timeval {
            tv_sec: 100,
            tv_usec: 0,
        };
        assert_eq!(c.convert(&packet), 10_000_000_000);
        c.observe(10_100_000_000, 100_600_000_000, 100);
        assert_eq!(c.convert(&packet), 0);
        c.observe(13_200_000_000, 103_700_000_000, 100);
        assert_eq!(c.convert(&packet), 0, "old packet is outside maximum age");
        assert_eq!(
            c.convert(&libc::timeval {
                tv_sec: 103,
                tv_usec: 700_000
            }),
            13_200_000_000
        );
    }

    #[test]
    fn flow_storage_is_bounded_and_excess_bytes_remain_visible() {
        let mut batch = Batch::default();
        for port in 0..MAX_FLOWS + 1 {
            batch.push(
                Packet {
                    flow: Flow {
                        source: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        destination: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        source_port: Some(port as u16),
                        destination_port: Some(123),
                        protocol: Protocol::Udp,
                        interface_index: 1,
                        direction: Direction::Outgoing,
                    },
                    bytes: 128,
                    fragment: None,
                },
                1,
            );
        }
        assert_eq!(batch.flows.len() + batch.timed_flows.len(), MAX_FLOWS);
        assert_eq!(batch.overflow, 1);
        assert_eq!(
            batch
                .untracked
                .get(&(1, Direction::Outgoing))
                .unwrap()
                .bytes,
            128
        );
    }

    #[test]
    fn pcap_drop_counters_report_wrapping_deltas() {
        let stats = |dropped, interface_dropped| PcapStats {
            received: 0,
            dropped,
            interface_dropped,
        };
        assert_eq!(dropped_since(&stats(0, 0), &stats(5, 2)), 7);
        assert_eq!(dropped_since(&stats(5, 2), &stats(5, 2)), 0);
        assert_eq!(dropped_since(&stats(u32::MAX - 1, 0), &stats(3, 0)), 5);
    }

    #[test]
    fn later_fragments_reuse_first_fragment_ports_briefly() {
        let key = FragmentKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            id: 7,
            protocol: 17,
        };
        let packet = |ports: Option<(u16, u16)>, fragment| Packet {
            flow: Flow {
                source: key.source,
                destination: key.destination,
                source_port: ports.map(|ports| ports.0),
                destination_port: ports.map(|ports| ports.1),
                protocol: Protocol::Udp,
                interface_index: 1,
                direction: Direction::Outgoing,
            },
            bytes: 1500,
            fragment: Some(fragment),
        };
        let mut fragments = Fragments::default();
        let now = Instant::now();
        let mut later = packet(None, Fragment::Later(key));
        fragments.apply(&mut later, now);
        assert_eq!(later.flow.source_port, None, "no first fragment seen yet");
        fragments.apply(&mut packet(Some((5000, 53)), Fragment::First(key)), now);
        fragments.apply(&mut later, now);
        assert_eq!(
            (later.flow.source_port, later.flow.destination_port),
            (Some(5000), Some(53))
        );
        let mut other = packet(None, Fragment::Later(FragmentKey { id: 8, ..key }));
        fragments.apply(&mut other, now);
        assert_eq!(other.flow.source_port, None, "identification must match");
        let mut stale = packet(None, Fragment::Later(key));
        fragments.apply(&mut stale, now + FRAGMENT_LIFETIME + Duration::from_secs(1));
        assert_eq!(stale.flow.source_port, None, "entries expire");
        fragments.expire(now + FRAGMENT_LIFETIME + Duration::from_secs(1));
        assert!(fragments.ports.is_empty());
        for id in 0..MAX_FRAGMENTED_DATAGRAMS as u32 + 10 {
            fragments.apply(
                &mut packet(Some((5000, 53)), Fragment::First(FragmentKey { id, ..key })),
                now,
            );
        }
        assert_eq!(fragments.ports.len(), MAX_FRAGMENTED_DATAGRAMS);
    }
}
