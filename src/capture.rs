//! An owned, non-promiscuous libpcap session with bounded in-memory aggregation.

use super::packet::{self, Direction, Flow, Packet};
use anyhow::{Context, Result, anyhow, bail};
use libloading::Library;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const SNAPLEN: i32 = 192;
const MAX_FLOWS: usize = 16_384;
const MAX_INTERFACES: usize = 256;

#[repr(C)]
struct PcapHeader {
    timestamp: libc::timeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
#[derive(Default)]
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
        let library =
            library.context("Install libpcap runtime (libpcap0.8); process rates unavailable")?;
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
            bail!("sudo nettop for process rates; capture unavailable: {message}");
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
                if activated == -8 || activated == -11 {
                    bail!(
                        "sudo nettop for process rates; {}",
                        session.api.message(handle)
                    );
                }
                bail!(
                    "Process capture unavailable: {}",
                    session.api.message(handle)
                );
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

#[derive(Default)]
pub(super) struct Batch {
    pub flows: HashMap<Flow, u64>,
    pub untracked: HashMap<(u32, Direction), Untracked>,
    pub dropped: u64,
    pub overflow: u64,
    pub unsupported: u64,
    pub truncated: u64,
    pub error: Option<String>,
}

impl Batch {
    fn push(&mut self, packet: Packet) {
        if self.flows.len() < MAX_FLOWS || self.flows.contains_key(&packet.flow) {
            let bytes = self.flows.entry(packet.flow).or_default();
            *bytes = bytes.saturating_add(packet.bytes);
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
                let session = match Session::open() {
                    Ok(session) => session,
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        return;
                    }
                };
                if sender.send(Ok(session.datalink == 276)).is_err() {
                    return;
                }
                let mut stats_at = std::time::Instant::now();
                while !thread_stop.load(Ordering::Relaxed) {
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
                            Ok(packet) => packets.push(packet),
                            Err(packet::ParseError::Unsupported) => unsupported += 1,
                            Err(_) => truncated += 1,
                        }
                    }
                    let idle = packets.is_empty() && unsupported == 0 && truncated == 0;
                    if let Ok(mut buffer) = thread_buffer.lock() {
                        for packet in packets {
                            buffer.push(packet);
                        }
                        buffer.unsupported = buffer.unsupported.saturating_add(unsupported);
                        buffer.truncated = buffer.truncated.saturating_add(truncated);
                        if stats_at.elapsed() >= Duration::from_secs(1) {
                            let mut stats = PcapStats::default();
                            if unsafe { (session.api.stats)(session.handle, &mut stats) } == 0 {
                                buffer.dropped =
                                    stats.dropped as u64 + stats.interface_dropped as u64;
                            }
                            stats_at = std::time::Instant::now();
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
            Ok(Err(message)) => {
                let _ = worker.join();
                Err(anyhow!(message))
            }
            Err(error) => {
                stop.store(true, Ordering::Relaxed);
                let _ = worker.join();
                Err(anyhow!("starting packet capture: {error}"))
            }
        }
    }

    pub(super) fn drain(&self) -> Batch {
        let Ok(mut buffer) = self.buffer.lock() else {
            return Batch {
                error: Some("capture worker lock failed".to_string()),
                ..Batch::default()
            };
        };
        Batch {
            flows: std::mem::take(&mut buffer.flows),
            untracked: std::mem::take(&mut buffer.untracked),
            dropped: buffer.dropped,
            overflow: buffer.overflow,
            unsupported: buffer.unsupported,
            truncated: buffer.truncated,
            error: buffer.error.clone(),
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
    use super::super::packet::Protocol;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn flow_storage_is_bounded_and_excess_bytes_remain_visible() {
        let mut batch = Batch::default();
        for port in 0..MAX_FLOWS + 1 {
            batch.push(Packet {
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
            });
        }
        assert_eq!(batch.flows.len(), MAX_FLOWS);
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
}
