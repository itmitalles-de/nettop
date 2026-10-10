//! Optional metadata-only socket events from an embedded CO-RE BPF object.
//!
//! One worker owns every link, map and ring buffer. No object paths, pins or
//! payload bytes cross this boundary; dropping it detaches all its programs.

use super::capture::Wake;
use anyhow::Result;
#[cfg(not(feature = "ebpf"))]
use std::sync::Arc;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Event {
    pub timestamp_ns: u64,
    pub started_ns: u64,
    pub process_start_ns: u64,
    pub socket_id: u64,
    pub inode: u64,
    pub tgid: u32,
    pub uid: u32,
    pub netns: u32,
    pub family: u16,
    pub protocol: u16,
    pub local_port: u16,
    pub remote_port: u16,
    pub kind: u8,
    pub flags: u8,
    pub reserved: u16,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub comm: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<Event>() == 112);

/// One header-only IP skb observed at an actual socket endpoint. Addresses
/// are the packet's wire tuple, which may differ from the socket after NAT.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PacketEvent {
    pub timestamp_ns: u64,
    pub socket_id: u64,
    pub inode: u64,
    pub netns: u32,
    pub ifindex: u32,
    pub ip_bytes: u32,
    pub family: u16,
    pub protocol: u16,
    pub local_port: u16,
    pub remote_port: u16,
    pub receive: u8,
    pub flags: u8,
    pub reserved: u16,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
}
const _: () = assert!(std::mem::size_of::<PacketEvent>() == 80);

#[derive(Default)]
pub(super) struct Batch {
    pub events: Vec<Event>,
    pub packets: Vec<PacketEvent>,
    pub lost: u64,
    pub losses: Losses,
    pub error: Option<String>,
}

/// Fixed-size counters; no event data or growing diagnostic history is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
// First ten fields are counters; the last three describe nested calls:
// maximum observed age, maximum observed depth and the union of kind bits.
pub(super) struct Losses(pub [u64; 13]);

impl Losses {
    #[cfg(feature = "ebpf")]
    fn total(self) -> u64 {
        self.0[..10].iter().copied().fold(0, u64::saturating_add)
    }

    #[cfg(feature = "ebpf")]
    fn add(&mut self, other: Self) {
        for (count, extra) in self.0[..10].iter_mut().zip(other.0) {
            *count = count.saturating_add(extra);
        }
        self.0[10] = self.0[10].max(other.0[10]);
        self.0[11] = self.0[11].max(other.0[11]);
        self.0[12] |= other.0[12];
    }

    pub fn describe(self) -> String {
        const LABELS: [&str; 10] = [
            "kernel ring",
            "pending map",
            "socket map",
            "kernel read",
            "staging queue",
            "shared queue",
            "invalid record",
            "worker failure",
            "nested call",
            "pending delete",
        ];
        let mut description = LABELS
            .into_iter()
            .zip(self.0)
            .filter(|(_, count)| *count > 0)
            .map(|(label, count)| format!("{label}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        if self.0[8] > 0 {
            description.push_str(&format!(
                " (observed age={}ns, depth={}, kinds=0x{:x})",
                self.0[10], self.0[11], self.0[12]
            ));
        }
        description
    }
}

#[cfg(not(feature = "ebpf"))]
pub(super) struct Events;

#[cfg(not(feature = "ebpf"))]
impl Events {
    pub(super) fn start(_wake: Arc<Wake>) -> Result<Self> {
        anyhow::bail!("extended attribution is not included; install with --extended-attribution")
    }

    pub(super) fn drain(&self) -> Batch {
        Batch::default()
    }
}

#[cfg(feature = "ebpf")]
pub(super) use enabled::Events;

#[cfg(feature = "ebpf")]
mod enabled {
    use super::{Batch, Event, Losses, PacketEvent, Result, Wake};
    use anyhow::{Context, anyhow, bail};
    use libloading::Library;
    use std::ffi::{CStr, c_char, c_int, c_long, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lifecycle.bpf.o"));
    const MAX_EVENTS: usize = 32_768;
    const MAX_POLL_EVENTS: usize = 2048;
    const POLL_YIELD: c_int = -libc::ECANCELED;
    type Handle = *mut c_void;
    type Callback = unsafe extern "C" fn(Handle, Handle, usize) -> c_int;

    struct Api {
        open: unsafe extern "C" fn(*const c_void, usize, *const c_void) -> Handle,
        load: unsafe extern "C" fn(Handle) -> c_int,
        close: unsafe extern "C" fn(Handle),
        next_program: unsafe extern "C" fn(Handle, Handle) -> Handle,
        section_name: unsafe extern "C" fn(Handle) -> *const c_char,
        attach: unsafe extern "C" fn(Handle) -> Handle,
        destroy_link: unsafe extern "C" fn(Handle) -> c_int,
        find_map_fd: unsafe extern "C" fn(Handle, *const c_char) -> c_int,
        map_lookup: unsafe extern "C" fn(c_int, *const c_void, *mut c_void) -> c_int,
        map_update: unsafe extern "C" fn(c_int, *const c_void, *const c_void, u64) -> c_int,
        ring_new: unsafe extern "C" fn(c_int, Callback, Handle, *const c_void) -> Handle,
        ring_poll: unsafe extern "C" fn(Handle, c_int) -> c_int,
        ring_free: unsafe extern "C" fn(Handle),
        get_error: unsafe extern "C" fn(*const c_void) -> c_long,
        _library: Library,
    }

    impl Api {
        fn load() -> Result<Self> {
            // The privileged helper clears its environment before any library
            // load. Require the supported libbpf ABI, never a user object path.
            let library = unsafe { Library::new("libbpf.so.1") }
                .context("extended attribution needs libbpf.so.1")?;
            // Every symbol is tied to the Library stored in this value.
            unsafe {
                Ok(Self {
                    open: *library.get(b"bpf_object__open_mem\0")?,
                    load: *library.get(b"bpf_object__load\0")?,
                    close: *library.get(b"bpf_object__close\0")?,
                    next_program: *library.get(b"bpf_object__next_program\0")?,
                    section_name: *library.get(b"bpf_program__section_name\0")?,
                    attach: *library.get(b"bpf_program__attach\0")?,
                    destroy_link: *library.get(b"bpf_link__destroy\0")?,
                    find_map_fd: *library.get(b"bpf_object__find_map_fd_by_name\0")?,
                    map_lookup: *library.get(b"bpf_map_lookup_elem\0")?,
                    map_update: *library.get(b"bpf_map_update_elem\0")?,
                    ring_new: *library.get(b"ring_buffer__new\0")?,
                    ring_poll: *library.get(b"ring_buffer__poll\0")?,
                    ring_free: *library.get(b"ring_buffer__free\0")?,
                    get_error: *library.get(b"libbpf_get_error\0")?,
                    _library: library,
                })
            }
        }

        fn pointer(&self, pointer: Handle, operation: &str) -> Result<Handle> {
            let error = unsafe { (self.get_error)(pointer) };
            if pointer.is_null() || error != 0 {
                let detail = if error != 0 {
                    std::io::Error::from_raw_os_error((-error) as i32)
                } else {
                    std::io::Error::last_os_error()
                };
                bail!("{operation}: {detail}");
            }
            Ok(pointer)
        }
    }

    struct CallbackState {
        batch: Batch,
        polled: usize,
    }

    fn attachment_order(sections: &[&CStr]) -> Result<Vec<usize>> {
        let mut exits = Vec::new();
        let mut entries = Vec::new();
        for (index, section) in sections.iter().enumerate() {
            if section.to_bytes().starts_with(b"fexit/") {
                exits.push(index);
            } else if section.to_bytes().starts_with(b"fentry/") {
                entries.push(index);
            } else {
                bail!(
                    "unsupported socket-event section: {}",
                    section.to_string_lossy()
                );
            }
        }
        exits.extend(entries);
        Ok(exits)
    }

    unsafe extern "C" fn receive(context: Handle, data: Handle, size: usize) -> c_int {
        // libbpf invokes this synchronously while polling; context is a stable
        // Box that outlives the ring and data is valid for this callback only.
        let state = unsafe { &mut *context.cast::<CallbackState>() };
        let buffer = &mut state.batch;
        if data.is_null()
            || (size != std::mem::size_of::<Event>() && size != std::mem::size_of::<PacketEvent>())
        {
            buffer.lost = buffer.lost.saturating_add(1);
            buffer.losses.0[6] = buffer.losses.0[6].saturating_add(1);
            buffer.error = Some("invalid socket-event record".to_string());
        } else if buffer.events.len() + buffer.packets.len() >= MAX_POLL_EVENTS {
            buffer.lost = buffer.lost.saturating_add(1);
            buffer.losses.0[4] = buffer.losses.0[4].saturating_add(1);
        } else if size == std::mem::size_of::<PacketEvent>() {
            buffer
                .packets
                .push(unsafe { ptr::read_unaligned(data.cast::<PacketEvent>()) });
        } else {
            // Ring records need not satisfy Rust's alignment requirement.
            let event = unsafe { ptr::read_unaligned(data.cast::<Event>()) };
            buffer.events.push(event);
        }
        state.polled += 1;
        // libbpf stops only on a negative callback result and advances the
        // consumer position past this record before returning that result.
        // Yield without consuming the rest of the ring, so a producer flood
        // cannot prevent shutdown or statistics updates. Positive results are
        // ignored by libbpf and would silently overflow our staging batch.
        if state.polled >= MAX_POLL_EVENTS {
            POLL_YIELD
        } else {
            0
        }
    }

    fn poll_failed(result: c_int, polled: usize) -> bool {
        result < 0 && result != -libc::EINTR && !(result == POLL_YIELD && polled == MAX_POLL_EVENTS)
    }

    /// Publish one consumed poll only after reading its kernel loss counters.
    /// The callback's private staging batch is never visible to the collector,
    /// so a CLOSE cannot prove sole ownership before an earlier lost actor is
    /// reported. Events and their uncertainty become visible under one lock.
    fn publish(
        staged: &mut Batch,
        shared: &Mutex<Batch>,
        losses: Losses,
        error: Option<String>,
        wake: Option<&Wake>,
    ) -> bool {
        let Ok(mut shared) = shared.lock() else {
            return false;
        };
        let previous_size = shared.events.len() + shared.packets.len();
        shared.lost = shared
            .lost
            .saturating_add(losses.total())
            .saturating_add(staged.lost);
        shared.losses.add(losses);
        shared.losses.add(std::mem::take(&mut staged.losses));
        staged.lost = 0;
        if let Some(error) = error.or_else(|| staged.error.take()) {
            staged.events.clear();
            staged.packets.clear();
            shared.lost = shared.lost.saturating_add(1);
            shared.losses.0[7] = shared.losses.0[7].saturating_add(1);
            shared.error = Some(error);
            if let Some(wake) = wake {
                wake.notify();
            }
            return false;
        }
        let available = MAX_EVENTS.saturating_sub(shared.events.len() + shared.packets.len());
        let accepted = staged.events.len().min(available);
        shared.lost = shared
            .lost
            .saturating_add((staged.events.len() - accepted) as u64);
        shared.losses.0[5] =
            shared.losses.0[5].saturating_add((staged.events.len() - accepted) as u64);
        shared.events.extend(staged.events.drain(..accepted));
        staged.events.clear();
        let available = MAX_EVENTS.saturating_sub(shared.events.len() + shared.packets.len());
        let accepted = staged.packets.len().min(available);
        let dropped = (staged.packets.len() - accepted) as u64;
        shared.lost = shared.lost.saturating_add(dropped);
        shared.losses.0[5] = shared.losses.0[5].saturating_add(dropped);
        shared.packets.extend(staged.packets.drain(..accepted));
        staged.packets.clear();
        if previous_size < MAX_EVENTS / 4
            && shared.events.len() + shared.packets.len() >= MAX_EVENTS / 4
            && let Some(wake) = wake
        {
            wake.notify();
        }
        true
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Statistics {
        lost_events: u64,
        pending_failures: u64,
        socket_failures: u64,
        read_failures: u64,
        nested_calls: u64,
        nested_last_age_ns: u64,
        nested_last_depth: u64,
        nested_kind_mask: u64,
        pending_delete_failures: u64,
        fatal_socket_reuse: u64,
    }

    const _: () = assert!(std::mem::size_of::<Statistics>() == 80);

    impl Statistics {
        fn check(self) -> Result<()> {
            if self.fatal_socket_reuse > 0 {
                bail!("socket identity cleanup failed; packet attribution stopped until restart");
            }
            Ok(())
        }

        fn delta(self, previous: Self) -> Losses {
            let nested = self.nested_calls.saturating_sub(previous.nested_calls);
            Losses([
                self.lost_events.saturating_sub(previous.lost_events),
                self.pending_failures
                    .saturating_sub(previous.pending_failures),
                self.socket_failures
                    .saturating_sub(previous.socket_failures),
                self.read_failures.saturating_sub(previous.read_failures),
                0,
                0,
                0,
                0,
                nested,
                self.pending_delete_failures
                    .saturating_sub(previous.pending_delete_failures),
                if nested > 0 {
                    self.nested_last_age_ns
                } else {
                    0
                },
                if nested > 0 {
                    self.nested_last_depth
                } else {
                    0
                },
                if nested > 0 { self.nested_kind_mask } else { 0 },
            ])
        }
    }

    struct Session {
        api: Api,
        object: Handle,
        links: Vec<Handle>,
        ring: Handle,
        stats_fd: c_int,
        context: Box<CallbackState>,
    }

    impl Session {
        fn open() -> Result<Self> {
            let api = Api::load()?;
            let object = api.pointer(
                unsafe { (api.open)(OBJECT.as_ptr().cast(), OBJECT.len(), ptr::null()) },
                "opening embedded socket-event object",
            )?;
            let mut session = Self {
                api,
                object,
                links: Vec::new(),
                ring: ptr::null_mut(),
                stats_fd: -1,
                context: Box::new(CallbackState {
                    batch: Batch::default(),
                    polled: 0,
                }),
            };
            let loaded = unsafe { (session.api.load)(session.object) };
            if loaded != 0 {
                bail!(
                    "loading socket events (kernel BTF, BPF and PERFMON permissions required): {}",
                    std::io::Error::from_raw_os_error(-loaded)
                );
            }
            session.stats_fd = unsafe { (session.api.find_map_fd)(object, c"stats".as_ptr()) };
            let events_fd = unsafe { (session.api.find_map_fd)(object, c"events".as_ptr()) };
            if session.stats_fd < 0 || events_fd < 0 {
                bail!("embedded socket-event maps are unavailable");
            }
            session.ring = session.api.pointer(
                unsafe {
                    (session.api.ring_new)(
                        events_fd,
                        receive,
                        (&mut *session.context as *mut CallbackState).cast(),
                        ptr::null(),
                    )
                },
                "opening socket-event ring buffer",
            )?;
            let mut program = ptr::null_mut();
            let mut programs = Vec::new();
            let mut sections = Vec::new();
            loop {
                program = unsafe { (session.api.next_program)(object, program) };
                if program.is_null() {
                    break;
                }
                let section = unsafe { (session.api.section_name)(program) };
                if section.is_null() {
                    bail!("socket-event program has no section name");
                }
                programs.push(program);
                // Program section strings live until the object is closed.
                sections.push(unsafe { CStr::from_ptr(section) });
            }
            // An entry observed before its exit probe is attached leaves a
            // permanent pending call. Subsequent calls then appear nested and
            // repeatedly invalidate ownership. Attach every exit first; reverse
            // link destruction likewise removes all entries before their exits.
            for index in attachment_order(&sections)? {
                let link = session.api.pointer(
                    unsafe { (session.api.attach)(programs[index]) },
                    "attaching socket-event program",
                )?;
                session.links.push(link);
            }
            if session.links.is_empty() {
                bail!("embedded socket-event object has no programs");
            }
            // Attaching another probe can replace a function's trampoline.
            // Keep paired observations disabled throughout every attachment,
            // even though exit-first ordering also minimizes the attach gap.
            let armed_fd = unsafe { (session.api.find_map_fd)(object, c"armed".as_ptr()) };
            if armed_fd < 0 {
                bail!("embedded socket-event activation map is unavailable");
            }
            let key = 0_u32;
            let armed = 1_u32;
            let result = unsafe {
                (session.api.map_update)(
                    armed_fd,
                    (&key as *const u32).cast(),
                    (&armed as *const u32).cast(),
                    0, // BPF_ANY; the single array element already exists.
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("activating socket-event observations");
            }
            Ok(session)
        }

        fn stats(&self) -> Result<Statistics> {
            let key = 0_u32;
            let mut stats = Statistics::default();
            let result = unsafe {
                (self.api.map_lookup)(
                    self.stats_fd,
                    (&key as *const u32).cast(),
                    (&mut stats as *mut Statistics).cast(),
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("reading socket-event loss counters");
            }
            Ok(stats)
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // Detach producers before freeing their consumer and object maps.
            for link in self.links.drain(..).rev() {
                unsafe { (self.api.destroy_link)(link) };
            }
            if !self.ring.is_null() {
                unsafe { (self.api.ring_free)(self.ring) };
            }
            unsafe { (self.api.close)(self.object) };
        }
    }

    pub(in super::super) struct Events {
        buffer: Arc<Mutex<Batch>>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Events {
        pub(in super::super) fn start(wake: Arc<Wake>) -> Result<Self> {
            let buffer = Arc::new(Mutex::new(Batch::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_buffer = Arc::clone(&buffer);
            let thread_stop = Arc::clone(&stop);
            let (ready, receiver) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("nwtop-events".to_string())
                .spawn(move || {
                    let mut session = match Session::open() {
                        Ok(session) => session,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    if let Err(error) = crate::privilege::drop_capture_privileges() {
                        let _ = ready
                            .send(Err(error.context("dropping socket-event worker privileges")));
                        return;
                    }
                    if ready.send(Ok(())).is_err() {
                        return;
                    }
                    let mut previous = Statistics::default();
                    while !thread_stop.load(Ordering::Relaxed) {
                        session.context.polled = 0;
                        let result = unsafe { (session.api.ring_poll)(session.ring, 50) };
                        let mut error = None;
                        if poll_failed(result, session.context.polled) {
                            error = Some(format!(
                                "reading socket events: {}",
                                std::io::Error::from_raw_os_error(-result)
                            ));
                        }
                        // Sample on every completed poll, not on a timer:
                        // even a short burst may contain a lost conflicting
                        // actor followed by CLOSE and must be withheld now.
                        let lost = match session.stats() {
                            Ok(stats) => {
                                if let Err(problem) = stats.check() {
                                    error = Some(problem.to_string());
                                }
                                let lost = stats.delta(previous);
                                previous = stats;
                                lost
                            }
                            Err(problem) => {
                                error = Some(problem.to_string());
                                Losses::default()
                            }
                        };
                        if !publish(
                            &mut session.context.batch,
                            &thread_buffer,
                            lost,
                            error,
                            Some(&wake),
                        ) {
                            return;
                        }
                    }
                })
                .context("starting socket-event worker")?;
            match receiver.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(())) => Ok(Self {
                    buffer,
                    stop,
                    worker: Some(worker),
                }),
                Ok(Err(error)) => {
                    let _ = worker.join();
                    Err(error)
                }
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = worker.join();
                    Err(anyhow!("starting socket-event worker: {error}"))
                }
            }
        }

        pub(in super::super) fn drain(&self) -> Batch {
            let Ok(mut buffer) = self.buffer.lock() else {
                return Batch {
                    error: Some("socket-event worker lock failed".to_string()),
                    ..Batch::default()
                };
            };
            Batch {
                events: std::mem::take(&mut buffer.events),
                packets: std::mem::take(&mut buffer.packets),
                lost: std::mem::take(&mut buffer.lost),
                losses: std::mem::take(&mut buffer.losses),
                error: buffer.error.clone(),
            }
        }
    }

    impl Drop for Events {
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

        #[test]
        fn endpoint_packet_pressure_wakes_the_shared_attribution_worker() {
            let wake = Arc::new(Wake::default());
            let waiting = Arc::clone(&wake);
            let (done, result) = mpsc::channel();
            let worker = thread::spawn(move || {
                waiting.wait(Duration::from_secs(5));
                done.send(()).unwrap();
            });
            let shared = Mutex::new(Batch {
                events: vec![Event::default(); MAX_EVENTS / 4 - 1],
                ..Batch::default()
            });
            let mut staged = Batch {
                packets: vec![PacketEvent::default()],
                ..Batch::default()
            };
            assert!(publish(
                &mut staged,
                &shared,
                Losses::default(),
                None,
                Some(&wake)
            ));
            result.recv_timeout(Duration::from_secs(2)).unwrap();
            worker.join().unwrap();
            assert_eq!(shared.lock().unwrap().lost, 0);
        }

        #[test]
        fn packet_records_share_loss_publication_and_queue_bounds_with_lifecycle() {
            let shared = Mutex::new(Batch::default());
            let mut context = CallbackState {
                batch: Batch::default(),
                polled: 0,
            };
            let mut packet = PacketEvent {
                ip_bytes: 1052,
                socket_id: 4,
                ..PacketEvent::default()
            };
            let mut lifecycle = Event {
                socket_id: 4,
                ..Event::default()
            };
            unsafe {
                receive(
                    (&mut context as *mut CallbackState).cast(),
                    (&mut packet as *mut PacketEvent).cast(),
                    80,
                );
                receive(
                    (&mut context as *mut CallbackState).cast(),
                    (&mut lifecycle as *mut Event).cast(),
                    112,
                );
            }
            assert!(shared.lock().unwrap().packets.is_empty());
            assert!(publish(
                &mut context.batch,
                &shared,
                Losses([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                None,
                None
            ));
            let mut published = shared.lock().unwrap();
            assert_eq!(published.packets[0].ip_bytes, 1052);
            assert_eq!(published.events[0].socket_id, 4);
            assert_eq!(published.lost, 1);
            published.events.resize(MAX_EVENTS - 1, Event::default());
            drop(published);
            context.batch.packets.push(packet);
            assert!(publish(
                &mut context.batch,
                &shared,
                Losses::default(),
                None,
                None
            ));
            let published = shared.lock().unwrap();
            assert_eq!(published.packets.len(), 1);
            assert_eq!(published.lost, 2);
            assert_eq!(published.losses.0[5], 1);
        }

        #[test]
        fn every_exit_is_attached_before_any_entry_and_removed_after_it() {
            let sections = [
                c"fentry/inet_sendmsg",
                c"fexit/inet_sendmsg",
                c"fentry/inet_recvmsg",
                c"fexit/inet_recvmsg",
                c"fexit/inet_accept",
                c"fentry/inet_release",
            ];
            let order = attachment_order(&sections).unwrap();
            assert_eq!(order, [1, 3, 4, 0, 2, 5]);
            let removal: Vec<_> = order.into_iter().rev().collect();
            assert_eq!(removal, [5, 2, 0, 4, 3, 1]);
            assert!(attachment_order(&[c"tracepoint/unknown"]).is_err());
        }

        #[test]
        fn large_ring_burst_yields_without_losing_consumed_records() {
            let shared = Mutex::new(Batch::default());
            let mut context = CallbackState {
                batch: Batch::default(),
                polled: 0,
            };
            let total = MAX_POLL_EVENTS * 3 + 17;
            let mut consumed = 0;
            let mut polls = 0;
            while consumed < total {
                context.polled = 0;
                let mut result = 0;
                // Model libbpf's contract: consume the current record, then
                // stop only for a negative callback result. In particular,
                // returning +1 must not accidentally pass this regression.
                while consumed < total {
                    let mut event = Event {
                        socket_id: consumed as u64,
                        ..Event::default()
                    };
                    result = unsafe {
                        receive(
                            (&mut context as *mut CallbackState).cast(),
                            (&mut event as *mut Event).cast(),
                            std::mem::size_of::<Event>(),
                        )
                    };
                    consumed += 1;
                    if result < 0 {
                        break;
                    }
                }
                assert!(context.polled <= MAX_POLL_EVENTS);
                assert!(!poll_failed(result, context.polled));
                assert!(publish(
                    &mut context.batch,
                    &shared,
                    Losses::default(),
                    None,
                    None
                ));
                polls += 1;
            }
            let published = shared.lock().unwrap();
            assert_eq!(polls, 4);
            assert_eq!(published.lost, 0);
            assert!(published.error.is_none());
            assert_eq!(published.events.len(), total);
            for (index, event) in published.events.iter().enumerate() {
                assert_eq!(event.socket_id, index as u64);
            }
            assert!(poll_failed(POLL_YIELD, 0));
            assert!(poll_failed(-libc::EIO, MAX_POLL_EVENTS));
        }

        #[test]
        fn callback_bounds_queue_and_rejects_bad_lengths() {
            let mut context = CallbackState {
                batch: Batch::default(),
                polled: 0,
            };
            let pointer = (&mut context as *mut CallbackState).cast();
            let mut event = Event {
                tgid: 42,
                ..Event::default()
            };
            let data = (&mut event as *mut Event).cast();
            unsafe { receive(pointer, data, 1) };
            assert_eq!(context.batch.lost, 1);
            for _ in 0..=MAX_POLL_EVENTS {
                unsafe { receive(pointer, data, std::mem::size_of::<Event>()) };
            }
            let batch = &context.batch;
            assert_eq!(batch.events.len(), MAX_POLL_EVENTS);
            assert_eq!(batch.events[0].tgid, 42);
            assert_eq!(batch.lost, 2);
            assert_eq!(
                batch.losses,
                Losses([0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0])
            );
        }

        #[test]
        fn close_stays_private_until_its_loss_counters_are_published() {
            let shared = Mutex::new(Batch::default());
            let mut context = CallbackState {
                batch: Batch::default(),
                polled: 0,
            };
            let pointer = (&mut context as *mut CallbackState).cast();
            let mut event = Event {
                kind: 4,
                tgid: 42,
                ..Event::default()
            };
            unsafe {
                receive(
                    pointer,
                    (&mut event as *mut Event).cast(),
                    std::mem::size_of::<Event>(),
                )
            };
            assert!(shared.lock().unwrap().events.is_empty());
            assert_eq!(shared.lock().unwrap().lost, 0);
            assert!(publish(
                &mut context.batch,
                &shared,
                Losses([7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                None,
                None
            ));
            let published = shared.lock().unwrap();
            assert_eq!(published.events.len(), 1);
            assert_eq!(published.events[0].kind, 4);
            assert_eq!(published.lost, 7);
            assert_eq!(published.losses.describe(), "kernel ring=7");
        }

        #[test]
        fn failed_loss_read_and_publication_overflow_are_uncertain() {
            let shared = Mutex::new(Batch {
                events: vec![Event::default(); MAX_EVENTS],
                ..Batch::default()
            });
            let mut staged = Batch {
                events: vec![Event::default(); 2],
                ..Batch::default()
            };
            assert!(publish(
                &mut staged,
                &shared,
                Losses([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                None,
                None
            ));
            assert_eq!(shared.lock().unwrap().events.len(), MAX_EVENTS);
            assert_eq!(shared.lock().unwrap().lost, 5);
            staged.events.push(Event {
                kind: 4,
                ..Event::default()
            });
            assert!(!publish(
                &mut staged,
                &shared,
                Losses::default(),
                Some("stats failed".into()),
                None
            ));
            let published = shared.lock().unwrap();
            assert_eq!(published.lost, 6);
            assert_eq!(
                published.losses,
                Losses([3, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0])
            );
            assert_eq!(published.losses.total(), published.lost);
            assert_eq!(published.error.as_deref(), Some("stats failed"));
            assert!(staged.events.is_empty());
        }

        #[test]
        fn final_socket_identity_cleanup_failure_remains_fatal_across_drains() {
            let stats = Statistics {
                fatal_socket_reuse: 1,
                ..Statistics::default()
            };
            assert!(stats.check().is_err());
            assert_eq!(stats.delta(stats).total(), 0);
            assert!(stats.check().is_err()); // No new counter delta does not recover it.
            let shared = Mutex::new(Batch::default());
            let mut staged = Batch {
                packets: vec![PacketEvent::default()],
                ..Batch::default()
            };
            assert!(!publish(
                &mut staged,
                &shared,
                Losses::default(),
                stats.check().err().map(|e| e.to_string()),
                None
            ));
            let published = shared.lock().unwrap();
            assert!(published.packets.is_empty());
            assert!(
                published
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("until restart")
            );
        }

        #[test]
        fn statistics_count_every_failure_without_overflow() {
            let stats = Statistics {
                lost_events: 1,
                pending_failures: 2,
                socket_failures: 3,
                read_failures: 4,
                nested_calls: 5,
                nested_last_age_ns: 1000,
                nested_last_depth: 2,
                nested_kind_mask: 6,
                pending_delete_failures: 6,
                fatal_socket_reuse: 0,
            };
            assert_eq!(stats.delta(Statistics::default()).total(), 21);
            assert_eq!(
                stats.delta(Statistics::default()).describe(),
                "kernel ring=1, pending map=2, socket map=3, kernel read=4, nested call=5, pending delete=6 (observed age=1000ns, depth=2, kinds=0x6)"
            );
            assert_eq!(stats.delta(stats).total(), 0);
            let mut combined = stats.delta(Statistics::default());
            combined.add(Losses([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2000, 3, 8]));
            assert_eq!(combined.total(), 22);
            assert_eq!(&combined.0[10..], &[2000, 3, 14]);
            assert_eq!(
                Statistics {
                    lost_events: u64::MAX,
                    pending_failures: 1,
                    ..Statistics::default()
                }
                .delta(Statistics::default())
                .total(),
                u64::MAX
            );
        }
    }
}
