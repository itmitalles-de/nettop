//! Optional metadata-only socket events from an embedded CO-RE BPF object.
//!
//! One worker owns every link, map and ring buffer. No object paths, pins or
//! payload bytes cross this boundary; dropping it detaches all its programs.

use anyhow::Result;

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

#[derive(Default)]
pub(super) struct Batch {
    pub events: Vec<Event>,
    pub lost: u64,
    pub error: Option<String>,
}

#[cfg(not(feature = "ebpf"))]
pub(super) struct Events;

#[cfg(not(feature = "ebpf"))]
impl Events {
    pub(super) fn start() -> Result<Self> {
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
    use super::{Batch, Event, Result};
    use anyhow::{Context, anyhow, bail};
    use libloading::Library;
    use std::ffi::{c_char, c_int, c_long, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lifecycle.bpf.o"));
    const MAX_EVENTS: usize = 32_768;
    const MAX_POLL_EVENTS: usize = 2048;
    type Handle = *mut c_void;
    type Callback = unsafe extern "C" fn(Handle, Handle, usize) -> c_int;

    struct Api {
        open: unsafe extern "C" fn(*const c_void, usize, *const c_void) -> Handle,
        load: unsafe extern "C" fn(Handle) -> c_int,
        close: unsafe extern "C" fn(Handle),
        next_program: unsafe extern "C" fn(Handle, Handle) -> Handle,
        attach: unsafe extern "C" fn(Handle) -> Handle,
        destroy_link: unsafe extern "C" fn(Handle) -> c_int,
        find_map_fd: unsafe extern "C" fn(Handle, *const c_char) -> c_int,
        map_lookup: unsafe extern "C" fn(c_int, *const c_void, *mut c_void) -> c_int,
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
                    attach: *library.get(b"bpf_program__attach\0")?,
                    destroy_link: *library.get(b"bpf_link__destroy\0")?,
                    find_map_fd: *library.get(b"bpf_object__find_map_fd_by_name\0")?,
                    map_lookup: *library.get(b"bpf_map_lookup_elem\0")?,
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

    unsafe extern "C" fn receive(context: Handle, data: Handle, size: usize) -> c_int {
        // libbpf invokes this synchronously while polling; context is a stable
        // Box that outlives the ring and data is valid for this callback only.
        let state = unsafe { &mut *context.cast::<CallbackState>() };
        let buffer = &mut state.batch;
        if data.is_null() || size != std::mem::size_of::<Event>() {
            buffer.lost = buffer.lost.saturating_add(1);
            buffer.error = Some("invalid socket-event record".to_string());
        } else if buffer.events.len() >= MAX_POLL_EVENTS {
            buffer.lost = buffer.lost.saturating_add(1);
        } else {
            // Ring records need not satisfy Rust's alignment requirement.
            let event = unsafe { ptr::read_unaligned(data.cast::<Event>()) };
            buffer.events.push(event);
        }
        state.polled += 1;
        // A positive result stops this poll after consuming the current record,
        // so a producer flood cannot prevent shutdown or statistics updates.
        i32::from(state.polled >= MAX_POLL_EVENTS)
    }

    /// Publish one consumed poll only after reading its kernel loss counters.
    /// The callback's private staging batch is never visible to the collector,
    /// so a CLOSE cannot prove sole ownership before an earlier lost actor is
    /// reported. Events and their uncertainty become visible under one lock.
    fn publish(
        staged: &mut Batch,
        shared: &Mutex<Batch>,
        lost: u64,
        error: Option<String>,
    ) -> bool {
        let Ok(mut shared) = shared.lock() else {
            return false;
        };
        shared.lost = shared.lost.saturating_add(lost).saturating_add(staged.lost);
        staged.lost = 0;
        if let Some(error) = error.or_else(|| staged.error.take()) {
            staged.events.clear();
            shared.lost = shared.lost.saturating_add(1);
            shared.error = Some(error);
            return false;
        }
        let available = MAX_EVENTS.saturating_sub(shared.events.len());
        let accepted = staged.events.len().min(available);
        shared.lost = shared
            .lost
            .saturating_add((staged.events.len() - accepted) as u64);
        shared.events.extend(staged.events.drain(..accepted));
        staged.events.clear();
        true
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Statistics {
        lost_events: u64,
        pending_failures: u64,
        socket_failures: u64,
        read_failures: u64,
    }

    impl Statistics {
        fn delta(self, previous: Self) -> u64 {
            self.lost_events
                .saturating_sub(previous.lost_events)
                .saturating_add(
                    self.pending_failures
                        .saturating_sub(previous.pending_failures),
                )
                .saturating_add(
                    self.socket_failures
                        .saturating_sub(previous.socket_failures),
                )
                .saturating_add(self.read_failures.saturating_sub(previous.read_failures))
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
            loop {
                program = unsafe { (session.api.next_program)(object, program) };
                if program.is_null() {
                    break;
                }
                let link = session.api.pointer(
                    unsafe { (session.api.attach)(program) },
                    "attaching socket-event program",
                )?;
                session.links.push(link);
            }
            if session.links.is_empty() {
                bail!("embedded socket-event object has no programs");
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
            for link in self.links.drain(..) {
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
        pub(in super::super) fn start() -> Result<Self> {
            let buffer = Arc::new(Mutex::new(Batch::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_buffer = Arc::clone(&buffer);
            let thread_stop = Arc::clone(&stop);
            let (ready, receiver) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("nettop-events".to_string())
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
                        if result < 0 && result != -libc::EINTR {
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
                                let lost = stats.delta(previous);
                                previous = stats;
                                lost
                            }
                            Err(problem) => {
                                error = Some(problem.to_string());
                                0
                            }
                        };
                        if !publish(&mut session.context.batch, &thread_buffer, lost, error) {
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
                lost: std::mem::take(&mut buffer.lost),
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
            assert!(publish(&mut context.batch, &shared, 7, None));
            let published = shared.lock().unwrap();
            assert_eq!(published.events.len(), 1);
            assert_eq!(published.events[0].kind, 4);
            assert_eq!(published.lost, 7);
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
            assert!(publish(&mut staged, &shared, 3, None));
            assert_eq!(shared.lock().unwrap().events.len(), MAX_EVENTS);
            assert_eq!(shared.lock().unwrap().lost, 5);
            staged.events.push(Event {
                kind: 4,
                ..Event::default()
            });
            assert!(!publish(
                &mut staged,
                &shared,
                0,
                Some("stats failed".into())
            ));
            let published = shared.lock().unwrap();
            assert_eq!(published.lost, 6);
            assert_eq!(published.error.as_deref(), Some("stats failed"));
            assert!(staged.events.is_empty());
        }

        #[test]
        fn statistics_count_every_failure_without_overflow() {
            let stats = Statistics {
                lost_events: 1,
                pending_failures: 2,
                socket_failures: 3,
                read_failures: 4,
            };
            assert_eq!(stats.delta(Statistics::default()), 10);
            assert_eq!(stats.delta(stats), 0);
            assert_eq!(
                Statistics {
                    lost_events: u64::MAX,
                    pending_failures: 1,
                    ..Statistics::default()
                }
                .delta(Statistics::default()),
                u64::MAX
            );
        }
    }
}
