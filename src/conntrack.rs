//! Read-only, bounded conntrack metadata. Packet bytes still come from pcap.
//!
//! This worker alone retains NET_ADMIN. It subscribes before the initial dump,
//! queues concurrent events during dumps, and never publishes partial state.

use super::packet::Protocol;
use anyhow::{Context, Result, anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 32_768;
const MAX_TOMBSTONES: usize = MAX_ENTRIES * 6;
// Capture accepts packets up to three seconds old and attribution can defer
// them another two seconds. Never reinterpret those bytes as a new generation.
const REUSE_QUARANTINE: Duration = Duration::from_secs(6);
const MAX_QUEUED_EVENTS: usize = 65_536;
const MAX_DATAGRAM: usize = 256 * 1024;
const MAX_ATTRIBUTES: usize = 64;
const REFRESH: Duration = Duration::from_secs(30);
const MAX_CACHE_AGE: Duration = Duration::from_secs(45);
const DUMP_DEADLINE: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_secs(5);
const POLL_MS: i32 = 50;
const CT_NEW: u16 = 0x100;
const CT_GET: u16 = 0x101;
const CT_DELETE: u16 = 0x102;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Tuple {
    pub protocol: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl Tuple {
    fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            ..self
        }
    }
}

/// Both endpoint pairs in the observed packet's direction, including a
/// connection with simultaneous source and destination NAT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Translation {
    pub before: Tuple,
    pub after: Tuple,
    pub zones: (u16, u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// The complete view has no current matching entry. This is not proof
    /// that a just-created/unconfirmed connection does not use NAT.
    Missing,
    Unchanged,
    Translated(Translation),
    Ambiguous,
    Unavailable,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Identity {
    id: u32,
    original: Tuple,
    zones: (u16, u16),
}

#[derive(Clone, Debug)]
struct Entry {
    identity: Identity,
    reply: Tuple,
    expires: Instant,
}

impl Entry {
    fn translation(&self, reverse: bool) -> Translation {
        let after = self.reply.reversed();
        if reverse {
            Translation {
                before: self.reply,
                after: self.identity.original.reversed(),
                zones: (self.identity.zones.1, self.identity.zones.0),
            }
        } else {
            Translation {
                before: self.identity.original,
                after,
                zones: self.identity.zones,
            }
        }
    }

    fn observations(&self) -> Vec<(Tuple, bool)> {
        let before = self.identity.original;
        let after = self.reply.reversed();
        // In original direction DNAT happens before SNAT. The reverse packet
        // traverses the inverse stages. Do not invent the other Cartesian
        // combination (SNAT applied but DNAT not applied).
        let middle = Tuple {
            destination: after.destination,
            ..before
        };
        let mut seen = HashSet::new();
        let mut observations = Vec::with_capacity(6);
        for tuple in [before, middle, after] {
            for (tuple, reverse) in [(tuple, false), (tuple.reversed(), true)] {
                if seen.insert((tuple, reverse)) {
                    observations.push((tuple, reverse));
                }
            }
        }
        observations
    }
}

#[derive(Clone)]
struct Candidate {
    entry: Arc<Entry>,
    reverse: bool,
}

struct Cache {
    entries: HashMap<Identity, Arc<Entry>>,
    index: HashMap<Tuple, Vec<Candidate>>,
    tombstones: HashMap<Tuple, Instant>,
    quarantine_until: Instant,
    quarantine_after_resync: bool,
    ready: bool,
    error: Option<String>,
    lost: u64,
    valid_until: Instant,
}

impl Cache {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            index: HashMap::new(),
            tombstones: HashMap::new(),
            quarantine_until: now,
            quarantine_after_resync: false,
            ready: false,
            error: Some("initial conntrack synchronization pending".into()),
            lost: 0,
            valid_until: now,
        }
    }

    fn remove(&mut self, identity: &Identity) {
        if let Some(entry) = self.entries.remove(identity) {
            for (tuple, _) in entry.observations() {
                if let Some(candidates) = self.index.get_mut(&tuple) {
                    candidates.retain(|candidate| candidate.entry.identity != *identity);
                    if candidates.is_empty() {
                        self.index.remove(&tuple);
                    }
                }
            }
        }
    }

    fn apply(&mut self, event: Event) -> Result<()> {
        self.apply_at(event, Instant::now())
    }

    fn quarantine(&mut self, entry: &Entry, now: Instant) -> Result<()> {
        for (tuple, _) in entry.observations() {
            if self.tombstones.len() >= MAX_TOMBSTONES && !self.tombstones.contains_key(&tuple) {
                self.tombstones.retain(|_, until| *until > now);
                if self.tombstones.len() >= MAX_TOMBSTONES {
                    bail!("conntrack generation tombstone limit reached");
                }
            }
            let until = self.tombstones.entry(tuple).or_insert(now);
            *until = (*until).max(now + REUSE_QUARANTINE);
        }
        Ok(())
    }

    fn apply_at(&mut self, event: Event, now: Instant) -> Result<()> {
        match event {
            Event::Delete(entry) => {
                // DESTROY includes both tuples even if its NEW was not in our
                // previous dump, so quarantine all observed NAT stages.
                self.quarantine(&entry, now)?;
                if let Some(previous) = self.entries.get(&entry.identity).cloned() {
                    self.quarantine(&previous, now)?;
                }
                self.remove(&entry.identity);
            }
            Event::Upsert(entry) => {
                let mut conflicts = HashMap::new();
                for (tuple, _) in entry.observations() {
                    if let Some(candidates) = self.index.get(&tuple) {
                        for candidate in candidates {
                            let previous = &candidate.entry;
                            if previous.identity != entry.identity || previous.reply != entry.reply
                            {
                                conflicts.insert(previous.identity.clone(), previous.clone());
                            }
                        }
                    }
                }
                if !conflicts.is_empty() {
                    self.quarantine(&entry, now)?;
                    for previous in conflicts.values() {
                        self.quarantine(previous, now)?;
                    }
                }
                self.remove(&entry.identity);
                if self.entries.len() >= MAX_ENTRIES {
                    bail!("conntrack entry limit reached");
                }
                let entry = Arc::new(entry);
                for (tuple, reverse) in entry.observations() {
                    self.index.entry(tuple).or_default().push(Candidate {
                        entry: entry.clone(),
                        reverse,
                    });
                }
                self.entries.insert(entry.identity.clone(), entry);
            }
        }
        Ok(())
    }

    fn prune(&mut self, now: Instant) -> Result<()> {
        self.tombstones.retain(|_, until| *until > now);
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
            .map(|(identity, _)| identity.clone())
            .collect();
        for identity in expired {
            if let Some(entry) = self.entries.get(&identity).cloned() {
                self.quarantine(&entry, now)?;
            }
            self.remove(&identity);
        }
        Ok(())
    }

    fn invalidate(&mut self, error: impl Into<String>) {
        self.ready = false;
        self.error = Some(error.into());
        self.lost = self.lost.saturating_add(1);
        self.quarantine_after_resync = true;
        self.entries.clear();
        self.index.clear();
    }

    fn translate(&self, tuple: Tuple, now: Instant) -> Outcome {
        if !self.ready || now >= self.valid_until {
            return Outcome::Unavailable;
        }
        if now < self.quarantine_until
            || self
                .tombstones
                .get(&tuple)
                .is_some_and(|until| now < *until)
        {
            return Outcome::Ambiguous;
        }
        let Some(candidates) = self.index.get(&tuple) else {
            return Outcome::Missing;
        };
        let mut found: Option<(&Identity, Translation)> = None;
        for candidate in candidates {
            if candidate.entry.expires <= now {
                continue;
            }
            let translation = candidate.entry.translation(candidate.reverse);
            if let Some((identity, previous)) = found {
                // Even identical translations in separate zones/entries are
                // ambiguous: an AF_PACKET observation has no conntrack zone.
                if identity != &candidate.entry.identity || previous != translation {
                    return Outcome::Ambiguous;
                }
            } else {
                found = Some((&candidate.entry.identity, translation));
            }
        }
        match found {
            None => Outcome::Missing,
            Some((_, translation)) if translation.before == translation.after => Outcome::Unchanged,
            Some((_, translation)) => Outcome::Translated(translation),
        }
    }
}

/// A cheap live view. Each lookup rechecks readiness/expiry under the cache
/// lock, so an earlier snapshot cannot keep using state after packet loss.
pub(super) struct View {
    pub ready: bool,
    pub error: Option<String>,
    /// Cumulative synchronization failures/loss incidents, not packet counts.
    pub lost: u64,
    shared: Arc<Mutex<Cache>>,
}

impl View {
    pub(super) fn translate(
        &self,
        protocol: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Outcome {
        locked(&self.shared).translate(
            Tuple {
                protocol,
                source,
                destination,
            },
            Instant::now(),
        )
    }
}

pub(super) struct Conntrack {
    shared: Arc<Mutex<Cache>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Conntrack {
    pub(super) fn start() -> Result<Self> {
        let shared = Arc::new(Mutex::new(Cache::new(Instant::now())));
        let stop = Arc::new(AtomicBool::new(false));
        let (send, receive) = mpsc::sync_channel(1);
        let thread_shared = shared.clone();
        let thread_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("nettop-conntrack".into())
            .spawn(move || {
                let result = Socket::open().and_then(|socket| {
                    crate::privilege::retain_conntrack_privileges()?;
                    socket.request_dump(1)?;
                    Ok(socket)
                });
                match result {
                    Ok(socket) => {
                        if send.send(Ok(())).is_ok() {
                            run(socket, thread_shared, thread_stop);
                        }
                    }
                    Err(error) => {
                        let _ = send.send(Err(error));
                    }
                }
            })
            .context("starting conntrack worker")?;
        match receive.recv() {
            Ok(Ok(())) => Ok(Self {
                shared,
                stop,
                worker: Some(worker),
            }),
            result => {
                stop.store(true, Ordering::Relaxed);
                let _ = worker.join();
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(anyhow!("conntrack worker exited during startup")),
                }
            }
        }
    }

    pub(super) fn snapshot(&self) -> View {
        let cache = locked(&self.shared);
        let ready = cache.ready && Instant::now() < cache.valid_until;
        View {
            ready,
            error: if cache.ready && Instant::now() < cache.quarantine_until {
                Some("conntrack generation quarantine after synchronization loss".into())
            } else if cache.ready && !ready {
                Some("conntrack view expired".into())
            } else {
                cache.error.clone()
            },
            lost: cache.lost,
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Conntrack {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn locked(shared: &Mutex<Cache>) -> MutexGuard<'_, Cache> {
    match shared.lock() {
        Ok(cache) => cache,
        Err(poisoned) => {
            let mut cache = poisoned.into_inner();
            if cache.error.as_deref() != Some("conntrack cache poisoned") {
                cache.invalidate("conntrack cache poisoned");
            }
            cache
        }
    }
}

struct Socket(OwnedFd);

impl Socket {
    fn open() -> Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error())
                .context("opening conntrack netlink socket");
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 0b111; // NEW, UPDATE and DESTROY, before dumping.
        if unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error())
                .context("subscribing to conntrack events (NET_ADMIN required)");
        }
        let size: libc::c_int = 4 * 1024 * 1024;
        // Best effort: the kernel may clamp the buffer. ENOBUFS remains enabled
        // and is fatal to the current view; never request NETLINK_NO_ENOBUFS.
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            );
        }
        Ok(Self(descriptor))
    }

    fn request_dump(&self, sequence: u32) -> Result<()> {
        let mut request = [0_u8; 20];
        request[..4].copy_from_slice(&20_u32.to_ne_bytes());
        request[4..6].copy_from_slice(&CT_GET.to_ne_bytes());
        request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[16] = libc::AF_UNSPEC as u8;
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.0.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent != request.len() as isize {
            return Err(std::io::Error::last_os_error()).context("requesting conntrack dump");
        }
        Ok(())
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<Option<usize>> {
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = std::mem::size_of_val(&source) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let length = unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Ok(None);
            }
            return Err(error).context("receiving conntrack events");
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            bail!("truncated conntrack datagram");
        }
        if message.msg_namelen as usize != std::mem::size_of_val(&source)
            || source.nl_family != libc::AF_NETLINK as u16
            || source.nl_pid != 0
        {
            bail!("conntrack datagram was not sent by the kernel");
        }
        if length == 0 {
            bail!("conntrack socket closed");
        }
        Ok(Some(length as usize))
    }
}

#[derive(Clone)]
enum Event {
    Upsert(Entry),
    Delete(Entry),
}

enum Message {
    Event { sequence: u32, event: Event },
    Done(u32),
}

struct Dump {
    sequence: u32,
    deadline: Instant,
    cache: Cache,
    events: Vec<Event>,
}

impl Dump {
    fn new(sequence: u32, now: Instant) -> Self {
        Self {
            sequence,
            deadline: now + DUMP_DEADLINE,
            cache: Cache::new(now),
            events: Vec::new(),
        }
    }

    fn finish(mut self, now: Instant, previous: &Cache) -> Result<Cache> {
        // Replay all notifications after the dump, even when a dump row was
        // delivered later than its DESTROY or UPDATE notification.
        for event in self.events {
            self.cache.apply_at(event, now)?;
        }
        self.cache.prune(now)?;
        // A periodic dump replaces entries, never the evidence that a tuple
        // recently belonged to another generation.
        for (tuple, until) in &previous.tombstones {
            if *until > now {
                if self.cache.tombstones.len() >= MAX_TOMBSTONES
                    && !self.cache.tombstones.contains_key(tuple)
                {
                    bail!("conntrack generation tombstone limit reached");
                }
                let target = self.cache.tombstones.entry(*tuple).or_insert(*until);
                *target = (*target).max(*until);
            }
        }
        for old in previous.entries.values() {
            if !self
                .cache
                .entries
                .get(&old.identity)
                .is_some_and(|new| new.reply == old.reply)
            {
                self.cache.quarantine(old, now)?;
            }
        }
        let replacements: Vec<_> = self
            .cache
            .entries
            .values()
            .filter(|new| {
                new.observations().iter().any(|(tuple, _)| {
                    previous.index.get(tuple).is_some_and(|candidates| {
                        candidates.iter().any(|old| {
                            old.entry.identity != new.identity || old.entry.reply != new.reply
                        })
                    })
                })
            })
            .cloned()
            .collect();
        for new in replacements {
            self.cache.quarantine(&new, now)?;
        }
        self.cache.quarantine_until = previous.quarantine_until;
        if previous.quarantine_after_resync {
            self.cache.quarantine_until = now + REUSE_QUARANTINE;
        }
        self.cache.ready = true;
        self.cache.error = None;
        self.cache.valid_until = now + MAX_CACHE_AGE;
        self.cache.lost = previous.lost;
        Ok(self.cache)
    }
}

fn run(socket: Socket, shared: Arc<Mutex<Cache>>, stop: Arc<AtomicBool>) {
    let mut sequence: u32 = 1;
    let mut dump = Some(Dump::new(sequence, Instant::now()));
    let mut next_dump = Instant::now() + REFRESH;
    let mut prune_at = Instant::now();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let result = (|| -> Result<()> {
            if dump.as_ref().is_some_and(|dump| now >= dump.deadline) {
                bail!("conntrack dump timed out");
            }
            if dump.is_none() && now >= next_dump {
                sequence = sequence.wrapping_add(1).max(1);
                socket.request_dump(sequence)?;
                dump = Some(Dump::new(sequence, Instant::now()));
            }
            // Bound work before checking stop/deadlines again, even under flood.
            for _ in 0..32 {
                let Some(length) = socket.receive(&mut buffer)? else {
                    break;
                };
                let messages = parse_datagram(&buffer[..length], Instant::now())?;
                for message in messages {
                    match message {
                        Message::Event { sequence: 0, event } => {
                            if let Some(active) = &mut dump {
                                if active.events.len() == MAX_QUEUED_EVENTS {
                                    bail!("conntrack event queue limit reached");
                                }
                                active.events.push(event.clone());
                            }
                            let mut cache = locked(&shared);
                            if cache.ready {
                                cache.apply(event)?;
                            }
                        }
                        Message::Event { sequence, event } => {
                            if let Some(active) = &mut dump
                                && active.sequence == sequence
                            {
                                active.cache.apply(event)?;
                            }
                        }
                        Message::Done(sequence) => {
                            if dump
                                .as_ref()
                                .is_some_and(|active| active.sequence == sequence)
                            {
                                let completed = dump.take().expect("matched active dump");
                                let now = Instant::now();
                                let mut cache = locked(&shared);
                                *cache = completed.finish(now, &cache)?;
                                next_dump = now + REFRESH;
                            }
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            locked(&shared).invalidate(format!("{error:#}"));
            dump = None;
            next_dump = Instant::now() + RETRY;
        }
        if Instant::now() >= prune_at {
            let mut cache = locked(&shared);
            if let Err(error) = cache.prune(Instant::now()) {
                cache.invalidate(format!("{error:#}"));
                dump = None;
                next_dump = Instant::now() + RETRY;
            }
            prune_at = Instant::now() + Duration::from_secs(1);
        }
        let mut descriptor = libc::pollfd {
            fd: socket.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut descriptor, 1, POLL_MS);
        }
    }
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() >= MAX_ATTRIBUTES {
            bail!("invalid conntrack attribute header");
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if length < 4 || length > bytes.len() {
            bail!("invalid conntrack attribute length");
        }
        result.push((kind, &bytes[4..length]));
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            bail!("truncated conntrack attribute padding");
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn attr<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> Result<Option<&'a [u8]>> {
    let mut found = attributes
        .iter()
        .filter(|(candidate, _)| *candidate == kind);
    let value = found.next().map(|(_, value)| *value);
    if found.next().is_some() {
        bail!("duplicate conntrack attribute");
    }
    Ok(value)
}

fn required<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> Result<&'a [u8]> {
    attr(attributes, kind)?.context("missing conntrack attribute")
}

fn be16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(
        bytes.try_into().context("invalid conntrack u16")?,
    ))
}
fn be32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().context("invalid conntrack u32")?,
    ))
}

fn parse_tuple(bytes: &[u8], family: u8, default_zone: u16) -> Result<Option<(Tuple, u16)>> {
    let fields = attributes(bytes)?;
    let proto = attributes(required(&fields, 2)?)?;
    let number = required(&proto, 1)?;
    let protocol = match number {
        [6] => Protocol::Tcp,
        [17] => Protocol::Udp,
        [_] => return Ok(None),
        _ => bail!("invalid conntrack protocol"),
    };
    let ip = attributes(required(&fields, 1)?)?;
    let (source, destination) = if family == libc::AF_INET as u8 {
        (
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(required(&ip, 1)?).context("invalid conntrack IPv4")?,
            )),
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(required(&ip, 2)?).context("invalid conntrack IPv4")?,
            )),
        )
    } else if family == libc::AF_INET6 as u8 {
        (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(required(&ip, 3)?).context("invalid conntrack IPv6")?,
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(required(&ip, 4)?).context("invalid conntrack IPv6")?,
            )),
        )
    } else {
        return Ok(None);
    };
    let zone = attr(&fields, 3)?
        .map(be16)
        .transpose()?
        .unwrap_or(default_zone);
    Ok(Some((
        Tuple {
            protocol,
            source: SocketAddr::new(source, be16(required(&proto, 2)?)?),
            destination: SocketAddr::new(destination, be16(required(&proto, 3)?)?),
        },
        zone,
    )))
}

fn parse_entry(bytes: &[u8], delete: bool, now: Instant) -> Result<Option<Event>> {
    if bytes.len() < 4 || bytes[1] != 0 {
        bail!("invalid conntrack nfgenmsg");
    }
    let family = bytes[0];
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Ok(None);
    }
    let fields = attributes(&bytes[4..])?;
    let zone = attr(&fields, 18)?.map(be16).transpose()?.unwrap_or(0);
    let Some((original, original_zone)) = parse_tuple(required(&fields, 1)?, family, zone)? else {
        return Ok(None);
    };
    let Some((reply, reply_zone)) = parse_tuple(required(&fields, 2)?, family, zone)? else {
        bail!("conntrack reply protocol differs");
    };
    if original.protocol != reply.protocol {
        bail!("conntrack tuple protocols differ");
    }
    let identity = Identity {
        id: be32(required(&fields, 12)?)?,
        original,
        zones: (original_zone, reply_zone),
    };
    if delete {
        return Ok(Some(Event::Delete(Entry {
            identity,
            reply,
            expires: now,
        })));
    }
    let timeout = be32(required(&fields, 7)?)?;
    let expires = now + Duration::from_secs(timeout as u64).min(MAX_CACHE_AGE);
    Ok(Some(Event::Upsert(Entry {
        identity,
        reply,
        expires,
    })))
}

fn parse_datagram(mut bytes: &[u8], now: Instant) -> Result<Vec<Message>> {
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            bail!("truncated conntrack netlink header");
        }
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let sequence = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if length < 16 || length > bytes.len() {
            bail!("invalid conntrack message length");
        }
        if flags & 0x10 != 0 {
            bail!("conntrack dump interrupted");
        }
        let body = &bytes[16..length];
        match kind {
            1 => {} // NLMSG_NOOP
            2 => {
                if body.len() < 4 {
                    bail!("truncated conntrack error");
                }
                let error = i32::from_ne_bytes(body[..4].try_into().unwrap());
                if error != 0 {
                    bail!(
                        "conntrack netlink error {}",
                        std::io::Error::from_raw_os_error(error.saturating_neg())
                    );
                }
            }
            3 => {
                if !body.is_empty()
                    && (body.len() < 4 || i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0)
                {
                    bail!("conntrack dump failed");
                }
                messages.push(Message::Done(sequence));
            }
            4 => bail!("conntrack event buffer overrun"),
            CT_NEW | CT_DELETE => {
                if let Some(event) = parse_entry(body, kind == CT_DELETE, now)? {
                    messages.push(Message::Event { sequence, event });
                }
            }
            _ => {}
        }
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            bail!("truncated conntrack message padding");
        }
        bytes = &bytes[aligned..];
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(source: &str, destination: &str) -> Tuple {
        Tuple {
            protocol: Protocol::Tcp,
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
        }
    }

    fn entry(original: Tuple, translated: Tuple, now: Instant) -> Entry {
        Entry {
            identity: Identity {
                id: 42,
                original,
                zones: (0, 0),
            },
            reply: translated.reversed(),
            expires: now + Duration::from_secs(40),
        }
    }

    fn ready_cache(now: Instant) -> Cache {
        let mut cache = Cache::new(now);
        cache.ready = true;
        cache.error = None;
        cache.valid_until = now + MAX_CACHE_AGE;
        cache
    }

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
        result.extend_from_slice(&kind.to_ne_bytes());
        result.extend_from_slice(payload);
        result.resize((result.len() + 3) & !3, 0);
        result
    }

    fn tuple_payload(tuple: Tuple, zone: Option<u16>) -> Vec<u8> {
        let mut ip = Vec::new();
        for (source, address) in [(true, tuple.source.ip()), (false, tuple.destination.ip())] {
            match address {
                IpAddr::V4(address) => {
                    ip.extend(attribute(if source { 1 } else { 2 }, &address.octets()))
                }
                IpAddr::V6(address) => {
                    ip.extend(attribute(if source { 3 } else { 4 }, &address.octets()))
                }
            }
        }
        let mut proto = attribute(
            1,
            &[if tuple.protocol == Protocol::Tcp {
                6
            } else {
                17
            }],
        );
        proto.extend(attribute(2, &tuple.source.port().to_be_bytes()));
        proto.extend(attribute(3, &tuple.destination.port().to_be_bytes()));
        let mut result = attribute(0x8001, &ip);
        result.extend(attribute(0x8002, &proto));
        if let Some(zone) = zone {
            result.extend(attribute(3, &zone.to_be_bytes()));
        }
        result
    }

    fn entry_payload(entry: &Entry, timeout: u32) -> Vec<u8> {
        let mut result = vec![
            if entry.identity.original.source.is_ipv4() {
                libc::AF_INET as u8
            } else {
                libc::AF_INET6 as u8
            },
            0,
            0,
            0,
        ];
        result.extend(attribute(
            0x8001,
            &tuple_payload(entry.identity.original, Some(entry.identity.zones.0)),
        ));
        result.extend(attribute(
            0x8002,
            &tuple_payload(entry.reply, Some(entry.identity.zones.1)),
        ));
        result.extend(attribute(7, &timeout.to_be_bytes()));
        result.extend(attribute(12, &entry.identity.id.to_be_bytes()));
        result
    }

    fn message(kind: u16, flags: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        result.extend_from_slice(&kind.to_ne_bytes());
        result.extend_from_slice(&flags.to_ne_bytes());
        result.extend_from_slice(&sequence.to_ne_bytes());
        result.extend_from_slice(&0_u32.to_ne_bytes());
        result.extend_from_slice(body);
        result.resize((result.len() + 3) & !3, 0);
        result
    }

    #[test]
    fn combined_nat_maps_three_stages_and_both_directions() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let after = tuple("172.18.0.1:45000", "172.18.0.2:80");
        let mut cache = ready_cache(now);
        cache
            .apply(Event::Upsert(entry(before, after, now)))
            .unwrap();
        for observation in [
            before,
            Tuple {
                destination: after.destination,
                ..before
            },
            after,
        ] {
            assert_eq!(
                cache.translate(observation, now),
                Outcome::Translated(Translation {
                    before,
                    after,
                    zones: (0, 0)
                })
            );
            assert_eq!(
                cache.translate(observation.reversed(), now),
                Outcome::Translated(Translation {
                    before: after.reversed(),
                    after: before.reversed(),
                    zones: (0, 0)
                })
            );
        }
        let nonexistent_stage = Tuple {
            source: after.source,
            ..before
        };
        assert_eq!(cache.translate(nonexistent_stage, now), Outcome::Missing);
    }

    #[test]
    fn dnat_snat_no_nat_and_ipv6_udp_share_exact_tuple_matching() {
        let now = Instant::now();
        for (before, after) in [
            (
                tuple("198.51.100.2:40000", "192.0.2.1:8080"),
                tuple("198.51.100.2:40000", "172.18.0.2:80"),
            ),
            (
                tuple("172.18.0.2:40000", "198.51.100.2:80"),
                tuple("192.0.2.1:45000", "198.51.100.2:80"),
            ),
            (
                tuple("192.0.2.1:40000", "198.51.100.2:80"),
                tuple("192.0.2.1:40000", "198.51.100.2:80"),
            ),
            (
                Tuple {
                    protocol: Protocol::Udp,
                    ..tuple("[2001:db8::1]:40000", "[2001:db8::2]:8080")
                },
                Tuple {
                    protocol: Protocol::Udp,
                    ..tuple("[2001:db8::1]:40000", "[fd00::2]:80")
                },
            ),
        ] {
            let mut cache = ready_cache(now);
            cache
                .apply(Event::Upsert(entry(before, after, now)))
                .unwrap();
            let expected = if before == after {
                Outcome::Unchanged
            } else {
                Outcome::Translated(Translation {
                    before,
                    after,
                    zones: (0, 0),
                })
            };
            assert_eq!(cache.translate(before, now), expected);
            assert_eq!(cache.translate(after, now), expected);
            let other_protocol = Tuple {
                protocol: if before.protocol == Protocol::Tcp {
                    Protocol::Udp
                } else {
                    Protocol::Tcp
                },
                ..before
            };
            assert_eq!(cache.translate(other_protocol, now), Outcome::Missing);
        }
    }

    #[test]
    fn conflicting_zones_and_generations_never_choose_an_arbitrary_mapping() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let after = tuple("198.51.100.2:40000", "172.18.0.2:80");
        for other_zone in [false, true] {
            let mut cache = ready_cache(now);
            let first = entry(before, after, now);
            let mut second = first.clone();
            if other_zone {
                second.identity.zones = (1, 2);
            } else {
                second.identity.id += 1;
            }
            cache.apply(Event::Upsert(first.clone())).unwrap();
            cache.apply(Event::Upsert(second.clone())).unwrap();
            assert_eq!(cache.translate(before, now), Outcome::Ambiguous);
            cache.apply(Event::Delete(second)).unwrap();
            assert!(matches!(
                cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)),
                Outcome::Translated(_)
            ));
            cache.apply(Event::Delete(first)).unwrap();
            assert!(cache.index.is_empty());
        }
    }

    #[test]
    fn update_replaces_old_translation_and_expiry_is_absolute() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let old_after = tuple("198.51.100.2:40000", "172.18.0.2:80");
        let after = tuple("198.51.100.2:40000", "172.18.0.3:80");
        let mut cache = ready_cache(now);
        cache
            .apply(Event::Upsert(entry(before, old_after, now)))
            .unwrap();
        cache
            .apply(Event::Upsert(entry(before, after, now)))
            .unwrap();
        assert_eq!(cache.translate(old_after, now), Outcome::Ambiguous);
        assert_eq!(cache.translate(before, now), Outcome::Ambiguous);
        assert!(
            matches!(cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)), Outcome::Translated(translation) if translation.after == after)
        );
        assert_eq!(
            cache.translate(before, now + Duration::from_secs(40)),
            Outcome::Missing
        );
        assert_eq!(
            cache.translate(before, now + MAX_CACHE_AGE),
            Outcome::Unavailable
        );
        cache.prune(now + Duration::from_secs(40)).unwrap();
        assert!(cache.entries.is_empty() && cache.index.is_empty());
    }

    #[test]
    fn loss_invalidates_even_already_obtained_views() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let after = tuple("198.51.100.2:40000", "172.18.0.2:80");
        let mut cache = ready_cache(now);
        cache
            .apply(Event::Upsert(entry(before, after, now)))
            .unwrap();
        let shared = Arc::new(Mutex::new(cache));
        let view = View {
            ready: true,
            error: None,
            lost: 0,
            shared: shared.clone(),
        };
        assert!(matches!(
            view.translate(before.protocol, before.source, before.destination),
            Outcome::Translated(_)
        ));
        locked(&shared).invalidate("ENOBUFS");
        assert_eq!(
            view.translate(before.protocol, before.source, before.destination),
            Outcome::Unavailable
        );
        assert_eq!(locked(&shared).lost, 1);
    }

    #[test]
    fn dump_replays_notifications_after_rows_including_destroy() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let old = entry(before, tuple("198.51.100.2:40000", "172.18.0.2:80"), now);
        let new = entry(before, tuple("198.51.100.2:40000", "172.18.0.3:80"), now);
        let mut dump = Dump::new(1, now);
        // The update notification arrived before a stale dump row.
        dump.events.push(Event::Upsert(new.clone()));
        dump.cache.apply(Event::Upsert(old.clone())).unwrap();
        let mut previous = ready_cache(now);
        previous.lost = 3;
        let cache = dump.finish(now, &previous).unwrap();
        assert_eq!(cache.lost, 3);
        assert!(
            matches!(cache.translate(before, now + REUSE_QUARANTINE + Duration::from_secs(1)), Outcome::Translated(translation) if translation.after == new.reply.reversed())
        );
        let mut dump = Dump::new(2, now);
        dump.events.push(Event::Delete(old.clone()));
        dump.cache.apply(Event::Upsert(old)).unwrap();
        assert_eq!(
            dump.finish(now, &previous).unwrap().translate(before, now),
            Outcome::Ambiguous
        );
    }

    #[test]
    fn deleted_generation_cannot_relabel_deferred_packets_after_tuple_reuse() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let old = entry(before, tuple("172.18.0.1:45000", "172.18.0.2:80"), now);
        let mut new = entry(before, tuple("172.18.0.1:45001", "172.18.0.3:80"), now);
        new.identity.id += 1;
        let mut cache = ready_cache(now);
        cache.apply_at(Event::Upsert(old.clone()), now).unwrap();
        cache.apply_at(Event::Delete(old.clone()), now).unwrap();
        cache.apply_at(Event::Upsert(new.clone()), now).unwrap();
        for (observation, _) in old.observations() {
            assert_eq!(
                cache.translate(observation, now + Duration::from_secs(5)),
                Outcome::Ambiguous
            );
        }
        assert!(
            matches!(cache.translate(before, now + REUSE_QUARANTINE), Outcome::Translated(translation) if translation.after == new.reply.reversed())
        );
        // Ordinary timeout refreshes neither introduce nor extend quarantine.
        cache
            .apply_at(Event::Upsert(new), now + REUSE_QUARANTINE)
            .unwrap();
        assert!(matches!(
            cache.translate(before, now + REUSE_QUARANTINE),
            Outcome::Translated(_)
        ));
    }

    #[test]
    fn resync_preserves_tombstones_and_detects_disappeared_or_replaced_generations() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let old = entry(before, tuple("198.51.100.2:40000", "172.18.0.2:80"), now);
        let mut new = entry(before, tuple("198.51.100.2:40000", "172.18.0.3:80"), now);
        new.identity.id += 1;
        for deleted in [false, true] {
            let mut previous = ready_cache(now);
            previous.apply_at(Event::Upsert(old.clone()), now).unwrap();
            if deleted {
                previous.apply_at(Event::Delete(old.clone()), now).unwrap();
            }
            let mut dump = Dump::new(2, now);
            dump.cache
                .apply_at(Event::Upsert(new.clone()), now)
                .unwrap();
            let result = dump.finish(now, &previous).unwrap();
            assert_eq!(result.translate(before, now), Outcome::Ambiguous);
            assert_eq!(result.translate(old.reply, now), Outcome::Ambiguous);
            let mut second = Dump::new(3, now);
            second
                .cache
                .apply_at(Event::Upsert(new.clone()), now)
                .unwrap();
            let result = second
                .finish(now + Duration::from_secs(1), &result)
                .unwrap();
            assert_eq!(
                result.translate(before, now + Duration::from_secs(5)),
                Outcome::Ambiguous
            );
            assert!(matches!(
                result.translate(before, now + REUSE_QUARANTINE),
                Outcome::Translated(_)
            ));
        }
        let mut previous = ready_cache(now);
        previous.apply_at(Event::Upsert(old), now).unwrap();
        let result = Dump::new(4, now).finish(now, &previous).unwrap();
        assert_eq!(result.translate(before, now), Outcome::Ambiguous);
    }

    #[test]
    fn loss_quarantines_even_previously_unknown_tuples_after_resync() {
        let now = Instant::now();
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let mut previous = ready_cache(now);
        previous.invalidate("ENOBUFS");
        let mut dump = Dump::new(2, now);
        dump.cache
            .apply_at(Event::Upsert(entry(before, before, now)), now)
            .unwrap();
        let result = dump.finish(now, &previous).unwrap();
        assert_eq!(
            result.translate(before, now + Duration::from_secs(5)),
            Outcome::Ambiguous
        );
        assert_eq!(
            result.translate(before, now + REUSE_QUARANTINE),
            Outcome::Unchanged
        );
        assert_eq!(result.lost, 1);
    }

    #[test]
    fn tombstone_memory_is_bounded_and_overflow_reports_failure() {
        let now = Instant::now();
        let mut cache = ready_cache(now);
        for value in 0..MAX_TOMBSTONES {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(value as u32)), 1);
            cache.tombstones.insert(
                Tuple {
                    protocol: Protocol::Tcp,
                    source: address,
                    destination: address,
                },
                now + REUSE_QUARANTINE,
            );
        }
        let before = tuple("198.51.100.2:40000", "192.0.2.1:8080");
        let error = cache
            .apply_at(Event::Delete(entry(before, before, now)), now)
            .unwrap_err();
        assert!(error.to_string().contains("tombstone limit"));
        assert_eq!(cache.tombstones.len(), MAX_TOMBSTONES);
    }

    #[test]
    fn parses_kernel_layout_ipv4_ipv6_and_directional_zones() {
        let now = Instant::now();
        for (before, after) in [
            (
                tuple("198.51.100.2:40000", "192.0.2.1:8080"),
                tuple("198.51.100.2:40000", "172.18.0.2:80"),
            ),
            (
                Tuple {
                    protocol: Protocol::Udp,
                    ..tuple("[2001:db8::1]:40000", "[2001:db8::2]:8080")
                },
                Tuple {
                    protocol: Protocol::Udp,
                    ..tuple("[2001:db8::1]:40000", "[fd00::2]:80")
                },
            ),
        ] {
            let mut expected = entry(before, after, now);
            expected.identity.zones = (7, 9);
            let body = entry_payload(&expected, 12);
            let data = message(CT_NEW, 2, 3, &body);
            let parsed = parse_datagram(&data, now).unwrap();
            let Message::Event {
                sequence,
                event: Event::Upsert(parsed),
            } = &parsed[0]
            else {
                panic!("expected entry");
            };
            assert_eq!(*sequence, 3);
            assert_eq!(parsed.identity, expected.identity);
            assert_eq!(parsed.reply, expected.reply);
            assert_eq!(parsed.expires, now + Duration::from_secs(12));
            assert!(
                matches!(parse_entry(&body, true, now).unwrap(), Some(Event::Delete(entry)) if entry.identity == expected.identity)
            );
        }
    }

    #[test]
    fn malformed_truncated_duplicate_or_interrupted_dumps_fail_closed() {
        let now = Instant::now();
        let expected = entry(
            tuple("198.51.100.2:40000", "192.0.2.1:8080"),
            tuple("198.51.100.2:40000", "172.18.0.2:80"),
            now,
        );
        let body = entry_payload(&expected, 10);
        let valid = message(CT_NEW, 2, 1, &body);
        for length in 1..valid.len() {
            assert!(
                parse_datagram(&valid[..length], now).is_err(),
                "accepted truncation at {length}"
            );
        }
        let mut duplicate = body.clone();
        duplicate.extend(attribute(12, &42_u32.to_be_bytes()));
        assert!(parse_entry(&duplicate, false, now).is_err());
        for data in [
            message(3, 0x10, 1, &0_i32.to_ne_bytes()),
            message(3, 0, 1, &(-libc::EINTR).to_ne_bytes()),
            message(4, 0, 0, &[]),
            message(2, 0, 1, &(-libc::EPERM).to_ne_bytes()),
        ] {
            assert!(parse_datagram(&data, now).is_err());
        }
        let excessive: Vec<_> = (0..=MAX_ATTRIBUTES)
            .flat_map(|_| attribute(0, &[]))
            .collect();
        assert!(attributes(&excessive).is_err());
        assert!(matches!(
            parse_datagram(&message(3, 0, 1, &0_i32.to_ne_bytes()), now).unwrap()[0],
            Message::Done(1)
        ));
    }
}
