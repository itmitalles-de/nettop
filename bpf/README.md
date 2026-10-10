# Optional socket metadata events

`cargo build --features ebpf` compiles `lifecycle.bpf.c` with clang's BPF backend
and libbpf development headers. The default build needs neither tool. The
result is embedded in the Rust binary; the runtime loader uses `libbpf.so.1`
and never accepts an external BPF object. `NETTOP_BPF_CLANG` can name an explicit
compiler executable. Linux little-endian x86_64 and aarch64 builds are supported;
actual kernel validation currently covers x86_64 Linux 6.8.

The CO-RE declarations contain only accessed fields. Kernel BTF resolves their
real layouts. Loading requires BPF and PERFMON capabilities and compatible BTF
functions. The loader must attach every program successfully or detach the
partial set and report that the optional backend is unavailable. Map/ring
access through existing descriptors continues after dropping those capabilities.
No maps or programs need to be pinned.
The `armed` array has one `u32` key and value, initially zero. The loader writes
one only after every hook is attached; entry state and metadata publication stay
disabled during attachment so partial trampoline configurations cannot seed
an unmatched operation.

`inet_sendmsg` and `inet6_sendmsg` cover the IP-family userspace send paths;
`socket.c` can bypass the exported `sock_sendmsg` wrapper. `inet_recvmsg` and
`inet6_recvmsg` cover receive calls, including the security-check bypass for
later recvmmsg datagrams. Successful bind, TCP connect and accept hooks provide
earlier lifecycle evidence, and
`inet_release` ends a socket incarnation. Actorless TCP clone events let a
later accept connect queued packets with that same child; the child tuple can
still be incomplete at clone return, so only ID, namespace and time are birth
evidence. Final `__sk_free` cleanup also removes IDs for never-accepted children.
Only successful operations publish send/receive/connect/accept/bind records.
Close records are lifecycle boundaries, never proof that the closer owned
preceding traffic.

The event ABI is the 112-byte `lifecycle_event` declaration in the C source,
mirrored by `Event` in `src/events.rs`. Ports use host byte order, address bytes
use network order (IPv4 occupies the first four bytes), and event times use the
monotonic clock. The process identity contains the initial PID namespace TGID
and group leader's boot-time start in nanoseconds; `/proc/PID/stat` uses that
start time in clock ticks. Network namespace identity is `net->ns.inum`, matching
`stat(/proc/PID/ns/net).st_ino`; it is not a socket network namespace cookie.

`socket_id` is an opaque increasing ID scoped to this loaded object. Kernel
socket pointers are internal map keys and never appear in event records. A
bounded non-evicting map retains IDs until release or final socket destruction;
capacity failures are counted instead of silently reassigning live incarnations.
The bounded per-thread call
map preserves entry time and outgoing UDP peer metadata through automatic bind.
Nested same-kind calls are rejected conservatively. UDP receive peer metadata
is read after the call; a caller that requests no peer address can leave it
unknown. No payload bytes, iovecs, or send/receive byte counts are read or stored.

`events` is a 4 MiB ring buffer. `stats` is an array with one `u32` key (zero)
and nine `u64` fields: ring reservation failures, in-flight map update failures,
socket-ID failures, peer metadata read failures, nested calls, last nested
call age in nanoseconds, last nested depth, a bitmask of nested call kinds and
in-flight map deletion failures.
The last age/depth are diagnostic snapshots and may be updated independently
by concurrent collisions; no process or thread IDs are exported. Consumers must surface
losses and avoid confident attribution across missing lifecycle evidence.

Events identify the process performing an operation, not exclusive descriptor
ownership. Forked, passed and shared sockets therefore require conservative
correlation. Kernel tasks and io_uring worker actors are flagged as unreliable.
Socket tuple reuse requires packet timestamps and lifecycle boundaries; joining
only by tuple can falsely assign earlier bytes to a later process. Packet
capture remains the sole process traffic byte source.
