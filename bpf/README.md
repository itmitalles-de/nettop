# Optional socket metadata and IP packet capture

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

The lifecycle ABI is the 112-byte `lifecycle_event` declaration in the C source,
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
and ten `u64` fields: ring reservation failures, in-flight map update failures,
socket-ID failures, peer metadata read failures, nested calls, last nested
call age in nanoseconds, last nested depth, a bitmask of nested call kinds and
in-flight map deletion failures, and fatal socket-identity cleanup failures.
The last age/depth are diagnostic snapshots and may be updated independently
by concurrent collisions; no process or thread IDs are exported. Consumers must surface
losses and avoid confident attribution across missing lifecycle evidence.

Events identify the process performing an operation, not exclusive descriptor
ownership. Forked, passed and shared sockets therefore require conservative
correlation. Kernel tasks and io_uring worker actors are flagged as unreliable.
Socket tuple reuse requires packet timestamps and lifecycle boundaries; joining
only by tuple can falsely assign earlier bytes to a later process. Captured IP packets remain the sole process traffic byte source; operation
return values never supply traffic byte totals.


## Socket-bound IP packets

Five additional entry hooks bring the required set to 23 programs:
`ip_finish_output2` and `ip6_finish_output2` observe transmit IP skbs after
POST_ROUTING and software fragmentation/GSO splitting; `tcp_rcv_established`
and `tcp_rcv_state_process` observe the mutually exclusive TCP established and
other ordinary state paths after socket demultiplexing; and
`__udp_enqueue_schedule_skb` observes the common IPv4/IPv6 UDP queue boundary.
The entire program set must attach before `armed` is enabled. Missing hooks
reject the optional backend as a whole, leaving the standard capture fallback.

The 80-byte `packet_event` / Rust `PacketEvent` ABI carries monotonic time,
opaque socket incarnation, inode, network namespace, namespace-local interface
index, IP byte length, address family/protocol, packet direction, and the actual
packet address/port tuple. These addresses can differ from the socket tuple
because of NAT. Flag bit 0 means transport ports were available; bit 1 marks
IPv4 fragmentation. No current-task PID is assigned in packet/softirq context.
Only IP base headers and four transport-port bytes are read, never payload or
TCP/UDP data contents. Matching packet headers is deliberately not accepted as
proof that two observations represent the same packet.

The counted length is `skb->len + (skb->data - skb_network_header(skb))`:
already pulled headers are restored to the observed IP skb's length. GRO and
hardware-offloaded GSO stay aggregated; no extra per-segment wire headers are
invented. Software-fragmented transmit packets are observed separately; receive
packets have passed IP reassembly. Neighbor/receive-queue rejection can occur
after these observation points: these are captured IP bytes, not a promise of
successful delivery. Retransmitted IP skbs remain real traffic observations.

All-interface TCP/UDP process accounting uses this socket-bound stream alone,
including foreign namespaces and their internal loopback. A namespace-local
interface index never selects a same-numbered host interface. Selected host
interfaces keep their independent pcap view, including forwarding; pure routed
TCP/UDP has no local socket endpoint in the All view. Non-TCP/UDP capture remains
unattributed pcap traffic. The two TCP/UDP byte sources are never added to the
same view. Selected-interface NAT/untracked ambiguity remains conservative.

Ownership still requires lifecycle evidence for the exact socket incarnation.
An open actor outside its observed syscall additionally needs the same current
inode, namespace and full process identity from the descriptor inventory;
shared or conflicting actors veto attribution. The uniquely observed reader can
receive queued bytes even if a descriptor was transferred after packet arrival;
this describes the process handling the traffic, not historical descriptor
possession. Unknown packet owners remain visible rather than guessed.

Lifecycle and packet records share the 4 MiB kernel ring and bounded userspace
queues. Every bounded poll publishes both record classes together with loss
counters; mixed queues reaching one quarter capacity notify the same coalescing
wake signal as pcap pressure. All resource ceilings remain fixed. Overflow is
visible and invalidates uncertain ownership; it never silently evicts a
conflicting actor.

Socket-ID deletion errors other than ENOENT are counted. A failed final
`__sk_free` deletion permanently clears `armed` and increments the fatal status:
otherwise kernel pointer reuse could inherit an old incarnation. The worker
reports a persistent unavailable error and detaches its programs. Only a new
object on restart can recover. Runtime failure does not switch an active All
view to pcap midstream, which could count already observed traffic twice.

Kernel validation results belong in the repository state and test evidence;
compiling this object alone does not establish that a target kernel supports
all 23 hooks.
