# Optional attribution kernel tests

Run these tests only inside a dedicated QEMU/KVM guest. A privileged Docker
container shares the host kernel and is not sufficient isolation for global BPF
tracing. The script verifies both the explicit `--isolated-vm` argument and the
virtualization type before launching nwtop.

Build nwtop with `cargo build --release --features ebpf`; the build requires
clang with a BPF backend and libbpf development headers. The guest needs BTF,
libbpf.so.1, libpcap, Python 3 and iproute2. As guest root:

```sh
python3 tests/extended.py --isolated-vm target/release/nwtop
```

`--case tcp4|tcp6|udp4|udp6|exited|burst` selects an individual case. Every socket
exchange finishes without deliberate delays, typically within a millisecond;
the test rejects runs whose median socket lifetime is not below 25 ms. TCP
accepts and both UDP endpoints are created after packet capture is ready and
close before the final five-second snapshot. Sender and receiver are separate
processes. The UDP test uses unconnected sendto/recvfrom and rotates both sockets.
A separate case exits and reaps the receiver before the snapshot, so even its
`/proc/PID/stat` identity is gone.

The assertions require actual BPF links before sending, an active optional
backend without capture drops, and attributed IP byte
counts at least equal to transferred application payload in both directions for
both processes. Upper bounds detect duplicate loopback counting. The test never
uses syscall return sizes as traffic measurements. It reports median and maximum
socket lifetimes, attributed totals, and unknown totals as JSON lines.
Degraded-status notes fail the test except for the precise missing-conntrack
notice on TCP: control packets after a proven ownership window may remain
unknown. That exception requires positive unknown traffic bounded to 1024 bytes
per socket and direction; all four payload attribution checks still apply.

The `burst` case briefly stops its own monitor process after verifying its
capture socket and BPF links. It binds and closes 2500 UDP sockets without
sending packets, queuing at least 5000 metadata events while avoiding pcap and
conntrack queue pressure. After resuming every monitor thread, a real datagram
must be attributed exactly in both directions without degradation. This exceeds
the libbpf callback's 2048-record batch limit while remaining below the kernel
ring capacity, detecting a callback that discards the remaining records instead
of yielding. Cleanup always resumes a stopped monitor before terminating it.

Only loopback sockets, ephemeral ports, temporary configuration and child
processes owned by the harness are created. Shutdown waits are bounded and
owned subprocesses are cleaned up on failure. These cases do not establish
correctness for arbitrary shared descriptors, io_uring workers, packet loss,
unsupported kernels, or every namespace/NAT topology; those need separate tests.

## Namespace and NAT integration

Inside the same isolated guest, install nftables and run:

```sh
python3 tests/namespaces.py --isolated-vm target/release/nwtop
```

The harness owns three temporary network namespaces (client/router/server),
veth links and a bridge. Only its router namespace receives forwarding and NAT
rules. Separate client/server PIDs exchange TCP/UDP traffic through direct,
DNAT, SNAT and combined translation paths. All and a selected outer interface
are checked independently for attribution and duplicate counting. Existing guest
networking and firewall configuration are preserved, and owned namespaces and
processes are removed even on failure.

Direct positive cases explicitly enable conntrack in the private router namespace.
Two additional untracked TCP/UDP cases deliberately queue replies before recv;
they assert conservative unknown RX and the visible missing-conntrack notice.
These cases document a limitation rather than claiming complete attribution
without conntrack tracking.
