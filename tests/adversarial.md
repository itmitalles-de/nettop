# Adversarial attribution integration tests

Run only in a dedicated QEMU/KVM guest. These tests attach the optional BPF
programs, deliberately overflow their event ring, alter **guest** realtime, add
an exact-port temporary nftables rule, and delete one deliberately created
conntrack entry. A temporary accept-only lo state-counter table activates
conntrack hooks even in fresh guests with no existing firewall. Every table is
removed in `finally`. They must never run on a workstation or shared machine.

Build with `cargo build --release --features ebpf`. The guest needs libbpf,
libpcap, Python 3, a C compiler, liburing development headers, nftables and
conntrack. Run as guest root:

```sh
python3 tests/adversarial.py target/release/nettop --isolated-vm --output /tmp/nettop-adversarial-results
```

Repeat with `--interface all` for the global socket-packet path. The default
`--interface lo` tests selected-device capture; its UDP totals are exact, whereas
All includes legitimate SSH/system traffic from other namespaces and therefore
checks the fixture actors rather than globally excluding unrelated traffic.
Clock-step uncertainty applies to selected pcap timestamps; All uses monotonic
kernel timestamps and must continue without a clock warning.

On a slow CPU emulator, `--readiness-delay 3` avoids competing proc polling
during BPF startup. It does not change any product timeout or readiness check.

`--case NAME` selects one case. Each case records the actual kernel snapshot,
actor PIDs and proof that its trigger occurred. Process bytes remain captured
IP bytes; syscall results establish the traffic fixture, never substitute
accounting counters.

| Case | Trigger and safety assertion |
| --- | --- |
| `fork` | A child inherits both UDP FDs but performs no I/O. It must receive no bytes. |
| `scm-rights` | A datagram queues before the receiving FD passes to an active reader and a passive holder. The passive holder must receive no bytes. A positively observed actual reader may receive RX; this does not claim historical FD ownership. |
| `reuseport-unread` | Two processes bind the same UDP port; readiness proves which socket actually queued the packets. Neither process reads. The other process must receive no RX. Unknown RX is permitted. |
| `io-uring` | `IOSQE_ASYNC` forces a UDP send through io-wq while a forked process passively holds the same FD. Only the supported actor or unknown may receive TX; unrelated worker/holder PIDs must receive none. |
| `tcp-fastopen` | The guest permits cookie-free SYN data, delays accept, and verifies both `TCPI_OPT_SYN_DATA` and a `TCPFastOpenActive` increment. Unsupported ownership remains unknown. The previous guest sysctl is restored. |
| `tcp-retransmit` | An exact-port guest rule drops ACKs until the kernel retransmits after the sender closes its final FD. `RetransSegs` must increase and a header-only AF_PACKET witness must observe the same payload sequence twice on this exact connection; the retransmission must not be credited as live ownership. The rule is removed even on assertion failure. |
| `event-overflow` | Stop all threads of this test's monitor, create at least 100,000 lifecycle records against its 4 MiB ring, resume and transmit a datagram. Loss must be visible and attribution quarantined. |
| `clock-pressure` | Pin all monitor threads and six busy workers to one guest CPU. Verify measured runqueue delay, conserve bytes, and forbid ownership by unrelated actors under preemption. |
| `clock-step` | Stop this monitor, advance guest realtime by 30 seconds, transmit and restore the clock before resuming. Uncertain timestamps must be visible and the bytes unknown. Active guest timesyncd is restored. |
| `conntrack-reuse` | Hold packet consumption, send from an old socket, delete its exact CT tuple, and send from another PID using the same source port. Old/new packet bytes must never cross to the replacement/original PID. |

The overflow and clock snapshots fall after the two-second packet defer period
but within the three-second evidence quarantine. The harness stops and reaps
its own monitors and children. The only global mutations happen inside the
explicitly required private guest; the VM owner remains responsible for stopping
that guest after testing.

For the Fast Open bitmap definitions, see the
[Linux IP sysctl documentation](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#tcp-fastopen-integer).

## Verified runtime matrix (2026-10-10)

The implementation at `b5f3b56` was exercised in separately owned guests:

- x86_64 Ubuntu 24.04, Linux 6.8.0-146: all original nine adversarial scenarios;
  added scheduler-pressure and precise retransmission witnesses in both scopes.
  The complete unprivileged UI/capability helper retained only the documented
  per-thread rights, loaded 23 probes, and removed its helper and BPF programs
  on exit. A private BPF fault build forced final socket-ID deletion failure:
  the object disarmed, withheld subsequent packet evidence and recovered only
  after loading a fresh object.
- x86_64 Ubuntu 24.04, Linux 7.0.0-38: all ten scenarios in both `lo` and `all`,
  including exact selected-device UDP totals and actor restrictions.
- aarch64 Ubuntu 24.04 under QEMU TCG, Linux 6.8.0-142: native libbpf loaded all
  23 programs in 2.712 seconds; IPv4/IPv6 TCP/UDP packets in both directions,
  all seven lifecycle event kinds, zero kernel event losses and final socket-ID
  cleanup were observed. The unchanged cross-built application passed three
  idle starts and SCM_RIGHTS, forced-async io_uring and proven Fast Open in both
  scopes. One selected TFO run showed conservative timestamp degradation under
  emulation load; its idle repeat passed. Busy initial provisioning also caused
  the existing three-second BPF startup deadline to expire visibly. No product
  deadline or timestamp guard was relaxed for these tests.

This matrix establishes actual kernel execution, not just cross-compilation.
It does not claim exhaustive coverage of every kernel/configuration or that
CPU emulation offers native timing guarantees. Large logs and guest resources
remain outside the repository in the task's review directory.
