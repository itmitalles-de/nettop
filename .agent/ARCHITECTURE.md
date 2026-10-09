# Architecture

`main.rs` owns CLI validation, source selection, refresh timing and terminal
restoration. `ui.rs` receives snapshots and draws the nvtop-style layout; it
never derives measurements from queue lengths or substitutes demo values.

`collector.rs` reads `/proc/net/dev`, sysfs interface metadata and getifaddrs.
Interface rates are monotonic counter deltas divided by the measured interval.
Device removal preserves the UI and permits selection of another device.

`capture.rs` owns a single dynamically loaded, non-promiscuous libpcap session
and its worker thread. It captures a bounded prefix for parsing headers, stores
only flow byte counts, and closes its own worker/handle on drop. SLL2 interface
indexes make device filtering explicit. Queue and capture drops remain visible.

`packet.rs` handles IP/TCP/UDP headers, link formats, VLANs, IPv6 extensions and
fragments. Process rates count observed IP bytes; interface totals also include
other protocols and link overhead. All-interface mode can observe the same
traffic at several virtual links and warns accordingly.

`sockets.rs` correlates flow endpoints with the current namespace's socket tables
and `/proc/PID/fd` socket inodes. Identity includes PID and start time. Owners are
scanned at most once per second; closed sockets survive briefly for late packets.
Ambiguous and shared ownership remains unattributed. Current sockets retain
totals through idle periods; expired closed entries and all maps are bounded.

The live integration harness sends known payloads between separate processes on
loopback. It checks each transport/address family, both process directions,
capture drops, interface rates and duplicate counting. UI and parser boundary
behavior is also covered by Rust tests. Review evidence is local and excluded
from the repository.
