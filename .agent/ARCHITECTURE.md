# Architecture

`main.rs` owns CLI validation, source selection, refresh timing and terminal
restoration. `ui.rs` receives snapshots and draws the nvtop-style layout; it
never derives measurements from queue lengths or substitutes demo values.
`config.rs` owns versioned user preferences, XDG path resolution and atomic
private writes. `main.rs` applies explicit CLI overrides after loading preferences;
F2 edits them live and F12 saves them. The collector never loads this configuration.
UI colors use native ANSI colors and inverse styles, inheriting the terminal theme.
`shutdown.rs` registers cooperative SIGINT/SIGTERM/SIGHUP handlers so raw mode,
the alternate screen and the cursor are restored even with long refresh periods.

Normal-user capture uses the optional root-owned, group-restricted
`/usr/local/libexec/nettop-collector`. `helper.rs` provides a versioned, bounded
stdio protocol; replies have a deadline and cancellation so a stalled helper
cannot trap the UI. `privilege.rs` drops per-thread capabilities: the capture
worker keeps none after opening pcap; the sampling thread keeps only
DAC_READ_SEARCH and SYS_PTRACE for process descriptors. Both set NO_NEW_PRIVS.
`scripts/setup-capture.sh` builds unprivileged, authenticates only for root-owned
installation, verifies the staged digest and refuses untracked replacements.
The UI itself never receives capabilities or elevated user IDs.

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
Overlapping socket incarnations involving retained matches stay unattributed.
Only local endpoints can match host sockets. Bounded SOCK_DIAG queries supply
IPv6 wildcard V6ONLY metadata; missing metadata never implies dual-stack support.

The live integration harness sends known payloads between separate processes on
loopback. It checks each transport/address family, both process directions,
capture drops, interface rates and duplicate counting. UI and parser boundary
behavior is also covered by Rust tests. Review evidence is local and excluded
from the repository.

The public project website is a dependency-free static site in `site/`, deployed
by `.github/workflows/pages.yml` from `main`. Only `site/` is uploaded to Pages;
the source repository is also public under MIT. `nettop.wutz.io` is a DNS-only Cloudflare
CNAME to `itmitalles-de.github.io`, with HTTPS enforced by Pages. Deployment checks
the public HTTPS endpoint. The site uses local fonts and explicit DEMO
captures as intentional public product assets; local QA evidence stays outside Git.
