# Architecture

`main.rs` owns CLI validation, source selection, refresh timing and terminal
restoration. `ui.rs` receives snapshots and draws the nvtop-style layout; it
never derives measurements from queue lengths or substitutes demo values.
`config.rs` owns versioned user preferences, XDG path resolution and atomic
private writes. `main.rs` applies explicit CLI overrides, `NO_COLOR` and the
unavailable-interface fallback to a runtime copy only; the UI tracks fields the
user changed by key or in F2 Setup, and F12 writes the file values plus only
those fields. Unknown keys warn and are preserved on save. As root, saving into a
non-root-owned settings tree is refused. The collector never loads this configuration.
`i18n.rs` provides English and German TUI text; the `language` preference
(`auto` follows LC_ALL/LC_MESSAGES/LANG) is editable in Setup. CLI help, errors,
`--once` and `--json` stay English. Runtime sample errors become notices; a failed
helper falls back to direct unprivileged collection instead of exiting.
UI colors use native ANSI colors and inverse styles, inheriting the terminal theme.
`shutdown.rs` registers cooperative SIGINT/SIGTERM/SIGHUP handlers so raw mode,
the alternate screen and the cursor are restored even with long refresh periods.
`input.rs` reads crossterm events on a `nettop-input` thread, because crossterm's
reader retries end-of-file/EIO from a hung-up terminal forever inside
`event::poll`/`read`. The event loop waits on that channel in 100 ms steps and
also exits (code 0, like SIGHUP) when stdin reports POLLHUP/POLLERR, which covers
closed terminals that send no SIGHUP to non-session-leaders. Final restore errors
are written without `eprintln!`, which would panic on a dead stderr.

Normal-user capture uses the optional root-owned, group-restricted
`/usr/local/libexec/nettop-collector`, which clears its whole environment before
loading libpcap, because libibverbs honors driver variables via plain getenv. `helper.rs` provides a versioned, bounded
stdio protocol; replies have a deadline and cancellation so a stalled helper
cannot trap the UI. `privilege.rs` drops per-thread capabilities: the capture
worker keeps none after opening pcap; the sampling thread keeps only
DAC_READ_SEARCH and SYS_PTRACE for process descriptors, as does the
`nettop-attrib` thread it starts. All set NO_NEW_PRIVS.
`scripts/setup-capture.sh` builds unprivileged, authenticates only for root-owned
installation, copies the build into a root-only file (no final symlink), verifies
that copy's digest before granting group access and capabilities, and refuses
untracked replacements. It refuses a primary group that is not a user private
group or has other members (`--allow-shared-group`) and a silent takeover from
another group (`--reassign-group`). The authenticating administrator trusts the
user's checkout. Collector status is sent both as English `message` and as
structured `notes` (serde default, unknown codes decode as `Unknown`), which the
UI translates; older helpers without notes keep working with English text, so
the protocol version is unchanged.
The UI itself never receives capabilities or elevated user IDs.

`collector.rs` reads `/proc/net/dev`, sysfs interface metadata and getifaddrs.
Interface indexes come from `if_nametoindex`/AF_PACKET entries, never a 0
fallback; IPv4 alias labels (`eth0:1`) map to their device, so VIPs are local.
Interface rates are monotonic counter deltas divided by the measured interval.
Device removal preserves the UI and permits selection of another device.
With capture, a background `nettop-attrib` thread, started from the sampling
thread on the first snapshot (so it inherits exactly that thread's
capabilities), refreshes sockets and attributes captured flows every 250–500 ms,
independent of the UI interval; snapshots only add the final pass and divide
accumulated deltas by the interval. Each pass drains captured flows before
rereading socket tables, so tables are never older than the packets. Flows of
sockets awaiting their first owner scan or V6ONLY metadata are retried until
the next owner scan can have run (one to six seconds, derived from the
cost-dependent scan gap, at most 4096 merged flow directions). Local flows
without any candidate wait once for a table read after their drain; nonlocal
flows never wait. Per pass, host addresses, loopback links and stacked-device
relations (`master`/`upper_*` in sysfs, cached two seconds in the worker) are
precomputed as sets. Counters carry their capture link and a lower-device flag:
host traffic seen on a bridge port, bond slave or VLAN parent is skipped in
all-interface rows but shown when that link is selected. Wildcard-only matches to a
`docker-proxy` listener from non-loopback links stay unattributed, since
AF_PACKET sees published-port traffic before Docker's DNAT.

`capture.rs` owns a single dynamically loaded, non-promiscuous libpcap session
and its worker thread. It captures a bounded prefix for parsing headers, stores
only flow byte counts, and closes its own worker/handle on drop. SLL2 interface
indexes make device filtering explicit. Queue and capture drops remain visible
as per-snapshot deltas (wrapping pcap_stats counters), as do unsupported or
unreadable packets, so a past burst does not taint later snapshots.

`packet.rs` handles IP/TCP/UDP headers, link formats, VLANs, IPv6 extensions and
fragments, including zero-length IPv4 BIG TCP/GSO frames. The capture worker
keeps a bounded two-second cache of first-fragment ports so later fragments of
the same datagram are attributed. Process rates count observed IP bytes; interface totals also include
other protocols and link overhead. All-interface mode can observe the same
traffic at several virtual links and warns accordingly.

`sockets.rs` correlates flow endpoints with the current namespace's socket tables
and `/proc/PID/fd` socket inodes. Identity includes PID and start time. Descriptor
scans run promptly when unscanned inodes or exited cached owners appear, spaced
by at least 200 ms or ten times the previous scan's cost, and otherwise every
five seconds; cached owners are revalidated against `/proc/PID/stat` each second.
Closed sockets survive briefly for late packets; an owner whose descriptor
closes between the socket-table read and the descriptor scan is kept for that
scan. Flows use an exact endpoint
index; only listeners and wildcard sockets are scanned per port.
Ambiguous and shared ownership remains unattributed, except that equally
matching sockets of one process (`SO_REUSEPORT`) credit that process only. Current sockets retain
totals through idle periods; expired closed entries and all maps are bounded.
Overlapping socket incarnations involving retained matches stay unattributed,
except that a TCP listener or an inode-less closing remnant (FIN-WAIT,
TIME-WAIT, LAST-ACK) of the same endpoint pair never competes with a connection,
nor does the inode-less accept-queue entry of a connection accepted afterwards.
Status flags describe the latest refresh/scan, not the process lifetime.
Only local endpoints can match host sockets. State-filtered, per-protocol
bounded SOCK_DIAG queries supply IPv6 wildcard V6ONLY metadata, cached per socket
incarnation; missing metadata never implies dual-stack support, but an IPv4 flow
whose only candidate is such a wildcard is deferred instead of lost. The 50 ms
receive budget starts after sendto(), which can synchronously autoload diag
modules; EINTR is retried. An incomplete dump is retried on the next refresh up
to three times, a complete or rejected one that lacks a socket after two seconds.

The live integration harness sends known payloads between separate processes on
loopback. It checks each transport/address family, both process directions,
capture drops, interface rates and duplicate counting. UI and parser boundary
behavior is also covered by Rust tests. Review evidence is local and excluded
from the repository.

The public project website is a dependency-free static site in `site/`, deployed
by `.github/workflows/pages.yml` from `main`. Only `site/` is uploaded to Pages;
the source repository is also public under GPL-3.0-or-later. `nettop.wutz.io` is a DNS-only Cloudflare
CNAME to `itmitalles-de.github.io`, with HTTPS enforced by Pages. Deployment checks
the public HTTPS endpoint. The site uses local fonts and explicit DEMO
captures as intentional public product assets; local QA evidence stays outside Git.
