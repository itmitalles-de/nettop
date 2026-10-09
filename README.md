# nettop

A Linux terminal network monitor inspired by **nvtop**: compact interface
statistics, a green RX / yellow TX history graph, and a sortable process or
connection table. The layout adapts to narrow terminals, including 40 × 24.

## Install

Requirements: Linux, Rust 1.88 or newer, and the libpcap runtime library for
process traffic capture. A libpcap development package is not required.

```bash
# Ubuntu 24.04 and newer: needed for packet capture.
sudo apt install libpcap0.8t64

git clone https://github.com/itmitalles-de/nettop.git
cd nettop
./scripts/install.sh
~/.local/bin/nettop
```

Older Debian/Ubuntu versions call the runtime package `libpcap0.8`. Interface
statistics also work without libpcap, using `nettop --no-capture`.

The installer builds with `cargo build --release --locked` and installs into
`~/.local/bin` without sudo. It only updates an unchanged executable previously
installed by this script; it refuses to overwrite other files. Add
`~/.local/bin` to your `PATH` to launch with `nettop`.

For captured traffic and attribution to all accessible processes:

```bash
sudo ~/.local/bin/nettop
```

## Use

```bash
nettop --interface eth0          # Select a network interface.
nettop --interface all           # Aggregate all monitored interfaces.
nettop --no-capture              # Interface rates and sockets; no packet capture.
nettop --interval 0.5 --history 90
nettop --bits                    # Display rates in bits per second.
nettop --once                    # Print one measured snapshot and exit.
nettop --json                    # Machine-readable snapshot, then exit.
nettop --demo                    # Explicit synthetic UI preview labeled DEMO.
```

The refresh interval defaults to one second (`--interval`, or `-d`, accepts
0.1–60 seconds). Graph history defaults to 60 seconds (`--history` accepts
10–600 seconds). `-i` selects an interface and `-b` starts in bits per second.

| Key | Action |
| --- | --- |
| `F1` / `?` | Help |
| `F2` / `i` | Open the interface picker; choose with arrows and `Enter` |
| `Tab` / `Shift+Tab` | Cycle active interfaces and loopback |
| `F3` / `/` | Search the table |
| `F6` / `s` | Cycle sorting |
| `c` | Switch between processes and connections |
| `b` | Toggle bytes / bits |
| `Space` | Pause the display |
| `↑` / `↓`, `k` / `j` | Move through the table |
| `Page Up` / `Page Down`, `Home` / `End` | Move by a page or jump to the ends |
| `Enter` / `Esc` | Finish search / clear the search or close a picker |
| `q` / `F10` / `Ctrl+C` | Quit (`q` closes an open help/picker) |

The help overlay scrolls with `↑` / `↓` and `Page Up` / `Page Down`.

## What the rates mean

Interface rates are deltas of kernel RX/TX byte counters. Process and connection
rates come from captured TCP/UDP IP packets correlated with socket inodes and
PIDs. Socket queue lengths are not used as traffic estimates.

Capture and process access depend on permissions. Missing capture, dropped
packets, and unattributed traffic are visible in the interface. Unattributed
traffic stays in an unknown bucket; it is never replaced with demo values.
Packet-derived process totals can differ from interface totals because interface
counters include other protocols and link-layer overhead. Aggregating multiple
interfaces can count the same traffic more than once, for example across a
bridge and its member interfaces.

Attribution covers sockets accessible in the host network namespace. Processes
in separate container network namespaces are not fully attributed. Capture
inspects packet headers; nettop does not log payloads or perform DNS lookups.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
shellcheck scripts/install.sh

# In an isolated Linux CI runner or test container with libpcap installed:
sudo python3 tests/live_capture.py target/release/nettop
```

CI runs formatting, linting, unit tests, a release build, and privileged capture
checks on an Ubuntu 24.04 runner. The integration script uses only Python's
standard library and loopback sockets: separate sender and receiver PIDs exchange
real IPv4/IPv6 TCP and UDP traffic. It checks positive interface/process rates,
PID attribution, packet drops, and duplicate counting without changing network
configuration. Run these capture checks in an isolated test environment. See
[AGENTS.md](AGENTS.md) for repository-specific contributor instructions.

MIT licensed. The project name is not intended to imply affiliation with other
tools named nettop or ntop.
