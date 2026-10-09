# nettop

A Linux terminal network monitor inspired by **nvtop**: compact interface
statistics, a green RX / yellow TX history graph, and a sortable process or
connection table. The layout adapts to narrow terminals, including 40 × 24.

## Install

Requirements: Linux, Rust 1.88 or newer, and the libpcap runtime library for
process traffic capture. A libpcap development package is not required.

```bash
# Ubuntu 24.04 and newer: needed for packet capture.
sudo apt install libpcap0.8t64 libcap2-bin

git clone https://github.com/itmitalles-de/nettop.git
cd nettop
./scripts/install.sh
./scripts/setup-capture.sh       # One-time administrator authentication.
~/.local/bin/nettop
```

Older Debian/Ubuntu versions call the runtime package `libpcap0.8`. Interface
statistics also work without libpcap, using `nettop --no-capture`.

The installer builds with `cargo build --release --locked` and installs into
`~/.local/bin` without sudo. It only updates an unchanged executable previously
installed by this script; it refuses to overwrite other files. Add
`~/.local/bin` to your `PATH` to launch with `nettop`.

After capture setup, start normally, including full process rates:

```bash
nettop
```

### How capture works without sudo at startup

Linux requires privileges to open a packet capture socket and read other users'
socket descriptors. The optional setup script builds as your regular user, then
uses the desktop authentication dialog (`pkexec`, or `sudo` on systems without
it) only to install `/usr/local/libexec/nettop-collector`. Repeat setup when
updating the helper. The UI installer never updates the privileged helper.

The helper is root-owned, mode `0750`, and executable only by root and your
primary group. Members of that group can monitor system-wide network metadata.
Its only file capabilities are `CAP_NET_RAW`, `CAP_DAC_READ_SEARCH`, and
`CAP_SYS_PTRACE`. The capture thread drops all capabilities after opening the
capture socket; the sampling thread retains only the two capabilities needed to
read `/proc/PID/fd`. Both lock out new privileges. Core dumps are disabled.

The terminal UI has no capabilities. It starts the fixed helper over private
stdin/stdout pipes; there is no background service, listening port, or arbitrary
file/command API. Helper responses are bounded and interruptible. The helper
ends with its UI. Running inside containers or sandboxes can prevent capability
acquisition even after setup; this is reported instead of fabricating rates.

Without setup, interface counters and accessible socket lists still work as your
regular user. `--no-capture` explicitly bypasses the helper. Unavailable process
rates are shown as unavailable. To revoke access, an administrator can remove
`/usr/local/libexec/nettop-collector` and its
`/usr/local/libexec/.nettop-collector.sha256` receipt.

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
Socket ownership is sampled: short-lived, shared, or ambiguously reused sockets
remain unattributed. Forwarded traffic is not assigned to unrelated host
listeners. Multicast/broadcast receiver membership is not inferred from ports.
Dual-stack wildcard sockets are matched to IPv4 only when Linux socket
diagnostics confirm that the socket accepts IPv4.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
shellcheck scripts/*.sh
python3 tests/terminal.py target/release/nettop

# Isolated capture tests (Docker access required):
docker build -t nettop-test tests
docker run --rm --network none -v "$PWD:/work:ro" nettop-test \
  python3 tests/live_capture.py target/release/nettop
docker run --rm --network none --cap-add DAC_READ_SEARCH --cap-add SYS_PTRACE \
  -v "$PWD:/work:ro" nettop-test python3 tests/helper.py --isolated \
  target/release/nettop target/release/nettop-collector
```

CI runs formatting, linting, unit tests on stable and the minimum Rust 1.88.0,
a release build, terminal restoration, and capture checks in isolated Ubuntu
24.04 containers. The integration script uses only Python's
standard library and loopback sockets: separate sender and receiver PIDs exchange
real IPv4/IPv6 TCP and UDP traffic. It checks positive interface/process rates,
PID attribution, packet drops, and duplicate counting without changing network
configuration. `tests/helper.py` additionally verifies capability separation,
unprivileged cross-user attribution, installer checks, bounded protocol input,
and shutdown with a stopped helper in an isolated container. Run capture and
helper checks only in an isolated test environment. See
[AGENTS.md](AGENTS.md) for repository-specific contributor instructions.

MIT licensed. The project name is not intended to imply affiliation with other
tools named nettop or ntop.
