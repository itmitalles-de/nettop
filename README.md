<p align="center">
  <a href="https://nettop.wutz.io">
    <img src="site/assets/readme-banner.svg" alt="nettop — your network, in view" width="100%">
  </a>
</p>

<p align="center">
  <strong>Linux network activity. Right in your terminal.</strong><br>
  Live traffic graphs, process rates, and F2 Setup — inspired by htop and nvtop.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-81c784?style=flat-square&amp;labelColor=111827" alt="Platform: Linux">
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/Rust-1.88%2B-f4d35e?style=flat-square&amp;labelColor=111827" alt="Rust 1.88 or newer"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-81c784?style=flat-square&amp;labelColor=111827" alt="MIT license"></a>
</p>

<p align="center">
  <a href="https://nettop.wutz.io">Website</a> ·
  <a href="#install">Install</a> ·
  <a href="#keyboard">Keyboard</a> ·
  <a href="https://github.com/itmitalles-de/nettop">Source</a>
</p>

**nettop** puts interface traffic, process activity, and individual connections
in one compact view. Green for receive, yellow for send, stepped history graphs,
and your terminal's own ANSI palette. The layout works in a split terminal,
including 36 × 16 and 52 × 18.

**Start without sudo after a one-time capture setup.** The interface runs as your
regular user; a separate helper provides the access needed for process traffic.
Interface counters also work without that setup.

<p align="center">
  <img src="site/assets/nettop-demo.png" alt="nettop terminal showing receive and send graphs above a process traffic table, with F2 Setup and F12 Save in the function-key bar" width="100%">
  <br>
  <sub>Actual terminal output in explicit DEMO mode. The displayed traffic is synthetic.</sub>
</p>

| At a glance | Under your control |
| --- | --- |
| **Traffic over time** | RX/TX history, link-speed bars, bytes or bits per second |
| **Processes and connections** | Sort by traffic, receive, send, total, PID, or command; search the table |
| **A familiar terminal UI** | Native colors, inverse headers, keyboard navigation, and a function-key bar |
| **F2 Setup** | Change the interface, refresh rate, graph, colors, and table; save with F12 |

## Install

You need **Linux**, **Rust 1.88+**, and the **libpcap runtime** for process capture.
A libpcap development package is not required. The repository is currently
private; cloning requires GitHub access to it.

```bash
# Ubuntu 24.04 and newer: capture runtime and capability tools.
sudo apt install libpcap0.8t64 libcap2-bin

git clone https://github.com/itmitalles-de/nettop.git
cd nettop
./scripts/install.sh
./scripts/setup-capture.sh       # One-time administrator authentication.
~/.local/bin/nettop
```

The installer builds from source and installs the UI into `~/.local/bin` as your
regular user. Add that directory to your `PATH`, then start with:

```bash
nettop
```

Older Debian/Ubuntu versions call the runtime package `libpcap0.8`. Without
libpcap or capture setup, use `nettop --no-capture` for interface counters and
accessible socket lists. Unavailable process rates appear as `-`.

<details>
<summary><strong>Installation, updates, and permissions</strong></summary>

`scripts/install.sh` runs `cargo build --release --locked`. It only replaces an
unchanged executable previously installed by that script; unrelated files,
symlinks, and modified executables are preserved.

`scripts/setup-capture.sh` also builds as your regular user. It requests
administrator authentication through `pkexec`, or `sudo` when `pkexec` is not
installed, only for installing `/usr/local/libexec/nettop-collector`. Start both
scripts without sudo. The package installation command above is separate from
this user-local build.

Run the UI installer again to update the UI. Repeat capture setup when updating
the helper; the UI installer never replaces the installed privileged helper.

The helper is owned by root, mode `0750`, and executable only by root and your
primary group. **Members of that group can monitor system-wide network
metadata.** Its file capabilities are `CAP_NET_RAW`, `CAP_DAC_READ_SEARCH`, and
`CAP_SYS_PTRACE`. After opening the capture socket, the capture thread drops all
capabilities; the sampling thread retains only the two needed to read
`/proc/PID/fd`. Both prevent gaining new privileges. Core dumps are disabled.

The UI has no capabilities. It starts the fixed helper over private stdin/stdout
pipes: no background service, listening port, or arbitrary file/command API.
Responses are bounded and interruptible, and the helper ends with its UI.
Containers and sandboxes can prevent capability acquisition even after setup;
nettop reports this instead of inventing traffic measurements.

`--no-capture` explicitly bypasses the helper. An administrator can revoke access
by removing `/usr/local/libexec/nettop-collector` and its receipt,
`/usr/local/libexec/.nettop-collector.sha256`.

</details>

## Use

```bash
nettop --interface eth0          # Select a network interface.
nettop --interface all           # Include virtual interfaces in the aggregate.
nettop --interval 0.5 --history 90
nettop --bits                    # Display rates in bits per second.
nettop --bytes                   # Override saved bit/s units.
nettop --no-color                # Start in monochrome.
nettop --no-capture              # Interface counters and accessible sockets.
nettop --once                    # Print one measured snapshot and exit.
nettop --json                    # Print a JSON snapshot and exit.
nettop --demo                    # Clearly labeled synthetic UI preview.
```

The default refresh interval is **1 second**; `--interval` / `-d` accepts
0.1–60 seconds. History defaults to **60 seconds**; `--history` accepts 10–600.
`-i` selects an interface and `-b` starts in bits per second.

## Keyboard

| Key | Action |
| --- | --- |
| <kbd>F1</kbd> / `?` | Help |
| <kbd>F2</kbd> | Open Setup |
| <kbd>F3</kbd> / `/` | Search the table |
| <kbd>F4</kbd> / `c` | Switch between processes and connections |
| <kbd>F5</kbd> / `i` | Choose an interface with arrows and Enter |
| <kbd>F6</kbd> | Choose a sort column; `s` cycles sorting |
| <kbd>F9</kbd> / Space | Pause or resume the display |
| <kbd>F12</kbd> | Save current settings |
| Tab / Shift+Tab | Cycle active interfaces and loopback |
| `b` | Toggle bytes / bits |
| ↑ / ↓, `k` / `j` | Move through the table |
| Page Up / Page Down, Home / End | Move by a page or jump to the ends |
| Enter / Esc | Apply search / clear search or close a picker |
| `q` / <kbd>F10</kbd> / Ctrl+C | Quit; `q` closes overlays and F10 returns from Setup |

Help scrolls with ↑ / ↓ and Page Up / Page Down. The table starts directly below
the graph; routine capture details live in F1 Help. Notices, search/filter state,
and capture warnings get a status row when needed.

### Make it yours with F2

Setup has **General**, **Interface**, **Chart**, and **Processes** panels. Change
the refresh interval, units, interface, history, Steps/Braille drawing, RX/TX
colors, view, sorting, and idle-row visibility. Hide the graph to give the table
more room.

Use ↑ / ↓ to navigate, Tab or → to enter the options, and ← to return to the
categories. Enter, Space, or `+` changes a value; `-` goes backward. Changes apply
immediately. **F10 or Esc returns to monitoring. F12 saves for the next start.**
Exiting without F12 keeps changes only for the current session.

<details>
<summary><strong>Settings file and command-line overrides</strong></summary>

Settings are saved atomically with private file permissions to
`$XDG_CONFIG_HOME/nettop/config.json`, or `~/.config/nettop/config.json` when
`XDG_CONFIG_HOME` is unset, empty, or relative.

Explicit CLI options override saved preferences for that run. Pressing F12 saves
the current values, including those overrides. `--no-color` and a nonempty
`NO_COLOR` environment variable start in monochrome.

Malformed or unsupported settings produce a warning and use defaults. Saving
preserves the original file until it is fixed or moved aside. If a saved
interface no longer exists, nettop warns and selects an interface automatically.

</details>

## What the numbers mean

Interface rates come from **kernel byte counters**. Process and connection rates
come from **captured TCP/UDP IP packets**, matched to socket inodes and PIDs.
Socket queue lengths are never used as traffic estimates.

Attribution has limits. Missing capture, dropped packets, and unattributed
traffic stay visible; unavailable measurements are never replaced with demo
data. Interface totals and process totals can differ.

<details>
<summary><strong>Measurement boundaries and privacy</strong></summary>

- Interface counters include protocols and link-layer overhead that captured
  TCP/UDP IP-byte totals do not. Interface totals are the kernel's cumulative
  counters; process totals contain observed captured IP bytes.
- Aggregating interfaces can count traffic more than once, for example across a
  bridge and its member interfaces. `--interface all` includes virtual links.
- Attribution covers accessible sockets in the host network namespace. Processes
  in separate container network namespaces are not fully attributed.
- Socket ownership is sampled. Short-lived, shared, and ambiguously reused
  sockets can remain in the unattributed bucket; per-PID rates are not a complete
  accounting ledger.
- Forwarded traffic is not assigned to unrelated host listeners. Multicast and
  broadcast receiver membership is not inferred from ports. IPv6 wildcard
  sockets are matched to IPv4 only when Linux socket diagnostics confirm
  dual-stack operation.
- Packet headers are interpreted; payloads are not logged. nettop does not
  perform DNS lookups.

</details>

## Development

nettop is written in Rust. Build and run the core checks with:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
shellcheck scripts/*.sh
python3 tests/terminal.py target/release/nettop
python3 tests/setup.py target/release/nettop
```

<details>
<summary><strong>Isolated capture tests and CI coverage</strong></summary>

Run capture and helper tests in an isolated environment. These Docker commands
use a read-only repository mount and a separate network namespace with no
external connectivity:

```bash
docker build -t nettop-test tests
docker run --rm --network none -v "$PWD:/work:ro" nettop-test \
  python3 tests/live_capture.py target/release/nettop
docker run --rm --network none --cap-add DAC_READ_SEARCH --cap-add SYS_PTRACE \
  -v "$PWD:/work:ro" nettop-test python3 tests/helper.py --isolated \
  target/release/nettop target/release/nettop-collector
```

The Python integration tests use standard-library loopback sockets. Separate
sender and receiver PIDs exchange real IPv4/IPv6 TCP and UDP traffic; assertions
cover measured rates, PID attribution, packet drops, and duplicate counting
without changing network configuration. `tests/helper.py` also checks capability
separation, unprivileged cross-user attribution, installer safeguards, bounded
protocol input, and shutdown with a stopped helper.

[CI](.github/workflows/ci.yml) is configured to run formatting, linting, unit
tests on stable and Rust 1.88.0, release builds, terminal restoration, Setup and
persistence checks, and capture tests in isolated Ubuntu 24.04 containers.
Building the test image needs access to its base image and package repositories.

</details>

See [AGENTS.md](AGENTS.md) for repository-specific contributor instructions.

The [project website](https://nettop.wutz.io) is a dependency-free static site in
[`site/`](site/), published by the [Pages workflow](.github/workflows/pages.yml).
Its terminal images and recording use explicit DEMO mode with synthetic traffic.

---

[MIT licensed](LICENSE) · Inspired by htop and nvtop · No affiliation with other
projects named nettop or ntop.
