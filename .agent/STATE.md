# Verified state

- New private repository: `itmitalles-de/nettop`, branch `main`.
- Rust 1.88+ Linux binary, runtime-loaded libpcap; no libpcap development package.
- Native ANSI htop/nvtop styling: green RX, yellow TX, stepped history graph,
  inverse green headers, cyan selection and function-key bar. F2 opens persistent
  Setup; F5 selects an interface, F6 selects sorting, F12 saves preferences.
  Layout tests cover 36x16, 40x24, 52x18, 80x24 and 120x36, including Setup.
- Preferences use `$XDG_CONFIG_HOME/nettop/config.json` or
  `~/.config/nettop/config.json`, with atomic private writes. CLI options override
  saved values; malformed files stay intact. The helper never reads preferences.
- Full repository code review completed; fixed terminal signal cleanup, reused
  socket attribution, IPv4/IPv6 wildcard matching and forwarding misattribution.
- `cargo fmt --check`, Clippy with warnings denied, 39 Rust tests, release build,
  ShellCheck, terminal/CLI/JSON checks and Cargo Audit (109 dependencies, no known
  vulnerabilities reported) passed on 2026-10-09.
- All Rust tests also passed with the declared minimum Rust 1.88.0; CI covers it.
- `tests/setup.py` verifies real PTY editing/saving, restart, CLI overrides,
  unavailable saved interfaces and malformed settings. Terminal restoration
  checks pass for q, SIGTERM, SIGINT and SIGHUP. New UI/preferences changes were
  independently reviewed; unavailable rates remain visible when idle rows are hidden.
- Real separate-PID TCP/UDP capture tests passed for IPv4 and IPv6 in an isolated
  Ubuntu 26.04 Docker container, including IPv4 to a dual-stack UDP listener; no
  loopback double counting. CI uses Ubuntu 24.04. See `tests/live_capture.py`.
- Normal-user capture uses the optional root-owned capability helper installed
  once by `scripts/setup-capture.sh` with administrator authentication. Daily
  launch is `nettop`; the UI has no capabilities. Helper updates need setup again.
- `tests/helper.py` verified root-owned traffic from an unprivileged UI, exact
  per-thread capability limits, installer refusal cases, protocol bounds,
  signal/timeout cleanup with a stopped helper, and EOF cleanup after UI SIGKILL.
- Owners are sampled; short-lived, shared and ambiguously reused sockets can
  remain unattributed. Separate container network namespaces are not fully covered.
- Local installation uses `scripts/install.sh`, which refuses to replace an
  unrelated executable. Only explicitly requested `--demo` uses synthetic data.
