# Verified state

- Public, MIT-licensed repository: `itmitalles-de/nettop`, branch `main`.
- Rust 1.88+ Linux binary, runtime-loaded libpcap; no libpcap development package.
- Native ANSI htop/nvtop styling: green RX, yellow TX, stepped history graph,
  inverse green headers, cyan selection and function-key bar. F2 opens persistent
  Setup; F5 selects an interface, F6 selects sorting, F12 saves preferences.
  Layout tests cover 36x16, 40x24, 52x18, 80x24 and 120x36, including Setup.
- The device header omits the redundant app name. Table rows follow the graph
  directly; routine capture and table-summary lines are hidden. Notices, active
  filters and capture warnings can temporarily use one status row; details are in F1.
- Preferences use `$XDG_CONFIG_HOME/nettop/config.json` or
  `~/.config/nettop/config.json`, with atomic private writes. CLI options override
  saved values; malformed files stay intact. The helper never reads preferences.
- Full repository code review completed; fixed terminal signal cleanup, reused
  socket attribution, IPv4/IPv6 wildcard matching and forwarding misattribution.
- Second full review (2026-10-10) fixed: CLI overrides/NO_COLOR persisted by F12,
  runtime helper failure exiting the TUI, closed-pipe panics, unit rounding,
  `sudo -E` settings ownership, unknown config keys, fixed white text on light
  themes, collector environment (RDMA driver env), interval-dependent attribution
  (background `nettop-attrib` pass every 250–500 ms), O(N²) socket resolve,
  TIME-WAIT remnants, owner-scan latency, IPv4 alias labels, sticky drop/limit
  warnings, BIG TCP, SOCK_DIAG/fd-scan cost, fragments, docker-proxy DNAT and
  sysfs ifindex. TUI is English/German (`language` in Setup); the site has a
  system-aware light/dark theme and EN/DE, both with persisted toggles.
  `tests/short_lived.py` covers sockets closed within a 20 s interval.
- `cargo fmt --check`, Clippy with warnings denied, 67 Rust tests (also on Rust
  1.88.0), release build, ShellCheck, PTY terminal/setup checks, isolated live
  capture, helper and short-lived socket tests passed on 2026-10-10. CI now also
  runs Cargo Audit (109 dependencies, none reported locally) with job timeouts.
- All Rust tests also passed with the declared minimum Rust 1.88.0; CI covers it.
- `tests/setup.py` verifies real PTY editing/saving, restart, CLI overrides,
  unavailable saved interfaces and malformed settings. Terminal restoration
  checks pass for q, SIGTERM, SIGINT and SIGHUP. New UI/preferences changes were
  independently reviewed; unavailable rates remain visible when idle rows are hidden.
- Closed-terminal hang fix (branch `fix/tty-hangup`, 2026-10-10): a closed PTY
  master previously left nettop spinning in crossterm's EOF read loop (~60 % CPU)
  and deaf to SIGHUP. `tests/terminal.py` now checks a closed terminal without
  SIGHUP, SIGHUP after closing and a closed controlling terminal (exit 0 within
  2 s); `tests/helper.py` checks that the helper is reaped in both hang-up cases.
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
- The redesigned README shares the site's banner and explicit DEMO image.
  `site/` contains the responsive project website, terminal recording and local
  licensed fonts. Pages is configured as public with custom domain
  `nettop.wutz.io`; the source repository is also public. The Pages workflow
  deploys static files independently of Rust CI and its container dependencies.
- GitHub approved the custom-domain certificate and HTTPS enforcement is enabled.
  DNS points directly to `itmitalles-de.github.io` without Cloudflare proxying.
  Pages deployments probe the public HTTPS page after publication. The full Rust
  CI, including isolated capture/helper tests and Rust 1.88, passed for the site work.
