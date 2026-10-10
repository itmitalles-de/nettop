# nwtop

Follow `/home/tim/AGENTS.md` when working on the owner's machine.

This is a Linux terminal monitor in Rust, visually based on nvtop: compact device
information, a green RX / yellow TX history graph, a process or connection table,
and function-key help. Keep the compact terminal layout usable at 40x24 and 120x36.

Interface rates come from kernel counters. Process rates come from captured IP
packets correlated with socket inodes and PIDs, never from socket queue lengths.
Unavailable attribution and capture permissions must be visible; never substitute
demo values in live mode. Avoid packet payload retention and DNS lookups.

Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
`cargo test`. Test real TCP and UDP traffic in an isolated container when capture
code changes. Keep screenshots, recordings and local review data out of Git.
