#!/usr/bin/env bash
# Build as the regular user; install only a fixed, reviewed helper as root.
set -euo pipefail

destination=/usr/local/libexec/nettop-collector
receipt=/usr/local/libexec/.nettop-collector.sha256
capabilities=cap_dac_read_search,cap_net_raw,cap_sys_ptrace=ep
staged_binary=''
staged_receipt=''

fail() { printf '%s\n' "$*" >&2; exit 1; }
cleanup() {
    for staged in "$staged_binary" "$staged_receipt"; do
        if [[ -n "$staged" && ( -e "$staged" || -L "$staged" ) ]]; then
            rm -- "$staged"
        fi
    done
}
trap cleanup EXIT

safe_directory() {
    local directory="$1" owner mode
    [[ -d "$directory" && ! -L "$directory" ]] || fail "Unsafe helper directory: $directory"
    read -r owner mode < <(stat -c '%u %a' -- "$directory")
    if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
        fail "Helper directory must be root-owned and not writable by others: $directory"
    fi
}

check_destination() {
    local owner mode recorded actual
    if [[ -e "$receipt" || -L "$receipt" ]]; then
        [[ -f "$receipt" && ! -L "$receipt" ]] || fail "Unsafe helper receipt: $receipt"
        read -r owner mode < <(stat -c '%u %a' -- "$receipt")
        if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
            fail "Unsafe helper receipt permissions: $receipt"
        fi
    fi
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ -f "$destination" && ! -L "$destination" && -f "$receipt" ]] || fail "Refusing to replace an untracked helper: $destination"
        read -r owner mode < <(stat -c '%u %a' -- "$destination")
        if [[ "$owner" != 0 ]] || (( (8#$mode & 0022) != 0 )); then
            fail "Unsafe existing helper permissions: $destination"
        fi
        recorded="$(cat -- "$receipt")"
        read -r actual _ < <(sha256sum -- "$destination")
        [[ "$recorded" =~ ^[[:xdigit:]]{64}$ && "$actual" == "$recorded" ]] || fail "Refusing to overwrite a changed helper: $destination"
    fi
}

if [[ "${1:-}" == --install ]]; then
    (( EUID == 0 && $# == 5 )) || fail 'Internal installation requires root and four parameters.'
    # Do not inherit tool lookup or a permissive umask from the invoking user.
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    umask 077
    binary="$2"
    owner_uid="$3"
    owner_gid="$4"
    expected_digest="$5"
    [[ "$owner_uid" =~ ^[0-9]+$ && "$owner_uid" != 0 && "$owner_gid" =~ ^[0-9]+$ && "$owner_gid" != 0 ]] || fail 'Capture access must belong to a non-root user and primary group.'
    [[ "$(id -g -- "$owner_uid")" == "$owner_gid" ]] || fail 'Capture group must be the specified primary group.'
    [[ "$expected_digest" =~ ^[[:xdigit:]]{64}$ && -f "$binary" && ! -L "$binary" ]] || fail 'Invalid helper build or digest.'
    [[ "$(stat -c '%u' -- "$binary")" == "$owner_uid" ]] || fail 'Helper build must be owned by the requesting user.'
    command -v setcap >/dev/null || fail 'Install libcap2-bin (setcap) before capture setup.'
    command -v getcap >/dev/null || fail 'Install libcap2-bin (getcap) before capture setup.'

    for directory in / /usr /usr/local; do safe_directory "$directory"; done
    if [[ ! -e /usr/local/libexec && ! -L /usr/local/libexec ]]; then
        install -d -o 0 -g 0 -m 755 /usr/local/libexec
    fi
    safe_directory /usr/local/libexec
    check_destination
    staged_binary="$(mktemp /usr/local/libexec/.nettop-collector.XXXXXX)"
    staged_receipt="$(mktemp /usr/local/libexec/.nettop-collector-receipt.XXXXXX)"
    install -o 0 -g "$owner_gid" -m 750 -- "$binary" "$staged_binary"
    read -r installed_digest _ < <(sha256sum -- "$staged_binary")
    [[ "$installed_digest" == "$expected_digest" ]] || fail 'Helper build changed during setup; rerun as your regular user.'
    printf '%s\n' "$installed_digest" > "$staged_receipt"
    setcap "$capabilities" "$staged_binary"
    setcap -v "$capabilities" "$staged_binary" >/dev/null
    check_destination
    mv -T -- "$staged_binary" "$destination"
    staged_binary=''
    mv -T -- "$staged_receipt" "$receipt"
    staged_receipt=''
    printf 'Installed root-owned capture helper for primary group %s.\n' "$owner_gid"
    getcap "$destination"
    printf 'Start normally: nettop\n'
    exit 0
fi

(( $# == 0 )) || fail "Usage: $0"
(( EUID != 0 )) || fail 'Start this script as your regular user; it requests administrator authentication only for installation.'
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cargo build --release --locked --bin nettop-collector --manifest-path "$repo_dir/Cargo.toml" --target-dir "$repo_dir/target"
binary="$repo_dir/target/release/nettop-collector"
read -r digest _ < <(sha256sum -- "$binary")
printf 'One-time setup: install %s with capture and /proc read capabilities.\n' "$destination"
printf 'Access is restricted to your primary group (%s). The terminal UI stays unprivileged.\n' "$(id -gn)"
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec /usr/bin/bash "$repo_dir/scripts/setup-capture.sh" --install "$binary" "$(id -u)" "$(id -g)" "$digest"
elif command -v sudo >/dev/null 2>&1; then
    exec sudo /usr/bin/bash "$repo_dir/scripts/setup-capture.sh" --install "$binary" "$(id -u)" "$(id -g)" "$digest"
else
    fail 'Administrator authentication is unavailable; install pkexec or sudo to perform the one-time setup.'
fi
