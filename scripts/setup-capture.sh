#!/usr/bin/env bash
# Build as the regular user; install only a fixed, reviewed helper as root.
# The administrator who authenticates trusts this checkout: the root phase
# runs this user-writable script and installs the binary the user built.
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

# Prints why members of the group other than the account could use the
# helper, and succeeds if they could or this cannot be ruled out.
group_shared() {
    local uid="$1" gid="$2" user group members member other status=0
    local -a listed=()
    user="$(id -un -- "$uid" 2>/dev/null)" || { printf 'account %s has no name\n' "$uid"; return 0; }
    if ! IFS=: read -r group _ _ members < <(getent group "$gid"); then
        printf 'group %s cannot be resolved\n' "$gid"
        return 0
    fi
    # Without a user private group (named like the account), membership in
    # directory groups such as "users" or "domain users" cannot be enumerated.
    if [[ "$group" != "$user" ]]; then
        printf 'group %s is not the private group of %s\n' "$group" "$user"
        return 0
    fi
    IFS=, read -ra listed <<< "$members"
    for member in "${listed[@]}"; do
        if [[ -n "$member" && "$member" != "$user" ]]; then
            printf 'group %s also lists %s\n' "$group" "$member"
            return 0
        fi
    done
    # Accounts with this primary group. Directory services can list very many
    # accounts: stop at the first other one, and bound the time.
    other="$(timeout 10 getent passwd | awk -F: -v gid="$gid" -v uid="$uid" '$4 == gid && $3 != uid { print $1; exit }')" || status=$?
    if [[ -n "$other" ]]; then
        printf 'account %s also has primary group %s\n' "$other" "$group"
        return 0
    fi
    if (( status != 0 )); then
        printf 'the account list could not be read completely\n'
        return 0
    fi
    return 1
}

check_group() {
    local uid="$1" gid="$2" allow_shared="$3" reassign="$4" reason current
    if [[ -e "$destination" && ! -L "$destination" ]]; then
        current="$(stat -c '%g' -- "$destination")"
        if [[ "$current" != "$gid" && "$reassign" != 1 ]]; then
            fail "The installed helper grants access to group $(getent group "$current" | cut -d: -f1 || true) ($current); installing for group $gid would revoke it. Rerun with --reassign-group to move access."
        fi
    fi
    if [[ "$allow_shared" != 1 ]] && reason="$(group_shared "$uid" "$gid")"; then
        fail "Refusing to grant capture access to a possibly shared group: $reason. Every member could monitor system-wide traffic and process names. Use a user private group, or rerun with --allow-shared-group if all members are trusted."
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
    (( EUID == 0 && $# == 7 )) || fail 'Internal installation requires root, --install and six parameters.'
    # Do not inherit tool lookup or a permissive umask from the invoking user.
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    umask 077
    binary="$2"
    owner_uid="$3"
    owner_gid="$4"
    expected_digest="$5"
    allow_shared="$6"
    reassign="$7"
    [[ "$owner_uid" =~ ^[0-9]+$ && "$owner_uid" != 0 && "$owner_gid" =~ ^[0-9]+$ && "$owner_gid" != 0 ]] || fail 'Capture access must belong to a non-root user and primary group.'
    [[ "$allow_shared" =~ ^[01]$ && "$reassign" =~ ^[01]$ ]] || fail 'Invalid installation options.'
    [[ "$(id -g -- "$owner_uid")" == "$owner_gid" ]] || fail 'Capture group must be the specified primary group.'
    # Sanity checks only: the digest of the root-owned copy is what counts.
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
    check_group "$owner_uid" "$owner_gid" "$allow_shared" "$reassign"
    staged_binary="$(mktemp /usr/local/libexec/.nettop-collector.XXXXXX)"
    staged_receipt="$(mktemp /usr/local/libexec/.nettop-collector-receipt.XXXXXX)"
    # Copy once into a root-only file without following a final symlink, then
    # verify exactly those bytes before any group may read or execute them.
    chmod 700 -- "$staged_binary"
    dd if="$binary" of="$staged_binary" iflag=nofollow conv=notrunc status=none || fail 'Cannot read the helper build.'
    read -r installed_digest _ < <(sha256sum -- "$staged_binary")
    [[ "$installed_digest" == "$expected_digest" ]] || fail 'Helper build changed during setup; rerun as your regular user.'
    printf '%s\n' "$installed_digest" > "$staged_receipt"
    # Ownership changes clear file capabilities, so set them last.
    chgrp -- "$owner_gid" "$staged_binary"
    chmod 750 -- "$staged_binary"
    setcap "$capabilities" "$staged_binary"
    setcap -v "$capabilities" "$staged_binary" >/dev/null
    check_destination
    check_group "$owner_uid" "$owner_gid" "$allow_shared" "$reassign"
    mv -T -- "$staged_binary" "$destination"
    staged_binary=''
    mv -T -- "$staged_receipt" "$receipt"
    staged_receipt=''
    printf 'Installed root-owned capture helper for primary group %s.\n' "$owner_gid"
    getcap "$destination"
    printf 'Start normally: nettop\n'
    exit 0
fi

usage="Usage: $0 [--allow-shared-group] [--reassign-group]"
allow_shared=0
reassign=0
for option in "$@"; do
    case "$option" in
        --allow-shared-group) allow_shared=1 ;;
        --reassign-group) reassign=1 ;;
        *) fail "$usage" ;;
    esac
done
(( EUID != 0 )) || fail 'Start this script as your regular user; it requests administrator authentication only for installation.'
# Fail before building and authenticating; the root phase checks again.
check_group "$(id -u)" "$(id -g)" "$allow_shared" "$reassign"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cargo build --release --locked --bin nettop-collector --manifest-path "$repo_dir/Cargo.toml" --target-dir "$repo_dir/target"
binary="$repo_dir/target/release/nettop-collector"
read -r digest _ < <(sha256sum -- "$binary")
printf 'One-time setup: install %s with capture and /proc read capabilities.\n' "$destination"
printf 'Every member of your primary group (%s) can use it. The terminal UI stays unprivileged.\n' "$(id -gn)"
printf 'Authenticating trusts this checkout: the administrator runs this script and installs your build.\n'
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec /usr/bin/bash "$repo_dir/scripts/setup-capture.sh" --install "$binary" "$(id -u)" "$(id -g)" "$digest" "$allow_shared" "$reassign"
elif command -v sudo >/dev/null 2>&1; then
    exec sudo /usr/bin/bash "$repo_dir/scripts/setup-capture.sh" --install "$binary" "$(id -u)" "$(id -g)" "$digest" "$allow_shared" "$reassign"
else
    fail 'Administrator authentication is unavailable; install pkexec or sudo to perform the one-time setup.'
fi
