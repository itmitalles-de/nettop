#!/usr/bin/env bash
set -euo pipefail

extended=0
if (( $# == 1 )) && [[ "$1" == --extended-attribution ]]; then
    extended=1
elif (( $# != 0 )); then
    printf 'Usage: %s [--extended-attribution]\n' "$0" >&2
    exit 2
fi

if (( EUID == 0 )); then
    printf 'Run the installer as your regular user, without sudo.\n' >&2
    exit 1
fi

: "${HOME:?HOME must be set}"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="$HOME/.local/bin"
destination="$install_dir/nwtop"
receipt="$install_dir/.nwtop-install.sha256"
staged_binary=''
staged_receipt=''

cleanup() {
    if [[ -n "$staged_binary" && ( -e "$staged_binary" || -L "$staged_binary" ) ]]; then
        rm -- "$staged_binary"
    fi
    if [[ -n "$staged_receipt" && ( -e "$staged_receipt" || -L "$staged_receipt" ) ]]; then
        rm -- "$staged_receipt"
    fi
}
trap cleanup EXIT

for command in cargo install mktemp sha256sum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'Required command not found: %s\n' "$command" >&2
        exit 1
    fi
done

check_destination() {
    if [[ -e "$receipt" || -L "$receipt" ]]; then
        if [[ -L "$receipt" || ! -f "$receipt" || ! -O "$receipt" ]]; then
            printf 'Refusing unsafe install receipt: %s\n' "$receipt" >&2
            exit 1
        fi
    fi
    if [[ -e "$destination" || -L "$destination" ]]; then
        if [[ -L "$destination" || ! -f "$destination" || ! -O "$destination" || ! -f "$receipt" ]]; then
            printf 'Refusing to overwrite a file not installed by this script: %s\n' "$destination" >&2
            exit 1
        fi
        local recorded actual
        recorded="$(cat -- "$receipt")"
        read -r actual _ < <(sha256sum -- "$destination")
        if [[ ! "$recorded" =~ ^[[:xdigit:]]{64}$ || "$actual" != "$recorded" ]]; then
            printf 'Refusing to overwrite a changed or untracked executable: %s\n' "$destination" >&2
            exit 1
        fi
    fi
}

build_options=()
if (( extended )); then
    bpf_clang="${NWTOP_BPF_CLANG:-clang}"
    if ! command -v "$bpf_clang" >/dev/null 2>&1 ||
        ! "$bpf_clang" --print-targets 2>/dev/null | grep -q 'bpfel'; then
        printf 'Extended attribution requires clang with the bpfel target; install clang or set NWTOP_BPF_CLANG.\n' >&2
        exit 1
    fi
    if ! "$bpf_clang" -E -x c - >/dev/null 2>&1 <<'HEADERS'
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
HEADERS
    then
        printf 'Extended attribution requires libbpf-dev and Linux UAPI headers; install these build dependencies first.\n' >&2
        exit 1
    fi
    build_options=(--features ebpf)
fi
check_destination
cargo build --release --locked "${build_options[@]}" --manifest-path "$repo_dir/Cargo.toml" --target-dir "$repo_dir/target"
mkdir -p -- "$install_dir"
staged_binary="$(mktemp "$install_dir/.nwtop-binary.XXXXXX")"
staged_receipt="$(mktemp "$install_dir/.nwtop-receipt.XXXXXX")"
install -m 755 -- "$repo_dir/target/release/nwtop" "$staged_binary"
read -r installed_digest _ < <(sha256sum -- "$staged_binary")
printf '%s\n' "$installed_digest" > "$staged_receipt"
chmod 600 -- "$staged_receipt"

# Check again after building so a file changed during the build is preserved.
check_destination
mv -- "$staged_binary" "$destination"
staged_binary=''
mv -- "$staged_receipt" "$receipt"
staged_receipt=''
setup_option=''
if (( extended )); then setup_option=' --extended-attribution'; fi
printf 'Installed %s\nStart: %s\nOptional one-time capture setup: %s/scripts/setup-capture.sh%s\n' "$destination" "$destination" "$repo_dir" "$setup_option"
