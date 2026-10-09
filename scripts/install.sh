#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    printf 'Usage: %s\n' "$0" >&2
    exit 2
fi

if (( EUID == 0 )); then
    printf 'Run the installer as your regular user, without sudo.\n' >&2
    exit 1
fi

: "${HOME:?HOME must be set}"
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="$HOME/.local/bin"
destination="$install_dir/nettop"
receipt="$install_dir/.nettop-install.sha256"
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

check_destination
cargo build --release --locked --manifest-path "$repo_dir/Cargo.toml" --target-dir "$repo_dir/target"
mkdir -p -- "$install_dir"
staged_binary="$(mktemp "$install_dir/.nettop-binary.XXXXXX")"
staged_receipt="$(mktemp "$install_dir/.nettop-receipt.XXXXXX")"
install -m 755 -- "$repo_dir/target/release/nettop" "$staged_binary"
read -r installed_digest _ < <(sha256sum -- "$staged_binary")
printf '%s\n' "$installed_digest" > "$staged_receipt"
chmod 600 -- "$staged_receipt"

# Check again after building so a file changed during the build is preserved.
check_destination
mv -- "$staged_binary" "$destination"
staged_binary=''
mv -- "$staged_receipt" "$receipt"
staged_receipt=''
printf 'Installed %s\nStart: %s\nOptional one-time capture setup: %s/scripts/setup-capture.sh\n' "$destination" "$destination" "$repo_dir"
