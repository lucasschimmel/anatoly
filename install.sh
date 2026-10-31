#!/bin/sh
# Download an official Linux release, verify its checksum, and install one binary.
set -eu

REPOSITORY=lucasschimmel/anatoly
VERSION=v0.1.0
BIN_DIR=${HOME:?HOME must be set}/.local/bin
FORCE=0

fail() { printf 'anatoly installer: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh install.sh [--version vX.Y.Z] [--bin-dir DIRECTORY] [--force]

Default release: v0.1.0. Default directory: $HOME/.local/bin.
Supports Linux x86_64 and ARM64 with glibc >= 2.35 and OpenSSL 3.
No sudo, shell startup modifications, or scans are performed.
Existing binaries are preserved unless --force is supplied.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || fail '--version needs a value'; VERSION=$2; shift 2 ;;
        --bin-dir) [ "$#" -ge 2 ] || fail '--bin-dir needs a directory'; BIN_DIR=$2; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail 'Unknown option; use --help' ;;
    esac
done

printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail 'Use a stable version tag such as v0.1.0'
[ -n "$BIN_DIR" ] || fail 'The installation directory must not be empty'
case "$BIN_DIR" in /*) ;; *) fail '--bin-dir must be an absolute path' ;; esac
[ "$(uname -s)" = Linux ] || fail 'This installer supports Linux; see README for Windows and source builds'
case "$(uname -m)" in
    x86_64|amd64) TARGET=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-gnu ;;
    *) fail 'Unsupported CPU; build from source instead' ;;
esac
for tool in curl tar sha256sum mktemp install grep awk; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command not found: $tool"
done
DESTINATION=$BIN_DIR/anatoly
if [ -e "$DESTINATION" ] || [ -L "$DESTINATION" ]; then
    [ "$FORCE" = 1 ] || fail 'Binary already exists; use --force to replace it'
    [ ! -d "$DESTINATION" ] || fail 'Destination is a directory'
    [ ! -L "$DESTINATION" ] || fail 'Refusing to replace a symlink; choose a different directory'
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf -- "$WORK_DIR"' EXIT HUP INT TERM
ASSET=anatoly-$VERSION-$TARGET.tar.gz
BASE_URL=https://github.com/$REPOSITORY/releases/download/$VERSION
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 "$BASE_URL/$ASSET" -o "$WORK_DIR/$ASSET"
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 60 "$BASE_URL/SHA256SUMS" -o "$WORK_DIR/SHA256SUMS"
EXPECTED=$(awk -v asset="$ASSET" '$2 == asset { print $1 }' "$WORK_DIR/SHA256SUMS")
printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9a-fA-F]{64}$' || fail 'Release has no unique valid checksum for this asset'
ACTUAL=$(sha256sum "$WORK_DIR/$ASSET" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED" ] || fail 'Checksum mismatch; nothing installed'
# Extract exactly one expected member, ignoring any additional archive paths.
tar -xzf "$WORK_DIR/$ASSET" -C "$WORK_DIR" -- anatoly
if [ ! -f "$WORK_DIR/anatoly" ] || [ -L "$WORK_DIR/anatoly" ]; then
    fail 'Archive did not contain a regular binary'
fi
chmod 755 "$WORK_DIR/anatoly"
"$WORK_DIR/anatoly" --version || fail 'Binary cannot run; check glibc/OpenSSL requirements or build from source'
mkdir -p "$BIN_DIR"
install -m 755 "$WORK_DIR/anatoly" "$DESTINATION"
printf 'Installed %s to %s\n' "$VERSION" "$DESTINATION"
case ":${PATH:-}:" in
    *":$BIN_DIR:"*) ;;
    *) printf 'Add this directory to PATH: %s\n' "$BIN_DIR" ;;
esac
