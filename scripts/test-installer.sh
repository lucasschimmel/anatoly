#!/bin/sh
# Offline installer integration tests. curl and uname are replaced by fixtures.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
INSTALLER=$PROJECT_DIR/install.sh
TEST_TMP_BASE=${TMPDIR:-/tmp}
TEST_ROOT=$(mktemp -d "$TEST_TMP_BASE/anatoly-installer-tests.XXXXXX")
case "$TEST_ROOT" in "$TEST_TMP_BASE"/anatoly-installer-tests.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$TEST_ROOT"' EXIT HUP INT TERM

mkdir -p "$TEST_ROOT/mock-bin" "$TEST_ROOT/fixture" "$TEST_ROOT/payload"
cat > "$TEST_ROOT/mock-bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "${TEST_OS:-Linux}" ;;
    -m) printf '%s\n' "${TEST_ARCH:-x86_64}" ;;
    *) exit 1 ;;
esac
EOF
cat > "$TEST_ROOT/mock-bin/curl" <<'EOF'
#!/bin/sh
set -eu
url=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        https://*) url=$1; shift ;;
        -o) destination=$2; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s\n' "$url" >> "$TEST_DOWNLOAD_LOG"
case "$url" in
    https://github.com/lucasschimmel/anatoly/releases/download/v0.1.0/*) ;;
    *) exit 90 ;;
esac
name=${url##*/}
case "$name" in
    SHA256SUMS|anatoly-v0.1.0-x86_64-unknown-linux-gnu.tar.gz|anatoly-v0.1.0-aarch64-unknown-linux-gnu.tar.gz) ;;
    *) exit 91 ;;
esac
cp "$TEST_FIXTURE_DIR/$name" "$destination"
EOF
cat > "$TEST_ROOT/payload/anatoly" <<'EOF'
#!/bin/sh
[ "$#" = 1 ] && [ "$1" = --version ] || exit 92
printf 'anatoly 0.1.0\n'
EOF
chmod 755 "$TEST_ROOT/mock-bin/uname" "$TEST_ROOT/mock-bin/curl" "$TEST_ROOT/payload/anatoly"
export TEST_FIXTURE_DIR=$TEST_ROOT/fixture
export TEST_DOWNLOAD_LOG=$TEST_ROOT/downloads.log
export PATH=$TEST_ROOT/mock-bin:$PATH
ASSET=anatoly-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -czf "$TEST_FIXTURE_DIR/$ASSET" -C "$TEST_ROOT/payload" anatoly
cp "$TEST_FIXTURE_DIR/$ASSET" "$TEST_FIXTURE_DIR/anatoly-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"

reset_downloads() { : > "$TEST_DOWNLOAD_LOG"; }
valid_checksums() {
    (cd "$TEST_FIXTURE_DIR" && sha256sum --text "$ASSET" anatoly-v0.1.0-aarch64-unknown-linux-gnu.tar.gz) > "$TEST_FIXTURE_DIR/SHA256SUMS"
}
expect_failure() {
    if sh "$INSTALLER" "$@" > "$TEST_ROOT/output.log" 2>&1; then
        printf 'FAIL: installer unexpectedly succeeded\n' >&2
        exit 1
    fi
}
expect_no_downloads() {
    [ ! -s "$TEST_DOWNLOAD_LOG" ] || { printf 'FAIL: unexpected download attempt\n' >&2; exit 1; }
}
pass() { printf 'PASS: %s\n' "$1"; }

# A valid archive is verified, executed only for --version, and installed with spaces.
valid_checksums
reset_downloads
SPACED_DIR=$TEST_ROOT/'bin with spaces'
sh "$INSTALLER" --bin-dir "$SPACED_DIR" > "$TEST_ROOT/output.log" 2>&1 || {
    cat "$TEST_ROOT/output.log" >&2
    exit 1
}
[ -x "$SPACED_DIR/anatoly" ]
[ "$("$SPACED_DIR/anatoly" --version)" = 'anatoly 0.1.0' ]
[ "$(wc -l < "$TEST_DOWNLOAD_LOG" | tr -d ' ')" = 2 ]
pass 'valid checksum installs a working binary into a path containing spaces'

# Existing files are not replaced or downloaded without explicit --force.
printf 'preserve existing file\n' > "$SPACED_DIR/anatoly"
reset_downloads
expect_failure --bin-dir "$SPACED_DIR"
[ "$(cat "$SPACED_DIR/anatoly")" = 'preserve existing file' ]
expect_no_downloads
pass 'existing binary is preserved without force and without network activity'

reset_downloads
sh "$INSTALLER" --bin-dir "$SPACED_DIR" --force > "$TEST_ROOT/output.log" 2>&1
[ "$("$SPACED_DIR/anatoly" --version)" = 'anatoly 0.1.0' ]
pass 'force replaces an existing regular binary after verification'

# A bad digest must leave an existing destination untouched even when forced.
printf 'preserve on mismatch\n' > "$SPACED_DIR/anatoly"
printf '%064d  %s\n' 0 "$ASSET" > "$TEST_FIXTURE_DIR/SHA256SUMS"
expect_failure --bin-dir "$SPACED_DIR" --force
[ "$(cat "$SPACED_DIR/anatoly")" = 'preserve on mismatch' ]
grep -q 'Checksum mismatch' "$TEST_ROOT/output.log"
pass 'checksum mismatch does not alter the destination'

for checksum_case in missing malformed duplicate; do
    case "$checksum_case" in
        missing) printf 'not-a-matching-asset\n' > "$TEST_FIXTURE_DIR/SHA256SUMS" ;;
        malformed) printf 'not-a-digest  %s\n' "$ASSET" > "$TEST_FIXTURE_DIR/SHA256SUMS" ;;
        duplicate) valid_checksums; cat "$TEST_FIXTURE_DIR/SHA256SUMS" > "$TEST_ROOT/checksums-copy"; cat "$TEST_ROOT/checksums-copy" >> "$TEST_FIXTURE_DIR/SHA256SUMS" ;;
    esac
    expect_failure --bin-dir "$TEST_ROOT/$checksum_case"
    [ ! -e "$TEST_ROOT/$checksum_case/anatoly" ]
    pass "$checksum_case checksum records cannot install a binary"
done

valid_checksums
reset_downloads
TEST_ARCH=unsupported export TEST_ARCH
expect_failure --bin-dir "$TEST_ROOT/unsupported"
expect_no_downloads
unset TEST_ARCH
pass 'unsupported architecture is rejected before downloading'

reset_downloads
for invalid_version in '../bad' 'v0.1.0;echo bad' 'v0.1.0-beta' ''; do
    expect_failure --version "$invalid_version" --bin-dir "$TEST_ROOT/invalid-version"
done
expect_no_downloads
pass 'invalid version strings are rejected before downloading'

# Relative/empty paths and missing option values fail before a download attempt.
reset_downloads
expect_failure --bin-dir relative/path
expect_failure --bin-dir ''
expect_failure --version
expect_failure --bin-dir
expect_no_downloads
pass 'invalid option values are rejected before downloading'

reset_downloads
sh "$INSTALLER" --help > "$TEST_ROOT/output.log" 2>&1
grep -q 'Usage:' "$TEST_ROOT/output.log"
expect_no_downloads
pass 'help never downloads or installs anything'

# Symlinks are never followed when replacing a destination.
mkdir -p "$TEST_ROOT/symlink-bin"
printf 'unrelated file\n' > "$TEST_ROOT/unrelated"
ln -s "$TEST_ROOT/unrelated" "$TEST_ROOT/symlink-bin/anatoly"
if [ -L "$TEST_ROOT/symlink-bin/anatoly" ]; then
    reset_downloads
    expect_failure --bin-dir "$TEST_ROOT/symlink-bin" --force
    [ "$(cat "$TEST_ROOT/unrelated")" = 'unrelated file' ]
    expect_no_downloads
    pass 'forced installation refuses a symlink and preserves its target'
else
    printf 'SKIP: host shell cannot create symlinks; Linux CI must verify this case\n'
fi

reset_downloads
TEST_ARCH=aarch64 export TEST_ARCH
sh "$INSTALLER" --bin-dir "$TEST_ROOT/arm-bin" > "$TEST_ROOT/output.log" 2>&1
grep -q 'aarch64-unknown-linux-gnu' "$TEST_DOWNLOAD_LOG"
[ -x "$TEST_ROOT/arm-bin/anatoly" ]
unset TEST_ARCH
pass 'ARM64 selects the correct release asset'

printf 'Installer integration tests completed without external requests.\n'
