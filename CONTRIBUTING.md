# Contributing

Use Rust 1.99.0 (pinned in `rust-toolchain.toml`). Keep changes focused and use
Conventional Commit titles. Before opening a pull request:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests must use loopback fixtures and never contact external target applications.
Preserve request bounds, normal TLS verification, evidence provenance, query/cookie
redaction and explicit uncertainty. Public HTTP evidence must never certify security.
Do not add exploit execution to the default assessment workflow.

Report bugs with the tool version, operating system, sanitized command and a minimal
local reproducer. Remove target identifiers, URL queries, session values and other
sensitive data from attachments. See SECURITY.md for vulnerability reporting.

## Releasing

1. Update `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `install.sh` default `VERSION`, and the versioned install URLs in `README.md` / `docs/exegol.md` together. Recheck dated advisory policy sources.
2. Run formatting, clippy, all loopback tests, and `bash scripts/test-installer.sh`.
3. Merge the release changes through a reviewed pull request after CI succeeds.
4. Tag that commit `vX.Y.Z` and push the tag. The release workflow builds native Linux x86_64/ARM64 and Windows x86_64 archives, then publishes all assets and `SHA256SUMS` once all jobs pass.

License: MIT.
