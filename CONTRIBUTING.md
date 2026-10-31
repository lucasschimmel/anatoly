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

Release maintainers: see RELEASING.md. License: MIT.
