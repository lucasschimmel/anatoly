Anatoly is a Rust CLI for bounded public PHP evidence and PHP2Shell exposure assessment.

Includes scan, exposure, headers, watch, compare, report, policy, explain and doctor modes.
Version 0.2.0 adds custom headers, environment-based authentication, DNS overrides,
bounded wordlists, passive TLS/WAF evidence and live/offline CSV/SARIF exports.
Linux x86_64 and ARM64 binaries require glibc >= 2.35, OpenSSL 3 and CA certificates.
Windows x86_64 uses the Windows TLS trust store.

Download the archive for your platform and verify its hash against SHA256SUMS.
Linux users can download and inspect install.sh, then run it with a chosen --bin-dir.
See README.md and EXEGOL.md in the repository for setup and usage.

Version declarations and corroboration describe observations; vendor patch state and
absence of vulnerabilities are not certified. No exploit execution is performed.
