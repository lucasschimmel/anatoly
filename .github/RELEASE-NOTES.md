Anatoly is a Rust CLI for bounded public PHP evidence and PHP2Shell exposure assessment.

Version 0.2.2 improves PHP2Shell evidence coverage: plain-text phpinfo diagnostics,
16 allowlisted configuration observations and clearer partial-mitigation limits.
PHP advisory fix floors and configuration behavior have regression coverage.

Includes scan, exposure, headers, watch, compare, report, policy, explain and doctor modes.
Version 0.2.1 embeds the 24-path core list: use --builtin-wordlist without a separate
file or download. Its default request cap is 32; explicit --max-requests still wins.
Version 0.2.0 adds custom headers, environment-based authentication, DNS overrides,
bounded wordlists, passive TLS/WAF evidence and live/offline CSV/SARIF exports.
Linux x86_64 and ARM64 binaries require glibc >= 2.35, OpenSSL 3 and CA certificates.
Windows x86_64 uses the Windows TLS trust store.

Download the archive for your platform and verify its hash against SHA256SUMS.
Linux users can download and inspect install.sh, then run it with a chosen --bin-dir.
For an existing Exegol installation, download and inspect the release installer:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.2.2/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.2.2 --bin-dir "$HOME/.local/bin" --force
"$HOME/.local/bin/anatoly" --version
```

Keep the same --bin-dir as your existing installation. See README.md and EXEGOL.md
in the repository for setup and usage.

Version declarations and corroboration describe observations; vendor patch state and
absence of vulnerabilities are not certified. No exploit execution is performed.
