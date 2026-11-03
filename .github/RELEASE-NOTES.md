Anatoly 0.5.0 integrates real `exploit` and `connect` execution into the Rust CLI and public library with exact-version profile selection.

- Run the real PHP2Shell chain against an exact Apache prefork/mod_php target; select local lab versions through `local_lab.py --php-version`.
- Reuse the existing scanner and its CLI options to identify one exact stable affected version and select its verified profile. Never substitute another patch from the same branch.
- Embed 18 maintainer-verified Apache bookworm amd64 profiles covering PHP 8.4.10/11/19/20/25/26 and 8.5.0–8.5.11, with `carrier` and `vessel` geometries. Affected builds without a verified profile, including 8.3.35, are refused rather than presented as RCE-compatible.
- Verify the running version, image identity and exact libphp symbols before every attempt. Use `--force` only for HTTP-verdict limitations; it cannot bypass version or profile safeguards.
- Accept any valid absolute HTTP(S) URL through the shared scanner validation, without lab-specific host, port, path or query restrictions.
- Prove `exploit` with fresh `id` output from the container. A crash, heap leak or library leak alone is never reported as RCE.
- Use `connect` interactively or with `--command`; commands are passed verbatim to the shell without an allowlist or denylist and no persistent shell is provided.
- Select the project containing `lab/` at execution time with `--lab-dir`. JSON reports include scan evidence, force state and calibration; `--output` refuses to overwrite existing reports.

Scanning and reconnaissance do not send exploit, memory-exhaustion or command-execution payloads; only the explicit `exploit` and `connect` modes execute the chain.

## Validation

The full Rust test suite, formatting checks and Clippy pass without warnings. Real Docker verification completed scanner-driven `exploit` and `connect` flows with fresh `id`/`whoami` output on PHP 8.4.10, 8.4.26 and 8.5.0, covering both stage-3 geometries. A separate PHP 8.3.35 run confirmed that `--force` refuses an affected version without a verified RCE profile.

## Downloads

- Linux x86_64 and ARM64: glibc >= 2.35, OpenSSL 3 and CA certificates.
- Windows x86_64: native Windows TLS trust store.
- `SHA256SUMS` covers all platform archives and `install.sh`.
- Archives include the Docker lab, fingerprint catalog and documentation. The lab additionally requires Docker, Python 3.11+ and `linux/amd64` support.

Download the archive for your platform and verify its SHA-256 against `SHA256SUMS`. Checksums verify download integrity; they are not independent publisher signatures. The binary-only installer does not install the Docker lab; use a release archive or source checkout and pass its directory through `--lab-dir` when running elsewhere.

For Linux or an existing Exegol installation, download and inspect the release installer:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.5.0/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.5.0 --bin-dir "$HOME/.local/bin" --force
"$HOME/.local/bin/anatoly" --version
```

Keep the same `--bin-dir` as your existing installation. Omit `--force` for a new installation. The installer verifies the archive checksum, preserves existing binaries without `--force`, and does not change shell configuration or scan targets.

See [the local lab guide](https://github.com/lucasschimmel/anatoly/blob/v0.5.0/docs/local-lab.md) for setup, verification and teardown. [Exegol setup](https://github.com/lucasschimmel/anatoly/blob/v0.5.0/docs/exegol.md) describes persistent container installation; this independent release does not add Anatoly to Exegol's official images.

The PHP advisory policy remains dated 2026-10-31. Native CI and release jobs run formatting, Clippy and platform tests; Linux jobs also validate real loopback HTTPS and installer behavior.
