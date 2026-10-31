Anatoly 0.3.0 expands public technology reconnaissance while keeping framework versions, PHP runtime evidence and PHP2Shell assessment separate.

- Embedded, declarative catalog of **94 products**, including Laravel, Symfony, Craft CMS, WordPress, Django, Express, Next.js and frontend libraries.
- Add local signatures with `--fingerprints catalog.json`: selected headers, cookie names, asset paths and contextual HTML rules, with validated version captures.
- Observe Laravel versions through explicit declarations, production Composer lock packages and contextual error panels. Recognize unknown provider declarations without inventing runtime relationships.
- Preserve grouped technology observations and per-source versions in terminal, JSON, HTML, comparison, explanation and watch output. PHP presence is reported independently of its exact version.
- Prioritize disclosed diagnostic routes and deep-scan robots/Composer metadata within existing request budgets. Configure disclosed-route retention with `--max-linked-paths`.
- Reuse compiled detectors and catalog data; bound parsing, matching and observation retention with explicit coverage gaps.
- Add Orion, generic fingerprint and adversarial regressions: the local suite contains **189 passing tests**. Native release jobs also run formatting, Clippy and platform tests; Linux jobs verify real loopback HTTPS and installer behavior.

Framework declarations and dependency versions do not establish the installed PHP version or vendor patch state. Missing versions remain unknown. No exploit execution or security certification is performed.

## Downloads

- Linux x86_64 and ARM64: glibc >= 2.35, OpenSSL 3 and CA certificates.
- Windows x86_64: native Windows TLS trust store.
- `SHA256SUMS` covers all platform archives and `install.sh`.
- Platform archives include the fingerprint catalog, its authoring guide and reconnaissance documentation.

Download the archive for your platform and verify its SHA-256 against `SHA256SUMS`.

For Linux or an existing Exegol installation, download and inspect the release installer:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.3.0/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.3.0 --bin-dir "$HOME/.local/bin" --force
"$HOME/.local/bin/anatoly" --version
```

Keep the same `--bin-dir` as your existing installation. Omit `--force` for a new installation. The installer verifies the archive checksum, preserves existing binaries without `--force`, and does not change shell configuration or scan targets.

See [FINGERPRINTS.md](https://github.com/lucasschimmel/anatoly/blob/v0.3.0/FINGERPRINTS.md) for custom catalogs and [EXEGOL.md](https://github.com/lucasschimmel/anatoly/blob/v0.3.0/EXEGOL.md) for persistent container installation. Anatoly is an independent tool; this release does not add it to Exegol's official images.

The PHP advisory policy remains dated 2026-10-31. This release does not introduce new vulnerability verdicts from framework or frontend-library fingerprints.
