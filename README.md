# ANATOLY

[![CI](https://github.com/lucasschimmel/anatoly/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasschimmel/anatoly/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lucasschimmel/anatoly)](https://github.com/lucasschimmel/anatoly/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Rust CLI for public PHP version evidence, PHP2Shell exposure assessment and
response-hardening observations. Every conclusion includes its evidence and limits.
No exploit payloads, command execution or security certification.

Commands: `scan`, `exposure`, `headers`, `watch`, `compare`, `report`, `policy`,
`explain`, `doctor`, `version`, `builds` and `credits`.

New in 0.2.0: custom headers, environment-based authentication, DNS overrides,
diagnostic wordlists, TLS/edge evidence and CSV/SARIF. See [Audit controls](AUDIT-CONTROLS.md).

## Install

### Linux / Exegol — no Rust required

Download and inspect the installer, then install a versioned release:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.2.0/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.2.0
export PATH="$HOME/.local/bin:$PATH"
anatoly --version
anatoly scan -u https://your-app.example/ -o report.json
```

Supports Linux **x86_64 and ARM64**, with glibc >= 2.35, OpenSSL 3 and CA certificates.
The installer validates archive SHA-256, preserves existing binaries unless `--force`
is provided, and never changes your shell configuration. Checksums verify download
integrity; they are not independent publisher signatures. See [Exegol setup](EXEGOL.md)
for a persistent installation under `/opt/my-resources/bin`.

### Windows

Download `anatoly-v0.2.0-x86_64-pc-windows-msvc.zip` and `SHA256SUMS` from
[Releases](https://github.com/lucasschimmel/anatoly/releases). Compare the archive's
SHA-256 with its line in SHA256SUMS, extract it, then run the executable:

```powershell
Get-FileHash .\anatoly-v0.2.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Expand-Archive .\anatoly-v0.2.0-x86_64-pc-windows-msvc.zip -DestinationPath .\anatoly
.\anatoly\anatoly.exe --version
.\anatoly\anatoly.exe scan -u https://your-app.example/
```

### From source

Install [Rust](https://rustup.rs), then:

```sh
git clone https://github.com/lucasschimmel/anatoly.git
cd anatoly
cargo install --locked --path .
```

Rust **1.99.0** is pinned in the repository. Linux builds need a C compiler,
pkg-config and OpenSSL development headers (`build-essential pkg-config libssl-dev`
on Debian/Ubuntu). Source builds may also work on macOS, which is not part of the
release test matrix. Releases cover Linux x86_64/ARM64 and Windows x86_64.

## Build and run

```powershell
cargo build --release --locked
.\target\release\anatoly.exe version
.\target\release\anatoly.exe builds
.\target\release\anatoly.exe credits
.\target\release\anatoly.exe scan https://your-app.example/index.php
```

On Linux/macOS use `./target/release/anatoly`. Native TLS uses the platform trust
store (OpenSSL development packages may be required when building on Linux).
There is no background update. `Cargo.lock` pins dependencies. The Linux installer
supports explicit version selection; see `sh install.sh --help`.

See [Scan flags and profiles](FLAGS.md) for scope restrictions, pacing, deadlines,
proxy/custom-CA settings, dry-run, JSONL and CI exit policies.

```powershell
# Equivalent single-target syntax
.\target\release\anatoly.exe scan -u https://your-app.example/

# One URL per line; blank lines and # comment lines are skipped
.\target\release\anatoly.exe scan -l targets.txt --output report.json

# Pure machine-readable stdout, without the banner or ANSI codes
.\target\release\anatoly.exe scan https://your-app.example/ --json

# Restrict probing to the URL you provide
.\target\release\anatoly.exe scan https://your-app.example/ --no-discover

# Explicit diagnostic route, relative to the supplied application directory
.\target\release\anatoly.exe scan https://your-app.example/app/ --diagnostic-path diagnostics.php

# Display the styled header even when stdout is redirected
.\target\release\anatoly.exe --color always builds

# Extended public-only discovery (default: 32 requests per target)
.\target\release\anatoly.exe scan https://your-app.example/ --deep --output detailed.json
```

## What scan does

1. GET the supplied URL with normal TLS certificate validation. The CLI samples
   three application responses by default (`--samples 1..5`) to detect version
   changes or inconsistent disclosure. All samples share the request budget.
2. Extract explicit runtime declarations from PHP/server headers, recognizable
   phpinfo diagnostics, explicit PHP runtime JSON and error-page footers.
   Keep duplicate and redirect declarations. Ordinary PHP text, cookies,
   CMS markers and Composer constraints remain separate hypotheses.
3. Compare the version with the upstream fix floors for **CVE-2026-109618** and
   **CVE-2026-109619**.
4. GET two diagnostic paths by default (`phpinfo.php`, `info.php` relative to the
   final application URL), including when initial headers meet the fix floor.
   This catches contradictions that a reassuring first response could hide.
   Follow at most three disclosed same-origin diagnostic links; `--deep` adds
   known public diagnostic/metadata paths. All requests share the same budget.
5. If a recognizable phpinfo page is exposed, collect only allowlisted evidence:
   upload progress, memory limit, upload/request limits, SAPI, and display errors.
   Report conflicting versions rather than choosing the most reassuring one.
6. Report each CVE separately with its evidence, limitations and remediation.
   Planned checks that cannot finish (request budget, failed samples, blocked
   redirects or truncated bodies) downgrade an otherwise fixed-floor result
   to inconclusive. Affected evidence remains potentially affected.
   Diagnostic 401/403/429/5xx responses are evidence gaps. A diagnostic 404/410
   completes the path-exposure check without revealing PHP configuration.

This is a defensive exposure assessment informed by the PHP2Shell research,
not a port of the exploit. There are no POST uploads, OOM triggers, memory leaks,
worker pinning, command checks, or webshells. `exploitation: not_attempted` is
explicit in the JSON. GET requests can still exercise application logic and be
logged by your server.

An unavailable diagnostic page, a normal HTTP 200, a WAF, FPM, hidden errors, or
upload progress being disabled **does not demonstrate absence of either CVE**.
Configuration observations never downgrade an affected version to protected.
Remote data can be spoofed, cached, or served by a different worker/build.
Local directive values apply to the diagnostic route, not necessarily every app.

## Verdicts and CI exit codes

The terminal groups each target into a blue result card: verdict first, then
runtime evidence, per-CVE assessment, observed configuration, recommended action
and assessment limits. Long values wrap; undisclosed settings are grouped.
JSON exports retain the complete structured report.

The final summary counts analyzed URLs, initially usable HTTP responses, PHP
versions corroborated by headers and diagnostics, potentially affected URLs,
observed fix floors, unknown results and errors. The last four outcome counts
sum to the number of analyzed URLs; evidence counters overlap them.

`certified` and `secure` remain **zero**: this scanner does not attest vendor
patch contents or prove absence of exploitation. An HTTP 200, consistent
headers or a corroborated version cannot populate these counters. Verification
of the installed web-runtime package, complete vendor patches and restarted
workers is required on the server; even that only addresses the stated CVEs.

Each JSON target also has `analysis`: successful/requested response samples,
diagnostic completion, evidence level, plan coverage, gaps, and explicit false
certification/security flags. Levels are `unknown`, `single_source`,
`consistent_samples`, `corroborated`, or `conflicting`. These describe version
evidence, never a probability that the application is secure. Repeated responses
can be cached or reach the same worker, and cannot enumerate every pool member.

For library callers, `scan()` preserves one application sample;
`scan_with_samples()` accepts an explicit count. The CLI defaults to three.
`scan_public()` additionally selects extended discovery.

The canonical detection levels are now `declared`, `corroborated`,
`contradictory`, and `unknown` in `analysis.detection_level`. The older
`version_confidence` field retains sampling detail. Each version has grouped
`version_candidates` with proof methods, normalized tokens, HTTP status and source
URLs. `signals` contains hypotheses separately. See [Public detection](PUBLIC-DETECTION.md)
for the method matrix, inference limits and primary sources.

| Verdict | Meaning | Exit |
|---|---|---|
| `potentially_affected` | Version is below a known floor, or belongs to an unsupported PHP branch | 1 |
| `fix_floor_observed` | Advertised stable version meets its branch's floor; complete patches are unverified | 0 |
| `inconclusive` | Hidden/conflicting version, prerelease, unreviewed branch, blocked redirect or unusable initial HTTP response | 2 |
| `error` | Transport failure or exhausted redirect budget preventing the initial response | 3 |

For multiple targets, exit precedence is error (3), potentially affected (1),
inconclusive (2), then floor observed (0). CLI usage errors also exit 2. File and
configuration errors exit 3. **Exit 0 is not a security certification.**

## Request boundaries

- Sequential requests: default 150 ms spacing, adjustable with `--delay-ms`.
- Eight HTTP requests per target normally, 32 with `--deep`, including redirects
  (`--max-requests`, 1–32).
- Three application samples by default (`--samples`, 1–5), not automatic retries.
- Ten seconds per request including response reading (`--timeout`, 1–120),
  five seconds to connect, and a 60-second per-target HTTP-phase budget by default.
- At most 256 KiB per response (`--max-body`, 1 KiB–1 MiB); truncation is reported.
- Redirects and diagnostic paths stay on the exact same scheme/host/port.
  HTTP-to-HTTPS redirects are blocked too: supply the canonical HTTPS URL.
- No cookie persistence or login automation. Authentication headers are opt-in and
  pinned to one exact origin. URLs with userinfo are
  rejected. Query values are omitted from reports, but are sent to the supplied URL.
- Reports include evidence only, not complete HTTP bodies or session cookies.
- At most 256 distinct targets, a target-list file of at most 1 MiB, and no retries.
- Existing output files are never overwritten. The output directory must exist.
- Applied profiles/options and operator-skipped checks are recorded in reports.
- `--json` keeps stdout clean; remote terminal control sequences are neutralized
  in human-readable output. `--no-banner`, `--color never`, and `NO_COLOR` work.

The binary is intentionally transparent: the User-Agent identifies Anatoly.
It does not bypass a CDN, WAF, authentication wall or TLS verification.

## Advisory snapshot

Reviewed **2026-10-30**, static policy (no background network requests):

| Branch | Last affected version | First fixed version |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |
| 8.5 | 8.5.11 | 8.5.12 |

PHP <= 8.1 is classified as unsupported, not universally proven exploitable.
Newer, unreviewed branches and prereleases are inconclusive. Verify the actual
vendor package revision and complete patch set, including rebuilt packages;
version strings alone do not attest which patch was compiled. `builds` shows
this policy matrix, not exploit offsets or a list of proven RCE builds.

- [PHP advisory: OOM corruption / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory: stale global state / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Both advisories require complete patching for comprehensive protection.
Restart all PHP workers after deploying updates. Check the web runtime, which
may differ from the PHP executable available in your terminal. Review vendor
advisories and update this policy snapshot as needed. Other CVEs are outside scope.

## Credits

Independent Rust implementation for Lucas Schimmel. Research acknowledgment:
Wiz Research / PHP2Shell, PHP maintainers, and the linked advisory authors.
The locally cloned `aarsaputra/php2shell`, `cumakurt/php2shell-scan`,
`KtebhTeam/php2shell`, and `testerxma/php2shell` informed behavioral comparisons.
No exploit source or screenshot artwork was copied; no upstream endorsement.

## Verification

```text
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests use loopback fixtures only; they do not scan external applications.

See [MODES.md](MODES.md) for exposure, headers, watch, compare, report, policy, explain and doctor commands.
