# Changelog

## 0.5.0 — 2026-11-03

- Integrate real `exploit` and `connect` execution into the Rust CLI and public `anatoly::exploit` library, with structured proofs, shared target validation, export preflight and terminal rendering.
- Reuse the existing scanner and `ScanArgs` before execution; select only the exact stable affected version and never substitute a nearby build profile.
- Embed 18 maintainer-verified official Apache bookworm amd64 profiles: PHP 8.4.10/11/19/20/25/26 and PHP 8.5.0–8.5.11, with both `carrier` and `vessel` stage-3 geometries and preserved MIT attribution.
- Verify running PHP version, image identity and exact libphp symbols before every attempt; distinguish affected versions from RCE-calibrated builds and refuse missing profiles rather than claiming compatibility.
- Add `--force` for HTTP-verdict limitations only. Unknown, conflicting, fixed, prerelease, unsupported and unprofiled versions remain refused, as do non-loopback targets and arbitrary commands.
- Restrict execution to the exact loopback endpoint `http://127.0.0.1:18108/index.php` without a separate mode flag; require fresh command output instead of treating a crash or memory leak as RCE.
- Add single-command and interactive `connect` workflows limited to `id`, `whoami`, `pwd`, `hostname`, `php -v` and `uname -a`; scan once per interactive session and require fresh proof per command.
- Add `--lab-dir` for runtime lab resolution, structured scan/calibration evidence in JSON reports and no-overwrite `--output` exports; keep the library free of terminal output.
- Package the multi-version Apache/mod_php Docker lab and documentation with release archives; verify 8.4.10, 8.4.26 and 8.5.0 end-to-end locally and test the 8.3.35 refusal with `--force`.

## 0.4.0 — 2026-11-02

- Recognize conjunctive Laravel welcome-template generations and native exception-renderer families, retaining conditional version ranges when explicit declarations are hidden and preserving conflicting declarations across renderers.
- Retain contextual Laravel/PHP declarations in native Laravel 8–11 welcome footers when version numbers are visible; redacted or copied template structure alone remains a hypothesis.
- Recognize the `laravel-session` cookie used by current Laravel 12 skeletons as well as the older underscore form; preserve unknown PHP versions and cookie-value redaction.
- Add separate, bounded `version_hypotheses` with qualitative confidence, provenance, references and limitations when complete versions are unavailable; retain alternative ranges without changing exact PHP evidence or CVE verdicts.
- Derive conditional proposals from the modern Laravel cookie, selected framework requirements, partial declarations, PHP deprecation wording, Composer constraints and component-specific WordPress asset cache hints.
- Support validated hypothesis metadata on custom header, cookie, asset and HTML rules; preserve the separate channel across JSON, terminal, HTML, explain, compare and watch, with existing suppression controls.

- Inventory valid production Composer/npm package names beyond catalog mappings, preserving canonical products and ecosystem-qualified fallback names; support npm lock formats 2/3 and format 1 nested dependencies through eight levels, skip development dependencies and retain requirements without installed versions.
- Observe Composer `ext-*` requirements separately from loaded-extension or installed-version claims.
- Identify WordPress plugins/themes from exact-origin asset paths and retain dotted numeric query versions only as `asset_version_hint` cache hints, rejecting values with non-numeric suffixes without fetching assets or adding requests.
- Retain allowlisted phpinfo component versions, including MongoDB extension and section-scoped zlib compiled/linked versions, and HTTP error-footer provider declarations with source provenance, independently of PHP release evidence.
- Bound inventory to 256 technologies and 64 observations per technology, with truncation and coverage gaps; document that discovery and inventory are not exhaustive.
- Promote newly disclosed diagnostic routes ahead of fallback guesses even when already queued; avoid repeated diagnostic requests for URLs reached by redirects while preserving deliberate application samples.
- Retain received header evidence and HTTP status when response-body reading fails, mark `body_incomplete` and report a coverage gap without analyzing partial body text.
- Resolve relative HTML references against the first eligible `base href`, enforce exact-origin checks after resolution, and exclude hidden, inert and documentary HTML examples from guarded footer/phpinfo recognition.
- Validate library sample, linked-path and HTTP limits before scanning, including rejection of body limits that cannot accommodate the overflow-detection byte.

## 0.3.0 — 2026-10-31

- Recognize Craft CMS and a broader PHP application catalog through structured HTML and HTTP declarations, selected same-origin assets, Composer packages and canonical cookie names.
- Embed a 94-product declarative fingerprint catalog spanning PHP applications, other frameworks, frontend libraries and servers; accept strictly validated custom extensions with `--fingerprints`.
- Retain framework versions, including contextual Laravel error-panel declarations, selected version headers and production lock packages, without converting them into PHP version proof.
- Observe npm production dependencies/lock packages and unknown provider declarations; infer PHP only from explicit catalog runtime associations.
- Preserve grouped technology observations, per-observation versions and provenance independently of PHP version evidence and CVE assessment.
- Report PHP presence separately as declared, inferred or unknown; hypothesis suppression retains technology observations while disabling runtime inference.
- Prioritize disclosed diagnostics and deep-scan robots/Composer metadata within existing request budgets; add `--max-linked-paths` with explicit coverage gaps on limits.
- Reuse compiled detectors across batch/watch targets and bound HTML traversal and technology-observation retention.
- Add deterministic Orion and adversarial reconnaissance regressions; document evidence limits and Exegol validation requirements.

## 0.2.2 — 2026-10-31

- Extract allowlisted configuration settings from plain-text phpinfo diagnostics as well as HTML.
- Expand PHP2Shell configuration observations to 16 settings with explicit limits on partial mitigations.
- Recheck upstream fix floors against PHP advisories and add version-matrix and configuration regression coverage.

## 0.2.1 — 2026-10-31

- Embed the 24-path core discovery list in the binary with `--builtin-wordlist`.
- Default embedded discovery to 32 requests while preserving explicit caps and ordinary scans.
- Keep custom wordlists composable and include the embedded asset in Cargo packages.

## 0.2.0 — 2026-10-31

- Custom headers and environment-based authentication pinned to one origin.
- DNS overrides preserving Host/SNI and certificate validation.
- Bounded diagnostic wordlists, passive TLS/WAF metadata and an optional benign marker request.
- Live and offline CSV/SARIF exports without changing security verdicts.
- Loopback HTTPS trust/metadata and authentication/export regression tests.

## 0.1.0 — 2026-10-31

- Public PHP version evidence and separate weak hypotheses, with explicit confidence
  and coverage limits for PHP2Shell exposure assessment.
- Scan, exposure, headers, watch, compare, report, policy, explain and doctor modes;
  version, builds and credits metadata commands.
- Bounded HTTP, scope controls, TLS validation, proxies, redacted JSON/JSONL reports
  and CI exit policies.
- Linux x86_64/ARM64 and Windows x86_64 release packaging, checksums and a Linux
  installer; Exegol setup guide.
