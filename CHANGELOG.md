# Changelog

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
