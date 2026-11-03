# CLI Reference: Modes, Flags, Profiles & Audit Controls

All live modes reuse scan scope, TLS validation, proxy, pacing and per-target budgets. They send bounded GET requests only (except `exploit` and `connect`, which target only the loopback Docker lab — see [local-lab.md](local-lab.md)). Offline modes never contact targets. Public evidence cannot certify the running PHP binary or the absence of vulnerabilities.

## Operating Modes

| Mode | Purpose | Notes |
|---|---|---|
| `scan` | Public version evidence and PHP2Shell assessment | Explicit declarations and hypotheses stay separate. |
| `exposure` | Extended public information-disclosure discovery | Enables the deep path set, with a default budget of 32 requests per target. Rejects `quick`/`--no-discover`. Reports diagnostics, Composer hints, error disclosures and version proofs through the common scan engine. |
| `headers` | Response header and recognized PHP cookie audit | One response chain per input URL. Checks HSTS, CSP presence, nosniff, framing declarations, Referrer-Policy and cookie attributes. No policy-strength or security certification. |
| `exploit` | Prove command execution in the loopback Docker lab | Requires `http://127.0.0.1:18108/index.php`. Runs `id` and requires fresh proof output. |
| `connect` | Run an allowlisted command in the loopback Docker lab | Uses the same loopback-only target restriction. Supports `id`, `whoami`, `pwd`, `hostname`, `php -v`, `uname -a`. |
| `watch` | Repeated scans with change events | Default: two rounds, 300 seconds between completed rounds. Shows baseline, then changes only. No overlapping rounds. Ctrl+C stops the process. |
| `compare` | Compare saved aggregate reports (offline) | Added/removed targets, declarations, evidence, coverage and advisory-snapshot changes. |
| `report` | Generate standalone HTML, CSV, or SARIF (offline) | Escaped data, no scripts or remote assets; existing output files refused. |
| `policy` | Evaluate a saved report against JSON rules (offline) | Explicit `pass`/`fail`/`unknown`, with rule-level reasons. A policy pass is not a security attestation. |
| `explain` | Explain recorded evidence (offline) | Candidates, proofs, hypotheses, gaps, operator skips and remediation. |
| `doctor` | Validate local settings without HTTP | Validates target list, scope, budgets, proxy, CA and client construction. Does not test DNS, remote certificates or connectivity. |

```powershell
anatoly scan https://app.example/ --output before.json
anatoly exposure https://app.example/ --output disclosures.json
anatoly headers https://app.example/ --json
anatoly exploit -u http://127.0.0.1:18108/index.php --json
anatoly connect -u http://127.0.0.1:18108/index.php --command whoami
anatoly watch https://app.example/ --interval 300 --iterations 12
anatoly compare before.json after.json --json
anatoly report before.json --output assessment.html
anatoly explain before.json
anatoly policy before.json --rules requirements.json --json
anatoly doctor https://app.example/ --https-only --no-proxy --json
```

### Live Mode Notes

- **`exploit` / `connect`** reuse the scanner's target, transport, discovery, scope and pacing options before selecting an exact verified build profile. `--lab-dir DIR` selects the project containing `lab/` (default: current directory). `--output FILE` writes the JSON execution report to a new file and refuses to overwrite an existing file. Interactive `connect` (without `--command`) is incompatible with `--json` and `--output`. `--force` can override only a non-`potentially_affected` HTTP verdict when an exact stable affected version and verified profile are present; it never bypasses version/profile/target/command safeguards. Unsupported CSV, SARIF, JSONL and dry-run execution options are rejected before HTTP.
- **`watch --json`** emits one aggregate object at completion containing change events and `final_report`. Its `--output` writes that same envelope; extract `final_report` for offline report commands. Interrupted watches do not write a completed aggregate. JSONL and summary-only are not supported by watch. Exit status reflects the final round using `--fail-on`.
- **`headers`** exits 0 after completed observations and 3 for transport errors (unless `--fail-on never`). Missing or weak header declarations are reported for review; this mode does not use PHP version exit semantics. Only recognized session cookie names are inspected; values and opaque name suffixes are omitted.
- **`--dry-run`** sends no requests. `exposure` expands the scan plan; `headers` shows configured request caps; `watch` shows one round's plan without sleeping. `doctor` always sends zero requests. `exploit`/`connect` rejects dry-run because execution-profile selection requires scanner evidence.

---

## Offline Modes

Offline commands (`compare`, `explain`, `report`, `policy`) read an aggregate JSON report produced by `scan --output`. They send no HTTP requests. Inputs are limited to 16 MiB and 256 unique target URLs. JSONL event streams are not aggregate reports.

```powershell
anatoly compare before.json after.json --json
anatoly explain scan.json --json
anatoly report scan.json --output assessment.html
anatoly report scan.json --format csv -o scan.csv
anatoly report scan.json --format sarif -o scan.sarif
anatoly policy scan.json --json
anatoly policy scan.json --rules requirements.json --json
```

- **`compare`** returns 0 for equivalent observations and 1 for additions, removals, evidence, version, verdict, coverage, hypothesis, configuration-directive or advisory-snapshot changes. Request counts and duplicate proof order are ignored.
- **`explain`** retains candidate proofs, separates weak hypotheses, and lists coverage gaps and operator skips.
- **`report`** writes a self-contained HTML document (or CSV / SARIF 2.1.0 with `--format`) with escaped imported values and no scripts or external resources. Existing files are never overwritten.
- **`policy`** supports an optional JSON rules file (unknown keys and non-boolean values are rejected):

```json
{
  "require_https": true,
  "no_affected": true,
  "no_diagnostics": true,
  "require_version": false
}
```

Each enabled rule produces `pass`, `fail` or `unknown`. Overall exits: 0 for all passing rules, 1 for any failure, 2 for unknown or an empty rule set, and 3 for invalid input or output failures.

---

## Scan Profiles and Explicit Overrides

Use `anatoly scan --help` for the complete grouped reference.

| Flag | Behavior |
|---|---|
| `--profile quick` | 1 sample, supplied URLs only, request budget 4, 500 ms spacing |
| `--profile balanced` | Default: 3 samples, normal discovery, budget 8, 150 ms spacing |
| `--profile thorough` | 5 samples, extended discovery, budget 32, 150 ms spacing |
| `--deep` | Add extended discovery to balanced; default budget becomes 32 |
| `--samples N` | Override profile sampling, 1–5 |
| `--max-requests N` | Override profile request budget, 1–32; includes redirects |
| `--max-linked-paths N` | Retained disclosed diagnostic paths, 0–128; default 3, or 16 for thorough/deep |
| `--delay-ms N` | Override profile spacing, 0–5000 ms |

Explicit numeric flags override profile defaults. `--rate-limit` can increase spacing, never reduce it. `quick` plus `--deep` or `--diagnostic-path` is rejected before any HTTP request. `--no-discover` disables additional discovery in every profile.

---

## Scope and Method Controls

| Flag | Behavior |
|---|---|
| `--allow-host HOST` | Exact hostname allowlist, repeatable; no wildcards, URLs or ports |
| `--exclude-path /PREFIX` | Exclude a path prefix from supplied URLs, discovery and redirects; repeatable |
| `--https-only` | Reject HTTP targets before any request |
| `--max-targets N` | Maximum distinct input URLs, 1–256, checked before any request |
| `--no-linked-discovery` | Skip disclosed HTML/robots links; retain selected fixed diagnostics |
| `--no-cookie-hints` | Omit cookie hypotheses and cookie-based technology identification; retain explicit version evidence |
| `--no-hypotheses` | Omit weak signals and inferred PHP presence; retain observed technologies and explicit version evidence |
| `--no-discover` | Supplied URLs only; sampling still follows `--samples` |
| `--diagnostic-path PATH` | Replace default fixed diagnostic paths; repeatable, same origin |
| `--fingerprints FILE` | Extend built-ins with a validated UTF-8 JSON fingerprint catalog, at most 1 MiB |

Every input target is validated before the first request, so a mixed list with one denied target aborts rather than partially scanning. Disclosed diagnostic paths are prioritized ahead of fallback guesses. Deep discovery places `robots.txt`, `composer.json` and `composer.lock` ahead of guessed diagnostics.

---

## Time, Rate and Transport

| Flag | Default / behavior |
|---|---|
| `--rate-limit RPS` | Optional 1–100 requests/second per target; minimum spacing is max(delay, 1/RPS) |
| `--target-timeout SEC` | 60 s; total per-target HTTP phase, including delay, redirects and body reading; 1–3600 |
| `--connect-timeout SEC` | 5 s; connection timeout, also bounded by the request and target deadlines; 1–120 |
| `--timeout SEC` | 10 s per request including response reading; 1–120 |
| `--max-body BYTES` | 262144 bytes per body; 1024–1048576 |
| `--max-redirects N` | 5 followed hops per request chain; 0–10, within the shared request budget |
| `--no-redirects` | Equivalent to zero followed redirects; conflicts with explicit `--max-redirects` |
| `--proxy URL` | Explicit HTTP(S) proxy; URL credentials, paths and queries rejected |
| `--no-proxy` | Disable automatic environment/system proxy selection; conflicts with `--proxy` |
| `--ca-cert FILE` | Add a public PEM CA certificate to normal platform trust; no private keys, at most 1 MiB |

Redirects must remain on the exact original scheme/host/port. HTTPS certificate and hostname validation always remain enabled.

---

## Preview, Reporting and CI

| Flag | Behavior |
|---|---|
| `--dry-run` | Validate input/configuration and print a redacted plan; zero HTTP requests |
| `--summary-only` | Human summary without target cards; file exports remain complete |
| `--json` | One complete JSON report on stdout, no banner/ANSI |
| `--jsonl` | Stream a target JSON event after each scan, then one summary event; no banner/ANSI |
| `--output FILE` | Write full JSON to a new file; existing files never overwritten |
| `--csv FILE` | Export scan/exposure findings as CSV to a new file |
| `--sarif FILE` | Export scan/exposure findings as SARIF 2.1.0 to a new file |
| `--fail-on any` | Default policy: errors 3, potentially affected 1, unknown 2, otherwise 0 |
| `--fail-on affected` | Errors 3; potentially affected 1; unknown alone does not fail |
| `--fail-on error` | Only transport-error reports fail with 3 |
| `--fail-on never` | Return 0 after a completed scan, preserving all reported findings |

---

## Audit Controls (Virtual Hosts, Auth, Wordlists, TLS/WAF)

### Virtual Hosts (`--resolve`)

```sh
anatoly scan -u http://monitorsfour.htb/ --resolve monitorsfour.htb:10.129.1.20 --no-proxy
anatoly scan -u https://app.example:8443/ --resolve app.example:127.0.0.1 --no-proxy --ca-cert public-ca.pem
```

`--resolve HOST:IP` changes DNS while preserving HTTP `Host`, TLS SNI and certificate verification. `HOST` must be a DNS hostname; IP-literal URL hosts cannot be remapped. Repeat for different hosts (maximum 32); bracket IPv6 IPs. `--no-proxy` is mandatory because proxies can resolve hosts themselves.

### Headers and Authentication

```sh
anatoly scan -u https://app.example/ -H 'User-Agent: MyAudit/1.0'
anatoly scan -u https://app.example/ --header-env ANATOLY_SESSION_HEADER
anatoly scan -u https://app.example/ --basic-auth-env ANATOLY_BASIC_AUTH
```

Set `ANATOLY_SESSION_HEADER` to a complete `Cookie: ...` or `Authorization: ...` line. `ANATOLY_BASIC_AUTH` contains `user:password`. Values stay out of errors, plans and reports; configuration records only counts/presence. Custom headers are pinned to one exact scheme/host/port (limit: 32 fields / 16 KiB).

### Diagnostic Wordlists

`--builtin-wordlist` selects the embedded 24-path core list (`wordlists/anatoly-core.txt`) without reading a local file. Its default request cap is 32 unless `--max-requests` overrides it. Combine it with `--wordlist FILE` to append custom UTF-8 paths (max 64 non-comment paths / 64 KiB); both reject `quick` and `--no-discover`.

```sh
anatoly scan -u https://app.example/ --builtin-wordlist
anatoly exposure -u https://app.example/ --wordlist paths.txt --max-requests 32
```

### TLS and WAF/Edge Observations

TLS certificate subject, issuer and validity Unix timestamps come from the existing validated HTTPS connection. Cloudflare, AWS WAF, Sucuri and Akamai markers are normalized without retaining opaque identifiers. `--waf-probe` in `scan`/`exposure`/`watch` adds one benign `anatoly_probe=1` query request within the shared request budget.
