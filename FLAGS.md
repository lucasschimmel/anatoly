# Scan flags and operating profiles

Use `anatoly scan --help` for the complete grouped reference. All profiles use
bounded GET requests and retain the existing evidence/uncertainty rules.
No flag certifies security or disables TLS verification.

## Profiles and explicit overrides

| Flag | Behavior |
|---|---|
| `--profile quick` | 1 sample, supplied URLs only, request budget 4, 500 ms spacing |
| `--profile balanced` | Default: 3 samples, normal discovery, budget 8, 150 ms spacing |
| `--profile thorough` | 5 samples, extended discovery, budget 32, 150 ms spacing |
| `--deep` | Add extended discovery to balanced; default budget becomes 32 |
| `--samples N` | Override profile sampling, 1–5 |
| `--max-requests N` | Override profile request budget, 1–32; includes redirects |
| `--delay-ms N` | Override profile spacing, 0–5000 ms |

Explicit numeric flags override profile defaults. `--rate-limit` can increase
spacing, never reduce it. Quick plus `--deep` or `--diagnostic-path` is rejected
before any HTTP request. `--no-discover` disables additional discovery in every
profile. Intentionally choosing a budget smaller than the plan is allowed and
reported as incomplete coverage.

## Scope and method control

| Flag | Behavior |
|---|---|
| `--allow-host HOST` | Exact hostname allowlist, repeatable; no wildcards, URLs or ports |
| `--exclude-path /PREFIX` | Exclude a path prefix from supplied URLs, discovery and redirects; repeatable |
| `--https-only` | Reject HTTP targets before any request |
| `--max-targets N` | Maximum distinct input URLs, 1–256, checked before any request |
| `--no-linked-discovery` | Skip disclosed HTML/robots links; retain selected fixed diagnostics |
| `--no-cookie-hints` | Omit cookie hypotheses while retaining explicit version evidence |
| `--no-hypotheses` | Omit every weak hypothesis; retain explicit version evidence |
| `--no-discover` | Supplied URLs only; sampling still follows `--samples` |
| `--diagnostic-path PATH` | Replace default fixed diagnostic paths; repeatable, same origin |

Hostnames are normalized using URL hostname normalization (including IDNs).
Bracket IPv6 literals. Path exclusions compare case-insensitive prefixes after
decoding common percent escapes, normalizing separators and dot segments.
They conservatively exclude ambiguous percent encodings left after three passes.
For example `/admin` also excludes `/administrator`. These are client request
scope controls; they cannot model arbitrary application/server rewrite rules.

Every input target is validated before the first request, so a mixed list with
one denied target aborts rather than partially scanning. Explicitly excluded
diagnostics and disabled methods are recorded as operator-selected omissions;
plan coverage refers only to the remaining selected checks. It is never a claim
that all application paths were examined.

## Time, rate and transport

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

Pacing is sequential and per target, not a global cross-target quota. It cannot
be used to exceed the request budget. Target time limits bound the HTTP phase,
not subsequent terminal rendering or output-file I/O. A deadline or redirect
limit is reflected in coverage; an observed fixed floor becomes inconclusive
when required verification cannot finish.

Redirects must still remain on the exact original scheme/host/port, even when a
host allowlist contains several entries. Proxy selection does not broaden the
logical destination scope. HTTPS certificate and hostname validation always
remain enabled. Custom-CA input extends trust for that invocation only and does
not change the OS certificate store.

## Preview, reporting and CI

| Flag | Behavior |
|---|---|
| `--dry-run` | Validate input/configuration and print a redacted plan; zero HTTP requests |
| `--summary-only` | Human summary without target cards; file exports remain complete |
| `--json` | One complete JSON report on stdout, no banner/ANSI |
| `--jsonl` | Stream a target JSON event after each scan, then one summary event; no banner/ANSI |
| `--output FILE` | Write full JSON to a new file; existing files never overwritten |
| `--fail-on any` | Default existing policy: errors 3, potentially affected 1, unknown 2, otherwise 0 |
| `--fail-on affected` | Errors 3; potentially affected 1; unknown alone does not fail |
| `--fail-on error` | Only transport-error reports fail with 3 |
| `--fail-on never` | Return 0 after a completed scan, preserving all reported findings |

CLI usage, configuration, scope and output errors still fail independently of
`--fail-on`. Changing the exit policy never changes a verdict, certification
counter or evidence. JSONL conflicts with `--json`, `--summary-only` and
`--dry-run`. Summary-only conflicts with JSON and dry-run.

Dry-run JSON has `type: scan_plan`, `network_requests_sent: 0`, redacted targets
and effective `configuration`. With `--output`, that plan is saved instead of a
scan report. No client HTTP requests are sent, including through a proxy.

JSONL events are `{"type":"target","index":1,"data":{...}}`, followed by
`{"type":"summary","data":{...},"configuration":{...}}`. A saved output file
still contains the complete aggregate JSON report. Applied scan configuration
also appears in ordinary reports as `run_configuration`. Query/fragment values
are omitted from targets and diagnostic paths; no proxy credentials, cookie
values or PEM contents are exported.

## Examples

```powershell
# Review a narrowly scoped plan before any network traffic
.\target\release\anatoly.exe scan -l apps.txt --profile thorough --https-only --allow-host app.example --exclude-path /admin --rate-limit 2 --dry-run --json

# Small supplied-URL check, with a new report file
.\target\release\anatoly.exe scan https://app.example/ --profile quick --output quick.json

# Detailed but paced assessment, minimal terminal output
.\target\release\anatoly.exe scan -l apps.txt --profile thorough --rate-limit 2 --target-timeout 90 --summary-only --output full.json

# Stream machine-readable results; fail CI on affected findings or transport errors
.\target\release\anatoly.exe scan -l apps.txt --jsonl --fail-on affected

# Inspect traffic through a local test proxy with its public CA
.\target\release\anatoly.exe scan https://app.example/ --proxy http://127.0.0.1:8080 --ca-cert lab-ca.pem
```

The shared scan options also apply to live modes; see [MODES.md](MODES.md) for mode-specific semantics and restrictions.
