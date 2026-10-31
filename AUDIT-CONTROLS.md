# Audit controls (0.2.0)

## Virtual hosts

```sh
anatoly scan -u http://monitorsfour.htb/ --resolve monitorsfour.htb:10.129.1.20 --no-proxy
anatoly scan -u https://app.example:8443/ --resolve app.example:127.0.0.1 --no-proxy --ca-cert public-ca.pem
```

`--resolve HOST:IP` changes DNS while preserving HTTP Host, TLS SNI and certificate
verification. HOST must be a DNS hostname; IP-literal URL hosts cannot be remapped.
The URL supplies the port. Repeat for different hosts (maximum 32); bracket IPv6 IPs.
Duplicate mappings are rejected. `--no-proxy` is mandatory because proxies can resolve
hosts themselves. Origin restrictions remain unchanged. Use your own lab instance IP.

## Headers and authentication

```sh
anatoly scan -u https://app.example/ -H 'User-Agent: MyAudit/1.0'
anatoly scan -u https://app.example/ --header-env ANATOLY_SESSION_HEADER
anatoly scan -u https://app.example/ --basic-auth-env ANATOLY_BASIC_AUTH
```

Set `ANATOLY_SESSION_HEADER` to a complete `Cookie: ...` or `Authorization: ...` line
through your protected session setup. `ANATOLY_BASIC_AUTH` contains `user:password`.
Environment options avoid values in command arguments. Never put real authentication
values in shell history. Values stay out of errors, plans and reports; configuration
records only counts/presence. They still exist in process memory/environment.

Custom headers are pinned to one exact scheme/host/port. Multi-origin inputs are
rejected before HTTP. Same-origin diagnostics receive the headers too; use
`--no-discover` to restrict requests to supplied routes. Reserved transport headers,
including Host, framing, compression negotiation and proxy authentication, cannot be
overridden. Duplicate names are rejected. Limit: 32 fields / 16 KiB. HTTP does not encrypt
authentication. No login automation, credential guessing or session refresh is added.
Observed diagnostics may be accessible only to this authenticated request.

## Diagnostic wordlists

From 0.2.1, `--builtin-wordlist` selects the embedded 24-path core list without reading
a local file or contacting a wordlist server. Its default request cap is 32 unless
`--max-requests` overrides it. Combine it with `--wordlist` to append custom paths;
both reject the quick profile and `--no-discover`. Ordinary scan defaults are unchanged.

```sh
anatoly scan -u https://app.example/ --builtin-wordlist
```

```sh
anatoly exposure -u https://app.example/ --wordlist paths.txt --max-requests 32
```

UTF-8 wordlists append to default or explicit diagnostic paths. Maximum 64 non-comment
paths / 64 KiB; blank and `#` comment lines ignored. Queries, fragments, full URLs,
backslashes and control characters are rejected. Same-origin and exclusion rules apply.
Quick/no-discover combinations are rejected. The request cap is unchanged; large lists
can exhaust it and produce incomplete coverage.

## TLS and WAF/edge observations

TLS certificate subject, issuer and validity Unix timestamps come from the existing
validated HTTPS connection, without another handshake. HTTP has no TLS observation;
missing certificate metadata is `unavailable`. The native TLS backend does not expose
the negotiated protocol, so it remains null. This is not a protocol/cipher or revocation
audit. The peer can be a CDN/proxy rather than the PHP origin.

Cloudflare, AWS WAF, Sucuri and Akamai markers are normalized without retaining opaque
identifiers/full header values. Edge presence and challenge/action markers are separate.
Generic 403/429 alone cannot identify a WAF. Presence never proves PHP2Shell is blocked;
absence never proves there is no WAF.

`--waf-probe` in scan/exposure/watch adds one benign `anatoly_probe=1` query request.
It shares request/time/pacing budgets, can be logged or exercise application behavior,
and never sends attack payloads or attempts evasion. Failure to complete is a coverage
gap. Passive metadata collection is always enabled.

## CSV and SARIF

```sh
anatoly scan -u https://app.example/ -o scan.json --csv scan.csv --sarif scan.sarif
anatoly report scan.json --format csv -o exported.csv
anatoly report scan.json --format sarif -o exported.sarif
```

Offline conversions validate the imported report and send no requests. Live CSV/SARIF
flags apply to scan/exposure only, with no dry-run export. Output files must be new and
distinct. CSV quotes fields and neutralizes spreadsheet formula prefixes. SARIF 2.1.0
uses warnings for potentially affected declarations and diagnostics, notes for
inconclusive/error assessments; these are not confirmed RCE findings. A clean SARIF
result set is not a security attestation. Full JSON retains all proofs and hypotheses.

Compare, explain, HTML and watch retain TLS/WAF observations. Older 0.1.0 reports remain
readable with those observations absent.
