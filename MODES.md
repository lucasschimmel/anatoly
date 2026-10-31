# Anatoly modes

All live modes reuse scan scope, TLS validation, proxy, pacing and per-target budgets. They send GET requests only. Offline modes never contact targets. Public evidence cannot certify the running PHP binary or the absence of vulnerabilities.

| Mode | Purpose | Notes |
|---|---|---|
| `scan` | Public version evidence and PHP2Shell assessment | Explicit declarations and hypotheses stay separate. |
| `exposure` | Extended public information-disclosure discovery | Enables the deep path set, with a default budget of 32 requests per target. Rejects quick/no-discover. Reports diagnostics, Composer hints, error disclosures and version proofs through the common scan engine. |
| `headers` | Response header and recognized PHP cookie audit | One response chain per input URL. Checks HSTS, CSP presence, nosniff, framing declarations, Referrer-Policy and cookie attributes. No policy-strength or security certification. |
| `watch` | Repeated scans with change events | Default: two rounds, 300 seconds between completed rounds. Shows baseline, then changes only. No overlapping rounds. Ctrl+C stops the process. |
| `compare` | Compare saved aggregate reports | Added/removed targets, declarations, evidence, coverage and advisory-snapshot changes. |
| `report` | Generate standalone HTML | Escaped data, no scripts or remote assets; existing output files refused. |
| `policy` | Evaluate a saved report against JSON rules | Explicit pass/fail/unknown, with rule-level reasons. A policy pass is not a security attestation. |
| `explain` | Explain recorded evidence | Candidates, proofs, hypotheses, gaps, operator skips and remediation. |
| `doctor` | Validate local settings without HTTP | Validates target list, scope, budgets, proxy, CA and client construction. Does not test DNS, remote certificates or connectivity. Requires target input like scan. |

```powershell
anatoly scan https://app.example/ --output before.json
anatoly exposure https://app.example/ --output disclosures.json
anatoly headers https://app.example/ --json
anatoly watch https://app.example/ --interval 300 --iterations 12
anatoly compare before.json after.json --json
anatoly report before.json --output assessment.html
anatoly explain before.json
anatoly policy before.json --rules requirements.json --json
anatoly doctor https://app.example/ --https-only --no-proxy --json
```

`watch --json` emits one aggregate object at completion containing change events and `final_report`. Its `--output` writes that same envelope; extract `final_report` for offline report commands. Interrupted watches do not write a completed aggregate. JSONL and summary-only are not supported by watch. Exit status reflects the final round using `--fail-on`. Target order remains stable. Changes are observations, not automatically regressions.

`headers` exits 0 after completed observations and 3 for transport errors (unless `--fail-on never`). Missing or weak header declarations are reported for review; this mode does not use PHP version exit semantics. Its JSON is a dedicated headers report, not an input for the offline scan-report commands. Only recognized session cookie names are inspected; values and opaque name suffixes are omitted.

`--dry-run` sends no requests. Exposure expands the scan plan; headers shows configured request caps (actual mode performs one chain per URL); watch shows one round's plan without sleeping. `doctor` always sends zero requests. See [FLAGS.md](FLAGS.md) for shared controls and [OFFLINE-MODES.md](OFFLINE-MODES.md) for formats and policy rules.

Header reference semantics: [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security), [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy). Header presence alone does not establish browser protection.

Audit controls: scan/exposure export CSV/SARIF; report also accepts --format html|csv|sarif. Live modes share custom headers, environment authentication and DNS overrides. TLS/WAF peer observations remain distinct from security verdicts. See [AUDIT-CONTROLS.md](AUDIT-CONTROLS.md).
