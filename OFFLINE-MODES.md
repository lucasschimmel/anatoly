# Offline modes

These commands read an aggregate JSON report produced by `scan --output`. They send no HTTP requests. Inputs are limited to 16 MiB and 256 unique target URLs. JSONL event streams are not aggregate reports. The stored summary is never used as policy evidence.

```powershell
anatoly compare before.json after.json --json
anatoly explain scan.json --json
anatoly report scan.json --output assessment.html
anatoly policy scan.json --json
anatoly policy scan.json --rules requirements.json --json
```

`compare` returns 0 for equivalent observations and 1 for additions, removals, evidence, version, verdict, coverage, hypothesis, configuration-directive or advisory-snapshot changes. Request counts and duplicate proof order are ignored. A change is not automatically a regression.

`explain` retains candidate proofs, separates weak hypotheses, and lists coverage gaps and operator skips. It never upgrades a stored finding into a security attestation.

`report` writes a self-contained HTML document with escaped imported values and no scripts or external resources. Existing files are never overwritten. `compare` can export its JSON result with `--output`; use `--json` and stdout redirection for `explain` and `policy`.

`policy` supports this optional JSON rules file (unknown keys and non-boolean values are rejected):

```json
{
  "require_https": true,
  "no_affected": true,
  "no_diagnostics": true,
  "require_version": false
}
```

These are the defaults. Each enabled rule produces `pass`, `fail` or `unknown`. Overall exits: 0 for all passing rules, 1 for any failure, 2 for unknown or an empty rule set, and 3 for invalid input or output failures. Absence of observed diagnostics remains unknown: a bounded public scan cannot prove that no diagnostic route exists. `no_affected` uses the stored advisory snapshot and advertised version; its pass does not attest actual vendor patches.

Version 0.2.0 also supports report scan.json --format csv -o scan.csv and --format sarif -o scan.sarif. These conversions remain offline and validate the imported report.
