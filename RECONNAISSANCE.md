# Reconnaissance: Orion findings and version 0.3.0

Version 0.3.0 implements the reconnaissance changes described here. Its release is independent of Exegol; these results do not establish inclusion in Exegol.

## What the Orion archive teaches

The supplied `Anatoly-Orion-2026-10-31.zip` contains an Anatoly 0.2.2 report,
a later curl response capture and an analysis of the apparent detection gap.
The capture declares `X-Powered-By: Craft CMS` and a visible
`Powered by CraftCMS` attribution. It does not disclose a PHP version.

Inspection of the 0.2.2 source identified several concrete limitations:

- Craft CMS was absent from the application signature expression.
- Body application recognition was restricted to generator tags; visible
  attribution was not recognized.
- Generator matching tested a raw substring rather than actual HTML attribute
  semantics, allowing unrelated attributes or inert examples to resemble markers.
- Technology clues existed only as hypotheses and were not grouped by product
  with source-specific versions.
- An unknown complete PHP version did not clearly distinguish unknown runtime
  presence from a PHP application marker.
- Disclosed diagnostic paths were capped at three without explicit cap coverage
  reporting; deep metadata and newly disclosed routes could be scheduled late.

These findings explain how the saved Craft response could be missed. The curl
capture is later than the historical scan, whose complete received headers and
body were not saved. A local deterministic replay verifies the saved input and
the corrected behavior; it cannot prove which bytes the original scanner received.
No live HTB endpoint is required by the regression tests.

The four archive SHA-256 entries were verified locally. Replaying the saved HTML
with the captured `Server` and `X-Powered-By` declarations on loopback produced
zero signals in the existing 0.2.2 binary. The 0.3.0 candidate produced Craft CMS
and nginx observations, inferred PHP presence, and an unknown PHP version with
an inconclusive CVE verdict. This comparison uses the saved response, not the
unavailable historical scan response.

## Observation channels

| Channel | Retained information | Interpretation |
|---|---|---|
| Selected HTTP headers | Canonical technology and announced version, source header and status | Remotely supplied declaration; may describe a proxy or be imitated |
| Generator metadata | Actual `meta` name/content attributes, normalized aliases and version | Application announcement, not PHP version proof |
| Visible attribution | Short `Powered by ...` text with nested markup/entities handled | Application clue; ordinary mentions and inert examples are excluded |
| Asset paths | Selected catalog path markers, same-origin by default | May be copied/static; no query-string version inference and no asset fetch; a rule may explicitly permit an observed external reference |
| Canonical cookie names | Selected PHP/CMS/framework cookie-name markers | Values are discarded; session shape does not identify a PHP release |
| Composer requirements | Exact selected application names in production `require` | Requirement presence; constraints are not installed versions |
| Composer lock packages | Exact selected names and bounded package versions in `packages` | Lockfile observation, not proof of the deployed web runtime |
| npm metadata | Selected production dependencies and non-development lock packages | Requirements do not disclose installed versions; lock data does not prove a live runtime |
| Contextual HTML rules | Guarded selected elements, permitted attributes and version groups | Status/context requirements constrain claims; no JavaScript execution or browser rendering |

Package recognition runs only on selected Composer/npm metadata paths:
`composer.json`, `composer.lock`, `package.json` and `package-lock.json`.
Development dependencies do not identify the target application. Existing PHP
platform constraints remain separate hypotheses. Asset, framework and package
markers never create exact PHP version evidence.

The initial Orion correction covered 29 PHP application families, PHP and five
server products. Version 0.3.0 supersedes that first-stage catalog with
**94 canonical products** in [`fingerprints/catalog.json`](fingerprints/catalog.json),
including non-PHP frameworks, frontend libraries and proxies. The initial PHP
families remain represented below; see [Fingerprint catalogs](FINGERPRINTS.md)
for the current schema, extension example and framework-version behavior.

| Category | Canonical names |
|---|---|
| CMS | Craft CMS, WordPress, Drupal, Joomla, TYPO3, Concrete CMS, MODX, Silverstripe, October CMS, Winter CMS, Statamic, ProcessWire |
| Framework | Laravel, Symfony, Yii, CodeIgniter, CakePHP, Laminas, Zend Framework, Nette, Slim |
| Commerce | PrestaShop, Magento, OpenCart, Shopware |
| Forum / learning / wiki | phpBB, Moodle, MediaWiki, DokuWiki |
| Runtime | PHP |
| Server | nginx, Apache, LiteSpeed, OpenLiteSpeed, Microsoft IIS |

This is a conservative built-in catalog, not an exhaustive fingerprint database.
Each channel supports its selected markers; every listed product is not
recognized through every channel. Yii is retained when explicitly observed;
recognizing Craft does not fabricate a separate Yii observation.

## Report semantics

`technologies` groups repeated observations by canonical product. Each entry has
`name`, `kind`, `runtime_hint`, `versions`, `observations` and `truncated`. Each observation has
its own optional `version`, `source`, `method`, `http_status` and `detail`.
Different announced application versions remain attached to their sources;
they are never reconciled into an arbitrary PHP release. Exact repeated
observations are deduplicated while distinct sources/methods remain available.

`runtime.status` describes PHP presence independently:

| Status | Meaning |
|---|---|
| `declared` | Explicit PHP version evidence or a selected header naming PHP |
| `inferred` | Enabled clues whose catalog definition explicitly associates the product with PHP make PHP plausible |
| `unknown` | No enabled presence evidence; this does not establish PHP absence |

All declarations remain untrusted remote observations. `runtime.sources` names
the supporting sources. PHP presence, technology versions, complete PHP version
evidence and CVE assessment have separate meanings.

Non-PHP products and unknown provider declarations do not infer PHP. Generic
provider/version observations from selected headers and actual generator metadata
remain useful without a runtime association. `--fingerprints FILE` extends the
built-ins after strict preflight validation; the custom path and contents are not
recorded in report configuration. [FINGERPRINTS.md](FINGERPRINTS.md) documents the
channels, contextual Laravel version rule and data-only schema.

For the Orion fixture, the expected result is Craft CMS observed, PHP inferred,
PHP version undisclosed, no version candidates, and an inconclusive CVE verdict.
The Nginx version and a Craft version must never populate the PHP version.
`analysis.detection_level`, `version_confidence` and the existing `php_unknown`
summary counter continue to describe complete version evidence, not technology
presence. Neither declared nor inferred presence certifies patch state.

`--no-hypotheses` removes weak `signals` and disables inferred PHP presence,
while preserving observed technologies and exact PHP evidence. Cookie-name
observations are retained unless `--no-cookie-hints` is also selected; the latter
suppresses cookie-based technology identification and cookie hypotheses.

## Discovery, limits and performance

The request budget remains shared by application samples, redirects, diagnostics
and the optional benign WAF marker. `--max-linked-paths N` accepts 0–128:
balanced defaults to three retained disclosed paths and thorough/deep to 16.
Library `ScanOptions::default()` retains three. This setting does not increase
`--max-requests`; the maximum remains 32.

Actual HTML links/form actions and plain `robots.txt` allow/disallow entries may
disclose recognized diagnostic names, including selected extensionless names and
Composer metadata. Routes are query-free, deduplicated and restricted to the
same origin and configured scope. Excluded routes do not consume the retained
link capacity. Arbitrary HTML text containing `Disallow:` is not robots input.
Ordinary navigation and asset URLs are not crawled.

Disclosed diagnostics are scheduled before fallback guesses. Deep discovery
prioritizes `robots.txt`, `composer.json` and `composer.lock`; diagnostic routes
found in subsequent responses move ahead of remaining guesses. Explicit
request/time/scope controls remain authoritative.

HTML attributes, links and attribution use a structured parser and one
depth-bounded traversal rather than repeated ancestor/descendant scans.
Inert markup, comments and documentary attribution do not announce technologies.
Literal active diagnostic links inside articles remain eligible. Before parsing,
a conservative guard retains only the prefix preceding the 1,025th opening-tag-like
token (`<` followed by an ASCII letter). It bounds parser work and marks an HTML
coverage gap. This preliminary count can also include quoted or commented
examples; it is deliberately not a complete HTML tokenizer. The subsequent
traversal stops at depth 128 and also reports an HTML gap. Attribution buffers
retain at most 256 bytes; larger text blocks are not interpreted as short attribution.

Each technology retains at most 64 distinct observations. Further markers set
`truncated: true` and a coverage gap; retained versions retain their provenance.
Reaching a disclosed-link cap sets `analysis.discovery_limited` and a gap.
Body, deadline and request limits continue to report their existing gaps.

`analysis.coverage_complete` means the selected plan completed without known
gaps. `analysis.coverage_scope` explicitly excludes exhaustive technology
recognition and route discovery. A completed 404 path check does not prove that
no diagnostics exist elsewhere, and an absent marker does not prove PHP absence.

`Scanner::new()` compiles detectors once; repeated `Scanner::scan()` calls reuse
them across batch/watch targets while creating isolated transports and budgets.
This avoids repeated detector setup. Timing results depend on the workload and
environment; no unmeasured throughput or network speedup is claimed here.

Run `cargo run --locked --example benchmark_recon` for a self-contained loopback
comparison of fresh detectors against a shared scanner. A historical Windows debug
run using the initial 35-product catalog (three alternating rounds of 16
one-request targets, zero pacing) measured
median batches of 1.998 s versus 0.160 s, approximately 12.49 times faster.
The guarded 10,000-element nesting fixture completed in 0.272 s with an explicit
HTML coverage gap. These measurements cover this machine and build; detector
setup is deliberately prominent and normal request pacing or network latency
can dominate real scans. These are not measurements of the expanded 94-product
catalog. Release builds and other machines will differ.

## Validation and Exegol readiness

Local regression fixtures cover the Orion response, marker normalization,
inert examples, contradictory PHP/application versions, suppression options,
provenance, priority, scope and resource limits. See
`tests/technology_recon.rs`, `tests/technology_channels.rs` and
`tests/discovery_recon.rs` for executable behavior; final test results belong in
the release validation report rather than being assumed from these fixtures.

[Source validation for Exegol](EXEGOL.md#validate-the-source-build) lists source,
real loopback HTTPS and installer checks. Native Linux x86_64/ARM64 release validation is part of the release workflow;
representative Exegol image testing and maintainer review remain
separate prerequisites for any proposal to bundle Anatoly by default.

Saved-report comparison, explanation, HTML reports and watch state also preserve
the technology/runtime distinction. See `tests/technology_offline.rs`; a CMS-only
change remains observable when hypotheses are disabled.
