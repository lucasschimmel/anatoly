# Reconnaissance: Orion findings and version 0.4.0

Version 0.3.0 implements the original reconnaissance changes described here;
version 0.4.0 extends inventory and conditional Laravel recognition below.
Releases are independent of Exegol;
these results do not establish inclusion in Exegol.

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
| Asset paths | Selected catalog path markers, same-origin by default; WordPress plugin/theme identities from exact-origin component paths | May be copied/static; no asset fetch; WordPress query values are hint-only observations; a catalog rule may explicitly permit an observed external reference |
| Canonical cookie names | Selected PHP/CMS/framework cookie-name markers | Values are discarded; session shape does not identify a PHP release |
| Composer requirements | Valid production `require` names, including `ext-*`; lock `platform` extension requirements | Requirement presence; constraints are never installed versions |
| Composer lock packages | Valid production package names and bounded package versions in `packages` | Lockfile observation, not proof of installation or the deployed web runtime |
| npm metadata | Valid production dependencies, non-development lock `packages` entries (formats 2/3) and nested `dependencies` (format 1) | Requirements do not disclose installed versions; lock data does not prove a live runtime |
| phpinfo components | Allowlisted extension/library version rows in recognized HTML or plain-text diagnostics | Validated version declarations only; no arbitrary configuration-cell retention or binary verification |
| Error footers | Catalog/unknown provider declarations in `<address>` on HTTP errors (status at least 400) | Product versions remain distinct from exact PHP evidence |
| Contextual HTML rules | Guarded selected elements, permitted attributes and version groups | Status/context requirements constrain claims; no JavaScript execution or browser rendering |

Package recognition runs only on selected Composer/npm metadata paths:
`composer.json`, `composer.lock`, `package.json` and `package-lock.json`.
Development dependencies do not identify the target application. Existing PHP
platform constraints remain separate hypotheses. Asset, framework and package
markers never create exact PHP version evidence.

The version 0.4.0 inventory extension accepts successful (2xx) metadata responses.
Catalog-mapped packages retain canonical product names; other valid production
packages use `composer:vendor/package`, `npm:package` or `npm:@scope/package`.
Composer `ext-*` requirements use `PHP extension:<name>` and never establish a
loaded extension or its installed version. `require-dev`, `devDependencies`,
`packages-dev` and npm lock entries marked `dev: true` are skipped. Requirements
retain no version, even when the declared constraint is exact; production lock
entries may retain validated versions. Format 1 npm lock traversal stops after
eight dependency levels, marks deeper entries as truncated and skips development
subtrees. Formats 2 and 3 use `packages` entries. See [Composer basic usage](https://getcomposer.org/doc/01-basic-usage.md).

WordPress paths identify `WordPress plugin:<slug>` and `WordPress theme:<slug>`
from resource URLs already present in HTML. Exact origin means matching scheme,
host and effective port; references with credentials or another origin are
excluded. A single validated `ver` or `version` query value containing a dotted
numeric version can appear in `asset_version_hint.detail` as a cache hint after
leading lowercase `v` markers are removed. Values with non-numeric suffixes
produce no hint, avoiding retention of private query content. The hint never populates a component's
`versions` or an observation's `version`, and does not prove installation or
activation. No assets are fetched and no [WordPress REST discovery](https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/)
requests are added.

Recognized [phpinfo output](https://www.php.net/manual/en/function.phpinfo.php)
can disclose allowlisted versions for Redis, Imagick, cURL, OpenSSL, libxml,
Zend OPcache, Xdebug, APCu, Memcached, MongoDB, igbinary, msgpack, Zip and zlib.
Supported labels include `MongoDB extension version` and section-scoped zlib
`Compiled Version` / `Linked Version` rows.
These `phpinfo_component` observations retain validated version tokens, not
arbitrary diagnostic values. They remain component declarations rather than
verified installed binaries or PHP release evidence. [Fingerprint catalogs](FINGERPRINTS.md#package-and-component-inventory)
documents the observation methods and bounds.

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
Rules can also retain optional `hypothesis` metadata on an observation, with a
conditional range, qualitative confidence, reason and reference.
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

The `version_hypotheses` target field keeps conditional version
proposals separate from observed product versions and exact PHP evidence. Each
proposal records `technology`, `range`, `confidence`, `basis`, `reasons`, `sources`,
`references` and `limitations`. Confidence is `low` or `medium`, qualitative and
uncalibrated. Repeats do not boost it; competing ranges remain alternatives rather
than being intersected as facts. A complete observed version suppresses guesses
for that product, and exact PHP evidence suppresses PHP proposals. These ranges
never become exact version candidates or inputs to a CVE/patch verdict.

Selected inputs include partial declarations, PHP deprecation wording, Composer
compatibility constraints and upstream framework PHP requirements. The modern
`laravel-session` cookie can propose Laravel `>=12` and conditional PHP `>=8.2`
at low confidence. The cookie is configurable; it cannot identify Laravel
12.70.2 or a PHP patch. The underscore form alone identifies no version range.
WordPress numeric asset cache hints propose only the owning plugin/theme version,
without establishing installation or activation. See
[conditional hypotheses](FINGERPRINTS.md#conditional-version-hypotheses) for the
sources, schema and limitations.

At most 64 proposals are grouped per target, retaining at most eight distinct
entries in each reasons/sources/references list. Additional proposals report a
coverage gap. JSON, terminal, HTML, explain, compare and watch retain this
separate channel without additional requests.

`--no-hypotheses` removes weak `signals`, structured version proposals and
per-observation hypothesis metadata, and disables inferred PHP presence,
while preserving observed technologies and exact PHP evidence. Cookie-name
observations are retained unless `--no-cookie-hints` is also selected; the latter
suppresses cookie-based technology identification and cookie hypotheses.

## Laravel differential validation

The isolated validation matrix uses eight actual framework versions. Masked
default welcome responses produced the following conditional view-family ranges:

| Installed Laravel | Welcome-family hypothesis |
|---|---|
| 8.83.29 and 9.52.21 | `>=8,<10` |
| 10.48.29 | `10.x` |
| 11.8.0 and 11.9.0 | `11.x` |
| 12.28.0 and 12.70.2 | `>=12,<14` |
| 13.0.0 | `13.x` |

The 8/9 pair and the early/late 12 pair intentionally remain ambiguous from those
templates. This experiment does not establish a universal classifier: customized
or retained views can disagree with the installed framework. No template pattern
supplies an exact PHP version, Laravel patch or CVE verdict. Cookie configuration
is independent evidence and does not turn a skeleton minor tag into a framework
minor bound. [Pattern definitions and primary sources](FINGERPRINTS.md#laravel-generation-patterns)
describe the conjunctions and their assumptions.

The native classic welcome footer can explicitly announce both versions as
`Laravel v8.83.29 (PHP v8.4.26)`. Recognition requires a matching welcome
conjunction and a visible `footer` or `div.text-sm` containing the full anchored
declaration. PHP then has `structured_metadata` evidence on a successful response;
this remains an unverified declaration. Masked footer values do not become exact
versions, and standalone documentation or hidden examples cannot supply them.
Multiple conflicting footer declarations remain conflicting in either DOM order.

Native and redacted error views are separate cases. On HTTP errors, the dedicated
old renderer requires its `.renderer`/Request context; the new renderer requires
the exception heading and `Exception trace` plus bounded same-parent label/value
pairs. Valid labels announce Laravel and PHP independently. Redacted labels can
retain a renderer-family hypothesis instead. Old and modern renderer declarations
on the same page are all retained, so contradictory PHP values stay contradictory
regardless of DOM order. Later redactions do not erase valid earlier labels.
Inert, hidden, article and code examples cannot supply these declarations.
Unsupported older error layouts, including a missing Ignition renderer, can
remain unknown. The source prefix, node and text limits still report gaps.

Final validation on 2026-11-02 passed **32 expected-outcome checks across eight
installed framework versions**, using four response cases per installation:

| Response case | Cases | Observed result |
|---|---|---|
| Masked welcome | 8 | Expected family ranges above; no exact PHP version |
| Full native welcome | 8 | Exact Laravel and PHP declarations for the five 8–11 installations; family only for the three 12/13 installations |
| Native error | 8 | Exact Laravel and PHP declarations for 11.9.0, 12.28.0, 12.70.2 and 13.0.0; four older installations unknown |
| Redacted error | 8 | Two old-renderer `>=11.9.0,<12.29.0` and two modern-renderer `>=12.29.0` proposals; four older installations unknown; no exact PHP version |

The older error installations lacked the development Ignition renderer. All 16
error responses reported HTML analysis gaps on large native documents
(270,998–884,159 bytes); all 16 welcome responses had no reported gaps. Passing
means those bounded outcomes matched the recorded ground truth, including unknown
results and explicit gaps. It does not establish exhaustive coverage, detection
of every customized deployment or a verified patch state.

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

Reports retain at most 256 technologies, each with at most 64 distinct
observations, including uncataloged inventory. Further markers set
`truncated: true` and a coverage gap; retained versions retain their provenance.
Reaching a disclosed-link cap sets `analysis.discovery_limited` and a gap.
Body, deadline and request limits continue to report their existing gaps.

`analysis.coverage_complete` means the selected plan completed without known
gaps. `analysis.coverage_scope` explicitly excludes exhaustive technology
recognition and route discovery. A completed 404 path check does not prove that
no diagnostics exist elsewhere, and an absent marker does not prove PHP absence.
Package, WordPress and diagnostic inventory reuse received responses without
extra requests and do not guarantee complete package, plugin or extension coverage.

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

## Robustness behavior

Disclosing a diagnostic route promotes it ahead of remaining fallback guesses,
including a route already queued as a guess. Discovery tracks URLs actually
requested, including redirect hops, and skips a queued diagnostic URL already
reached by an earlier request. Deliberate application samples remain repeat
requests within the same budget; diagnostic deduplication does not suppress them.
Redirects continue to consume the shared request budget.

When receiving headers succeeds but bounded body reading fails, the report retains
the HTTP status and selected header evidence. The response observation sets
`body_incomplete: true` and analysis records an incomplete-body coverage gap.
Partial body bytes do not enter body fingerprinting, phpinfo parsing or route
discovery. Header declarations still describe untrusted remote evidence; they
do not make an incomplete application response usable or certify its patch state.

Relative HTML links, form actions and resource references resolve against the
first eligible `base` element with an `href`. Resolution falls back to the
document URL if that value cannot produce an HTTP(S) URL. Disclosed diagnostics
and same-origin resource rules check the resolved URL against the document's
scheme, host and effective port and reject embedded credentials. An external
base therefore cannot turn a relative reference into same-origin evidence.
Catalog rules that explicitly allow external resource references retain that
exception. No referenced asset is fetched.

The bounded DOM guards exclude `hidden` and `aria-hidden="true"` subtrees,
inert markup and article examples from guarded technology attribution, error
footers and HTML phpinfo evidence. Hidden or documentary `<address>` text does
not become error-footer evidence. HTML phpinfo recognition requires a selected
heading and diagnostic context in eligible nodes; raw strings in comments,
scripts, code examples or hidden rows do not supply its version or directives.
These are structural guards, without CSS evaluation or browser rendering;
active diagnostic links inside articles remain eligible for discovery.

Library scan entry points reject samples outside 1–5 and linked-path limits
above 128. HTTP transport construction rejects zero body limits and zero
timeouts, and rejects a body limit whose extra overflow-detection byte would
overflow. A zero request budget retains the library's error-report behavior and
sends no requests. These checks do not expand discovery coverage or add active checks,
requests or dependencies. All existing scope, time, body and request limits
remain authoritative.

## Validation and Exegol readiness

Local regression fixtures cover the Orion response, marker normalization,
inert examples, contradictory PHP/application versions, suppression options,
provenance, priority, scope and resource limits. See
`tests/technology_recon.rs`, `tests/technology_channels.rs` and
`tests/discovery_recon.rs` for executable behavior. `tests/laravel_generations.rs`
covers welcome conjunctions, scoped footer and renderer labels, contradictory declarations
and suppression controls. Final test results belong in
the release validation report rather than being assumed from these fixtures.

[Source validation for Exegol](EXEGOL.md#validate-the-source-build) lists source,
real loopback HTTPS and installer checks. Native Linux x86_64/ARM64 release validation is part of the release workflow;
representative Exegol image testing and maintainer review remain
separate prerequisites for any proposal to bundle Anatoly by default.

Saved-report comparison, explanation, HTML reports and watch state also preserve
the technology/runtime distinction. See `tests/technology_offline.rs`; a CMS-only
change remains observable when hypotheses are disabled.
