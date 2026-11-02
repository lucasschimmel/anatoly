# Extensible technology fingerprints

Since version 0.3.0, Anatoly embeds a declarative catalog in
[`fingerprints/catalog.json`](fingerprints/catalog.json). Its **94 products** cover
PHP applications, other server frameworks, frontend libraries, web servers and
proxies. Canonical aliases, selected headers, cookie names, asset paths, HTML
markers and package names share one catalog. Every product is not necessarily
detectable through every channel, and no channel guarantees a version.

This is Anatoly's own versioned schema. It does not import Wappalyzer-format
databases, execute JavaScript, fetch referenced scripts or crawl arbitrary pages.
Recognizing a framework does not establish security or the server's PHP version.

## Framework versions, including Laravel

A Laravel version can be observed in an explicit `X-Laravel-Version` header,
a declaration such as `X-Powered-By: Laravel/v13.1.0`, or the production
`laravel/framework` entry in an exposed Composer lockfile. A versioned Laravel
error panel can also match on HTTP errors. Dedicated bounded renderer recognition
requires the old `.renderer`/Request context, or the modern exception heading and
`Exception trace` context with adjacent `LARAVEL`/version and `PHP`/version spans
under their respective same parents. An ordinary article, successful response,
standalone number or distant label does not provide that renderer evidence.

The old [combined header](https://github.com/laravel/framework/blob/v11.9.0/src/Illuminate/Foundation/resources/exceptions/renderer/components/header.blade.php)
and new [adjacent-label header](https://github.com/laravel/framework/blob/v12.29.0/src/Illuminate/Foundation/resources/exceptions/renderer/components/header.blade.php)
announce framework and PHP versions separately. A validated PHP value from that
dedicated context produces `error_disclosure` evidence; Laravel versions never
become PHP versions. Generic contextual HTML rules use PHP text only as context.
Every matching header is retained, including contradictory values across old and
new renderers on one page. A later redacted value does not erase an earlier one.
These remain untrusted remote declarations, not binary or patch attestations.

A recognized default welcome conjunction also permits its visible `footer` or
`div.text-sm` to announce the fully matching `Laravel v<version> (PHP v<version>)`
footer. Both values must be full versions. Its observation method is
`laravel_welcome_footer`; PHP enters `structured_metadata` evidence even on HTTP
200. Standalone, documentary, hidden or arbitrary body text cannot supply this
declaration. Masked footer values leave the welcome-family hypothesis intact.
Every matching footer is retained, so contradictory declarations stay conflicting.

`technologies[].versions` and per-observation `version` hold the selected product's
announced/package versions. They never populate the exact PHP `version` merely
because the product uses PHP. Requirements in `composer.json` or `package.json`
identify dependencies without turning constraints into installed versions.
Exposed Composer production lock packages and non-development `package-lock.json`
`packages` entries (lockfile formats 2 and 3), or format 1 `dependencies` trees,
may retain versions; they do not prove what the web runtime executes.

Unknown providers in selected header or actual generator declarations can still
be reported by their supplied name and bounded version, without an implicit
runtime association. An unknown `Acme Server/2.3.4` declaration does not infer PHP.

## Conditional version hypotheses

When a technology has no complete observed version, each target report can retain
`version_hypotheses` separately from exact PHP evidence and product `versions`.
Each proposal contains `technology`, `range`, `confidence`, `basis`, `reasons`,
`sources`, `references` and `limitations`. Confidence is `low` or `medium`:
qualitative, uncalibrated labels rather than probabilities. Repeated responses
do not increase confidence. Distinct ranges remain alternatives; Anatoly does
not intersect them into a supposedly established version.

These proposals never populate exact PHP `version`, `version_candidates` or
product `versions`, and never determine a CVE or patch verdict. Complete PHP
evidence suppresses PHP proposals; a complete observed product version suppresses
that product's pattern guesses. A framework version can still support a
conditional PHP compatibility proposal when the PHP release is unknown.
Resolved Composer/npm lock tags count as complete artifact declarations even
when written as `2.0`; Anatoly does not expand them into a guessed `2.0.x`.

| Input | Proposal | Limits |
|---|---|---|
| Exact `laravel-session` cookie name | Laravel `>=12`, `low`, `pattern`; conditional PHP `>=8.2`, `low`, `framework_requirement` | Modern skeleton convention, configurable and imitable; no exact Laravel or PHP release |
| `laravel_session` cookie alone | No version proposal | Still identifies Laravel; the older spelling does not constrain its release |
| Partial major/minor declaration, such as PHP/8.4 | `8.4.x`, `medium`, `partial_declaration` or `partial_version` | Patch unknown; remote declaration remains unverified |
| Selected PHP deprecation wording | `>=8.2,<9` for dynamic properties or `>=8.1` for null-to-non-nullable parameters; `low`, `error_behavior` | Conditional on a real runtime diagnostic; copied text can imitate it |
| Selected Composer PHP platform constraints | Validated constraint, `low`, `composer_constraint` | Dependency/build compatibility, not the actual web runtime |
| Selected Laravel/Symfony version declarations | Upstream minimum PHP requirement, `low`, `framework_requirement` | Conditional on the declared framework matching deployment |
| Numeric WordPress component asset query hint | `=<numeric version>`, `low`, `asset_query` | Applies only to the named plugin/theme, not WordPress core or PHP; cache hint only |

The Laravel cookie proposal follows the [12.x skeleton's session naming](https://github.com/laravel/laravel/blob/12.x/config/session.php).
Its PHP compatibility proposal uses the [Laravel 12 framework requirement](https://github.com/laravel/framework/blob/v12.70.2/composer.json).
The version in that reference identifies the source document; a cookie does not
reveal Laravel 12.70.2. PHP pattern references include the
[dynamic-property deprecation RFC](https://wiki.php.net/rfc/deprecate_dynamic_properties)
and [PHP 8.1 release notes](https://www.php.net/releases/8.1/en.php).
WordPress documents the asset query's [cache-busting purpose](https://developer.wordpress.org/reference/functions/wp_enqueue_script/).

### Laravel generation patterns

Conjunctions of visible elements from upstream default views can propose template
families when no complete Laravel version is declared:

| Default-view conjunction | Conditional range |
|---|---|
| Nunito font, documentation link, Laravel News link and native documentation copy | `>=8,<10` — checked 8/9 defaults share this pattern |
| Figtree font, documentation card and “Vibrant Ecosystem” heading | `10.x` |
| `docs-card`, `docs-card-content` and the expected welcome background image | `11.x` |
| “Let's get started”, documentation and Laravel Cloud links | `>=12,<14` |
| Previous modern conjunction plus the exact `13.x/CHANGELOG.md` link | `13.x`, replacing the broader modern-view proposal on that page |

Sources are the tagged upstream views for [9](https://github.com/laravel/laravel/blob/v9.0.0/resources/views/welcome.blade.php),
[10](https://github.com/laravel/laravel/blob/v10.0.0/resources/views/welcome.blade.php),
[11](https://github.com/laravel/laravel/blob/v11.0.0/resources/views/welcome.blade.php),
[12](https://github.com/laravel/laravel/blob/v12.0.0/resources/views/welcome.blade.php)
and [13](https://github.com/laravel/laravel/blob/v13.0.0/resources/views/welcome.blade.php).
These `laravel_template` observations carry medium qualitative, uncalibrated
confidence. Templates can be customized, copied or retained after framework
upgrades, so none of these patterns predicts an installed patch. Incompatible
view families remain alternatives; explicit versions take precedence.

When renderer version labels are redacted, the old layout proposes
`>=11.9.0,<12.29.0`, and the redesigned layout proposes `>=12.29.0`.
A present previous-exception section can support `>=13.0.0`; its absence has no
version meaning. These are `laravel_renderer` family observations under the same
HTTP-error and visibility guards. Recognized full labels instead remain explicit
declarations. All matching renderers contribute evidence before resolution.

The hyphen cookie convention is visible in the [skeleton v12.3.0 configuration](https://github.com/laravel/laravel/blob/v12.3.0/config/session.php).
Skeleton tags and framework minor versions are distinct: this does not justify a
framework `>=12.3.0` bound. Either cookie spelling can persist after upgrades or
be configured independently. Earlier renderers without supported context,
including installations without Ignition, can remain unknown.

Matching catalog rules may attach the original `hypothesis` metadata to each
technology observation. This preserves the proposal's range, confidence, reason
and reference with its observed source, without turning it into an observed
version. `--no-hypotheses` removes these metadata objects and structured proposals,
as well as weak signals and inferred PHP presence, while keeping technology
identification and exact evidence. `--no-cookie-hints` suppresses cookie-based
observations and their proposals.

Reports retain at most 64 grouped proposals. Each proposal retains at most eight
distinct reasons, sources and references in each list; repeated entries are
deduplicated. Additional proposals produce a coverage gap. JSON, terminal and
HTML views expose the separate hypothesis channel. Explain and compare retain
it from saved reports; watch includes it in change detection. No extra HTTP
requests are added.

## Package and component inventory

Successful (HTTP 2xx) responses at `composer.json`, `composer.lock`, `package.json`
and `package-lock.json` inventory all syntactically valid production package names,
subject to report bounds, even when absent from the catalog. Catalog mappings use
their canonical product names, such as Laravel; otherwise reports retain
`composer:vendor/package`, `npm:package` or `npm:@scope/package` with kind `library`.
An unmapped Composer package permits PHP-presence inference; an unmapped npm
package has no runtime association. A catalog mapping uses its declared runtime.

| Input | Observation method | Version meaning |
|---|---|---|
| Composer `require` / npm `dependencies` with string values | `composer_requirement` / `npm_requirement` | Dependency identity only; even an exact requirement never becomes an installed version |
| Composer lock `packages` / npm lock `packages` entries below `node_modules/`, or format 1 `dependencies` | `composer_package` / `npm_package` | A validated lock version may be retained; installation and runtime loading remain unverified |
| Composer `require` or lock `platform` entries named `ext-*` | `composer_requirement` | `PHP extension:<name>` with kind `extension`; a requirement does not establish loading or an installed version |

`require-dev`, `devDependencies`, Composer `packages-dev` and npm lock entries
marked `dev: true` are skipped. Format 1 npm lockfiles traverse nested
`dependencies` through at most eight dependency levels, skipping development
subtrees; deeper entries mark truncation. Formats 2 and 3 use `packages` entries.
Package names are bounded to 120 bytes and validated as ecosystem
names; arbitrary JSON strings do not become inventory. PHP platform constraints
remain separate hypotheses. See [Composer basic usage](https://getcomposer.org/doc/01-basic-usage.md)
for the distinction between requirements and lockfile versions.

Resource URLs in already received HTML can identify `WordPress plugin:<slug>` or
`WordPress theme:<slug>` from `/wp-content/plugins/<slug>/<asset>` and
`/wp-content/themes/<slug>/<asset>`. These identities have kinds `plugin` and
`theme`, and a PHP runtime hint. Slugs allow at most 80 ASCII letters, digits,
underscores or hyphens. Only credential-free HTTP(S) references with the exact
page origin (scheme, host and effective port) qualify; matching paths on an
external host do not identify a local component. Assets are never fetched.

One valid `ver` or `version` query parameter containing a dotted numeric version
can add an `asset_version_hint` observation; leading lowercase `v` markers are
removed. Values with non-numeric suffixes produce no hint, avoiding retention of
private query content. Within technology observations, the numeric value appears in `detail`, never in the observation's
`version` or the technology's `versions`. A cache key cannot establish an exact
installed component version, presence or activation. This channel adds no
requests and does not perform [WordPress REST API discovery](https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/).

Recognized HTML or plain-text [phpinfo diagnostics](https://www.php.net/manual/en/function.phpinfo.php)
can retain `phpinfo_component` versions from allowlisted rows for Redis, Imagick,
cURL, OpenSSL, libxml, Zend OPcache, Xdebug, APCu, Memcached, MongoDB, igbinary,
msgpack, Zip and zlib. This includes `MongoDB extension version` and
`Compiled Version` / `Linked Version` rows under a recognized zlib section. Only bounded,
validated version tokens are retained;
arbitrary configuration cells are not copied into component observations. These
are diagnostic declarations with kind `extension`, not verified binaries or
PHP release evidence. HTML processing examines at most 1,024 rows and plain-text
processing at most 4,096 lines, within the existing response/parser bounds.

For HTTP statuses of at least 400, `<address>` error-footer declarations also
identify catalog or unknown providers, with bounded announced versions and
method `error_footer`. A server/framework version remains attached to that
product. Explicit PHP declarations continue through the separate PHP evidence
detector; an arbitrary footer product version never becomes a PHP version.

## Add a custom catalog

Save this complete UTF-8 JSON document as `acme.json`:

```json
{
  "schema_version": 1,
  "technologies": [
    {
      "name": "Acme Framework",
      "kind": "framework",
      "runtime": "PHP",
      "aliases": ["Acme"],
      "composer": ["vendor/acme"],
      "npm": [],
      "rules": [
        {
          "channel": "header",
          "key": "x-acme-version",
          "pattern": "^([0-9]+\\.[0-9]+\\.[0-9]+)$",
          "version_group": 1
        }
      ]
    }
  ]
}
```

Inspect the configuration without requests, then scan an authorized URL:

```sh
anatoly doctor https://app.example/ --fingerprints ./acme.json --json
anatoly scan https://app.example/ --fingerprints ./acme.json --dry-run --json
anatoly scan https://app.example/ --fingerprints ./acme.json --json
```

The custom document extends the built-ins. It cannot replace a built-in product
with a duplicate name or conflicting normalized alias. Here a matching
`X-Acme-Version: 2.3.4` identifies Acme Framework 2.3.4. The explicit association
`runtime: "PHP"` permits separate PHP-presence inference; it does not select PHP
2.3.4 or change the PHP CVE assessment. Omit `runtime` when no runtime association
is justified. Non-PHP runtime labels do not infer PHP.

The file is validated and expressions compiled before HTTP activity, including
doctor/dry-run. A malformed document aborts preflight. Compiled catalogs are reused
within the run; the document supplies data, not executable code. Saved configuration
records only `custom_fingerprints: true/false`, not the file's path or contents.

## Schema reference

The top level requires `schema_version: 1` and `technologies`. Each technology
requires `name` and `kind`; `runtime` is optional and `aliases`, `composer`,
`npm` and `rules` default to empty arrays.

| Technology field | Purpose |
|---|---|
| `name` | Canonical product name retained in reports |
| `kind` | Descriptive category, such as `framework`, `cms`, `frontend` or `server` |
| `runtime` | Optional association retained as `runtime_hint`; only the explicit value `PHP` enables PHP inference |
| `aliases` | Additional names recognized in selected provider/generator declarations |
| `composer` | Exact production Composer package names |
| `npm` | Exact npm package names, including scoped names |
| `rules` | Channel-specific observations described below |

| Rule field | Meaning |
|---|---|
| `channel` | Required: `header`, `cookie`, `asset` or `html` |
| `pattern` | Required Rust regex; use `(?i)` for case-insensitive matching |
| `key` | Required HTTP field name for `header`; unavailable on other channels |
| `selector` | Required CSS selector for `html`; unavailable on other channels |
| `attribute` | Optional permitted HTML attribute instead of visible element text |
| `version_group` | Optional positive regex capture-group index; no cookie versions |
| `hypothesis` | Optional `{range, confidence, reason, reference}` proposal metadata; mutually exclusive with `version_group` |
| `min_status` | Minimum HTTP status, default 100; range 100–599 |
| `same_origin` | Asset-reference origin restriction, default `true` |
| `context` | Up to four additional HTML regexes, all matching the same extracted text |

Header rules inspect only the selected field. Cookie rules inspect names and
discard values; they cannot extract versions. Catalog asset rules inspect URL
paths, excluding query values; WordPress inventory's numeric query hints remain
separate observations as described above. With `same_origin: false`, an observed external CDN
reference may match without being fetched; this describes a referenced resource,
not proof of the origin server's installed stack.

All four rule channels support conditional hypothesis metadata. For example,
this rule can be placed in an existing custom technology's `rules` array:

```json
{
  "channel": "header",
  "key": "x-acme-pattern",
  "pattern": "^modern$",
  "hypothesis": {
    "range": ">=3,<5",
    "confidence": "low",
    "reason": "Conditional compatibility of the observed Acme signature",
    "reference": "https://example.com/acme/compatibility"
  }
}
```

The example reference is a placeholder; use an authoritative compatibility source
for a real rule. A hypothesis rule cannot also specify `version_group`. The
`range` is bounded to 96 ASCII bytes and accepts numeric bounds, terminal `x`/`*`
wildcards, comparison/caret/tilde operators, commas, spaced bounds, numeric
hyphen ranges and `|`/`||` alternatives. Control characters are rejected.
Validation checks syntax, not whether the proposed compatibility
claim is true. `confidence` accepts only `low` or `medium`. A nonblank `reason`
allows at most 240 bytes without control characters; `reference` allows at most
512 bytes and must be an HTTPS URL with a host and without credentials or query
values. Unknown hypothesis fields are rejected before scanning.

HTML rules use compiled CSS selectors over the guarded document, following
[scraper's selector API](https://docs.rs/scraper/0.29.0/scraper/). Inert elements,
hidden content and articles cannot supply rule matches. Rules inspect bounded
visible text or an allowed attribute; they do not execute scripts, evaluate CSS
visibility or reproduce rendered browser state. Existing HTML prefix/depth guards
apply. Current matching considers at most 32 eligible nodes per rule and bounded
4 KiB text. Reaching these bounds reports an HTML coverage gap; an absent match
is not exhaustive evidence.

## Validation and limits

- Custom input is limited to 1 MiB. The combined catalog supports at most 256
  technologies and 512 rules.
- Unknown JSON fields, unsupported schema versions, duplicate product names,
  ambiguous normalized aliases, invalid regexes/selectors and nonexistent version
  capture groups are rejected.
- Labels, aliases, package names, selectors and patterns have bounded lengths;
  Composer and npm lists each allow at most 64 unique mappings per technology.
  each technology accepts at most 16 aliases. Rule patterns and each context
  expression are limited to 512 bytes, and HTML selectors to 128 bytes.
- Header rules reject sensitive or opaque fields such as authorization, cookies,
  credentials, location, ETag and request identifiers. HTML attribute selection
  is restricted; cookie rules accept names only.
- Retained product versions need two to four numeric components, at most six
  digits per component, and at most 64 bytes overall. ASCII prerelease/build
  suffixes are allowed. A rule can identify a product without retaining a version.

Observation grouping, retained-source limits, `--no-hypotheses`, cookie suppression,
request scope and coverage semantics still apply. See [Reconnaissance](RECONNAISSANCE.md)
and [scan controls](FLAGS.md). More entries expand recognition opportunities;
they do not make discovery, identification, version disclosure or security
assessment exhaustive.

Reports retain at most 256 technologies and 64 distinct observations per
technology, including uncataloged inventory. Overflow marks truncation and a
coverage gap. These report limits are separate from catalog-validation limits.
Inventory reuses received responses and adds no requests; no complete package,
plugin, extension or technology inventory is guaranteed.
