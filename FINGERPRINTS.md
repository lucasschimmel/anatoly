# Extensible technology fingerprints

Version 0.3.0 embeds a declarative catalog in
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
error panel can also match when the HTTP status is at least 400 and its bounded
visible text includes Laravel, a PHP version label, and Error/Exception/UNHANDLED
context. An ordinary article or a standalone version string is insufficient.

The contextual panel follows the structure represented by Laravel's
[exception-renderer header](https://github.com/laravel/framework/blob/13.x/src/Illuminate/Foundation/resources/exceptions/renderer/components/header.blade.php).
Applications can replace, hide or imitate that renderer. Its version remains a
remote framework observation. The PHP text used as context does not become PHP
version evidence through this rule.

`technologies[].versions` and per-observation `version` hold the selected product's
announced/package versions. They never populate the exact PHP `version` merely
because the product uses PHP. Requirements in `composer.json` or `package.json`
identify dependencies without turning constraints into installed versions.
Exposed Composer production lock packages and non-development `package-lock.json`
`packages` entries (lockfile formats 2 and 3) may retain versions; they do not prove
what the web runtime executes. Legacy format 1 dependency trees are not interpreted.

Unknown providers in selected header or actual generator declarations can still
be reported by their supplied name and bounded version, without an implicit
runtime association. An unknown `Acme Server/2.3.4` declaration does not infer PHP.

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
| `min_status` | Minimum HTTP status, default 100; range 100–599 |
| `same_origin` | Asset-reference origin restriction, default `true` |
| `context` | Up to four additional HTML regexes, all matching the same extracted text |

Header rules inspect only the selected field. Cookie rules inspect names and
discard values; they cannot extract versions. Asset rules inspect URL paths,
excluding query values. With `same_origin: false`, an observed external CDN
reference may match without being fetched; this describes a referenced resource,
not proof of the origin server's installed stack.

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
