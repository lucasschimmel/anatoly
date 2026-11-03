# Detection, Technology Fingerprints & Hypotheses

Anatoly separates explicit PHP runtime declarations, technology observations (`technologies`), PHP runtime presence (`runtime.status`), and conditional version hypotheses (`version_hypotheses`).

## 1. Public PHP Version Detection

`analysis.detection_level` reports four levels independently of the CVE verdict:

| Level | Meaning |
|---|---|
| `declared` | One method explicitly declares a complete PHP release; repeated headers remain one method |
| `corroborated` | Distinct public methods agree, such as headers plus `phpinfo()` or explicit runtime JSON |
| `contradictory` | Different complete releases were observed; no single runtime version is selected |
| `unknown` | No complete declaration; hypotheses may still be available |

Corroboration is observational agreement, not independent authentication or certification. `certified` and `secure` remain unattested, with zero summary counts.

### Proof Channels

`version_candidates` groups every distinct release with its own level and all proofs (source URL/header or metadata key, method kind, normalized PHP token, and observed HTTP status). `signals` holds unverified clues separately and **never selects an exact PHP version, changes a CVE fix-floor comparison, or certifies security.**

| Public method | Extracted information | Limits |
|---|---|---|
| Runtime headers | Complete duplicate fields; exact `PHP/x.y.z`; bare/comma-separated releases in `X-PHP-Version` and `PHP-Version` | A partial branch is a hypothesis, not a patch release; generic `X-Runtime` digits are not PHP |
| Cookies | Canonical PHP/CMS cookie names, length/alphabet, `Secure`/`HttpOnly`/`SameSite` | Values and opaque suffixes are discarded; configurable session shapes cannot identify releases |
| `phpinfo()` | Recognizable HTML heading and markers or plain-text diagnostics, version and allowlisted settings | Ordinary paragraphs with PHP keywords are not diagnostics |
| Runtime JSON | `php_version`, `phpversion`, `PHP_VERSION_ID`, `php.version`, optionally below `runtime`/`environment`/`system`/`php`/`info` | Generic package `version` fields are ignored; no body or environment dump |
| PHP-version endpoint | Numeric body on `phpversion.php` or `php-version.php` | Numeric content on generic `version.php` is not assumed to be PHP |
| HTTP error | Explicit PHP token inside an error-page `<address>`/footer | A footer can describe the frontend; no guarantee the app uses the same runtime |
| HTML/CMS | Exact generator attributes, visible attribution, selected same-origin asset paths and PHP-like links/forms | Application versions are not PHP versions; inert/documentary examples do not declare an application |
| Composer / npm | Root PHP requirements, simulated platform settings and production packages on metadata routes | Requirements, lock data and build overrides do not establish the live PHP runtime |
| Deprecations | Dynamic-property (`>=8.2,<9`) or null-parameter (`>=8.1`) diagnostic wording | Static pages or custom messages can imitate diagnostics; ranges are hypotheses only |
| Cache | Positive `Age`, `X-Cache`/`CF-Cache-Status` HIT | Cached samples cannot establish worker diversity |
| Discovery | Recognized same-origin diagnostic paths from structured HTML/`robots.txt` (default 3, thorough/deep 16, max 128) | Queries/fragments removed; shared request budget remains authoritative |

### Discovery Candidates (`--deep`)

The normal CLI keeps an 8-request budget and 3 application samples. `--deep` sets a 32-request default budget and includes:

```text
php_info.php       php-info.php       phpversion.php    php-version.php
version.php        status.php         diagnostics.php   info
version            status             composer.json     composer.lock
robots.txt         __anatoly_missing__.php
```

Disclosed diagnostics are scheduled ahead of fallback guesses. Deep discovery prioritizes `robots.txt`, `composer.json` and `composer.lock`.

---

## 2. PHP2Shell Coverage & Allowlisted `phpinfo()` Directives

Anatoly follows upstream PHP advisories:
- **CVE-2026-109618**: memory corruption after an out-of-memory interruption, including during request cleanup ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)).
- **CVE-2026-109619**: request-owned state retained across requests and consumed before reinitialization ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)).
- **Upstream fix floors**: **8.2.35, 8.3.36, 8.4.27 and 8.5.12**.

Recognizable HTML and plain-text `phpinfo()` diagnostics retain 16 allowlisted settings:

```text
session.upload_progress.enabled  session.serialize_handler
memory_limit                    post_max_size
upload_max_filesize             file_uploads
max_file_uploads                max_input_vars
max_input_nesting_level         max_multipart_body_parts
enable_post_data_reading        display_errors
server api                      fatal_error_backtraces
opcache.enable                  opcache.enable_cli
```

Configuration observations never downgrade a potentially affected version to a secure or certified result.

---

## 3. Technology Fingerprints & Inventory

Anatoly embeds a declarative catalog in [`fingerprints/catalog.json`](../fingerprints/catalog.json) covering **94 products** across PHP applications, server frameworks, frontend libraries, web servers and proxies.

### Runtime Presence (`runtime.status`)

| Status | Meaning |
|---|---|
| `declared` | Explicit PHP version evidence or a selected header naming PHP |
| `inferred` | Enabled clues whose catalog definition explicitly associates the product with PHP make PHP plausible |
| `unknown` | No enabled presence evidence; this does not establish PHP absence |

### Package and Component Inventory

- **Composer & npm** (`composer.json`, `composer.lock`, `package.json`, `package-lock.json`): Inventories valid production package names. Catalog mappings use canonical names (e.g. `Laravel`); unmapped packages use `composer:vendor/package` or `npm:package`. `require`/`dependencies` record identity only (`composer_requirement`/`npm_requirement`); lockfiles may retain versions (`composer_package`/`npm_package`). `ext-*` entries record `PHP extension:<name>`. Development dependencies are skipped.
- **WordPress components**: Same-origin resource URLs under `/wp-content/plugins/<slug>/...` and `/wp-content/themes/<slug>/...` identify `WordPress plugin:<slug>` and `WordPress theme:<slug>`. Numeric `ver`/`version` query parameters are recorded as `asset_version_hint` cache hints only.
- **`phpinfo()` components**: Extracts allowlisted extension/library versions (`phpinfo_component`) for Redis, Imagick, cURL, OpenSSL, libxml, Zend OPcache, Xdebug, APCu, Memcached, MongoDB, igbinary, msgpack, Zip and zlib.

---

## 4. Conditional Version Hypotheses

When a technology has no complete observed version, `version_hypotheses` retains bounded proposals (`technology`, `range`, `confidence` [`low`|`medium`], `basis`, `reasons`, `sources`, `references`, `limitations`) separately from exact PHP evidence.

| Input | Proposal | Limits |
|---|---|---|
| Exact `laravel-session` cookie name | Laravel `>=12` (`low`), conditional PHP `>=8.2` (`low`) | Modern skeleton convention, configurable |
| Partial major/minor declaration (e.g. `PHP/8.4`) | `8.4.x` (`medium`) | Patch unknown; remote declaration unverified |
| PHP deprecation wording | `>=8.2,<9` (dynamic properties) or `>=8.1` (null-to-non-nullable) (`low`) | Conditional on real runtime diagnostic |
| Composer PHP platform constraints | Validated constraint (`low`) | Dependency/build compatibility, not live web runtime |
| Laravel/Symfony version declarations | Upstream minimum PHP requirement (`low`) | Conditional on declared framework matching deployment |
| Default Laravel welcome views & error renderers | Template family (`>=8,<10`, `10.x`, `11.x`, `>=12,<14`, `13.x`) or renderer family (`>=11.9.0,<12.29.0`, `>=12.29.0`, `>=13.0.0`) | Templates can be customized or retained across upgrades |

Use `--no-hypotheses` to disable weak signals, structured version proposals and inferred PHP presence. Use `--no-cookie-hints` to suppress cookie-based observations and proposals.

---

## 5. Custom Fingerprint Catalogs (`--fingerprints`)

Extend built-in detection with a validated UTF-8 JSON file (max 1 MiB):

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

```sh
anatoly doctor https://app.example/ --fingerprints ./acme.json --json
anatoly scan https://app.example/ --fingerprints ./acme.json --json
```

### Schema Summary

- **Technology fields**: `name` (required), `kind` (required), `runtime` (optional; only `"PHP"` enables PHP inference), `aliases` (max 16), `composer` (max 64), `npm` (max 64), `rules`.
- **Rule fields**: `channel` (`header`, `cookie`, `asset`, `html`), `pattern` (Rust regex, max 512 bytes), `key` (required for `header`), `selector` (required CSS selector for `html`, max 128 bytes), `attribute` (optional HTML attribute), `version_group` (optional capture group; mutually exclusive with `hypothesis`), `hypothesis` (`{range, confidence, reason, reference}`), `min_status` (100–599, default 100), `same_origin` (default `true`), `context` (up to 4 additional regexes).
- **Bounds**: Combined catalog supports at most 256 technologies and 512 rules. Sensitive headers (`authorization`, `cookie`, `location`, `etag`, etc.) are rejected in custom rules.
