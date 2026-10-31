# Public PHP detection

`analysis.detection_level` reports four levels independently of the CVE verdict:

| Level | Meaning |
|---|---|
| `declared` | One method explicitly declares a complete PHP release; repeated headers remain one method |
| `corroborated` | Distinct public methods agree, such as headers plus phpinfo or explicit runtime JSON |
| `contradictory` | Different complete releases were observed; no single runtime version is selected |
| `unknown` | No complete declaration; hypotheses may still be available |

The same server can configure or spoof several methods. Corroboration is
observational agreement, not independent authentication or certification.
One hostname may route different paths or responses to different PHP pools.
`certified` and `secure` remain unattested, with zero summary counts.

## Proof records

`version_candidates` groups every distinct release with its own level and all
proofs: source URL/header or metadata key, method kind, normalized PHP token and
observed HTTP status. Repeated observations remain in JSON; the terminal groups
duplicates while showing every distinct proof source.

`signals` holds unverified clues separately. **Signals never select an exact
PHP version, change a CVE fix-floor comparison, or certify security.**

| Public method | Extracted information | Limits |
|---|---|---|
| Runtime headers | Complete duplicate fields; exact `PHP/x.y.z`; bare/comma-separated releases in `X-PHP-Version` and `PHP-Version` | A partial branch is a hypothesis, not a patch release; generic X-Runtime digits are not PHP |
| Cookies | Canonical PHP/CMS cookie names, length/alphabet, Secure/HttpOnly/SameSite | Values and opaque suffixes are discarded; configurable session shapes cannot identify releases |
| phpinfo | Recognizable HTML heading and markers or plain-text diagnostics, version and allowlisted settings | Ordinary paragraphs with PHP keywords are not diagnostics |
| Runtime JSON | `php_version`, `phpversion`, `PHP_VERSION_ID`, `php.version`, optionally below runtime/environment/system/php/info | Generic package `version` fields are ignored; no body or environment dump |
| PHP-version endpoint | Numeric body on `phpversion.php` or `php-version.php` | Numeric content on generic `version.php` is not assumed to be PHP |
| HTTP error | Explicit PHP token inside an error-page address/footer | A footer can describe the frontend; no guarantee the app uses the same runtime |
| HTML/CMS | Generator markers and PHP-like link/form paths | Application versions are not PHP versions; ordinary PHP text is only a clue |
| Composer | Root PHP requirements and simulated platform settings if publicly exposed | Requirements, lock data and build overrides do not establish the live runtime |
| Deprecations | Dynamic-property or null-parameter diagnostic wording | Static pages or custom messages can imitate diagnostics; ranges are hypotheses only |
| Cache | Positive Age, X-Cache/CF-Cache-Status HIT | Cached samples cannot establish worker diversity |
| Discovery | Up to three recognized same-origin diagnostic links from HTML/robots | Queries/fragments removed; no general crawl, file inclusion or authentication bypass |

Dynamic-property wording suggests a possible `>=8.2,<9` range;
null-to-non-nullable wording suggests `>=8.1`. Neither establishes an exact
release, patch status or exploitability. No such error is actively provoked.

The terminal shows up to six hypotheses; JSON contains up to 64 distinct signals,
with explanations and reference links. Raw bodies, full header values, cookies
and session values are not exported. Full selected headers are parsed in memory
so a late declaration cannot silently hide a contradiction.

## Discovery boundaries

The normal CLI keeps an eight-request budget and three application samples.
`--deep` sets a 32-request default budget and appends these public candidates:

```text
php_info.php       php-info.php       phpversion.php    php-version.php
version.php        status.php         diagnostics.php   info
version            status             composer.json     composer.lock
robots.txt         __anatoly_missing__.php
```

The last candidate checks an ordinary missing-page response, not an injected
error. Explicit `--max-requests` always wins. `--no-discover` disables additional
path requests. A blocked, failed or budget-skipped planned route is reflected
in coverage; an absent diagnostic page does not prove protection.

Linked discovery accepts only specific diagnostic filenames, remains on the
same scheme/host/port and deduplicates routes. Generic action/navigation links
are never followed. No POST, malformed multipart, OOM, command or exploit is sent.

TLS certificates, IP/geolocation, server versions, CMS versions, favicon hashes,
session shapes and timing do not establish an exact PHP patch. No security
percentage or release is fabricated from them. Legacy logo/Easter-egg probes
and third-party fingerprint databases are not used.

## Primary references

- [PHP session settings](https://www.php.net/manual/en/session.configuration.php)
- [PHP runtime constants](https://www.php.net/manual/en/reserved.constants.php)
- [PHP diagnostics](https://www.php.net/manual/en/function.phpinfo.php)
- [PHP identification can be hidden or replaced](https://www.php.net/manual/en/security.hiding.php)
- [Dynamic-property deprecation](https://wiki.php.net/rfc/deprecate_dynamic_properties)
- [PHP 8.1 null-parameter deprecation](https://www.php.net/releases/8.1/en.php)
- [Composer platform dependencies](https://getcomposer.org/doc/articles/composer-platform-dependencies.md)
- [HTTP caching](https://www.rfc-editor.org/rfc/rfc9111.html)
