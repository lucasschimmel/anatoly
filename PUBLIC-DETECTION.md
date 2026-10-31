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

## PHP2Shell coverage review — 2026-10-31

Anatoly follows the PHP project's categories: **CVE-2026-109618** concerns
memory corruption after an out-of-memory interruption, including during request
cleanup; **CVE-2026-109619** concerns request-owned state retained across requests
and consumed before reinitialization. The upstream fix floors are **8.2.35,
8.3.36, 8.4.27 and 8.5.12**. See the [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

| Observation | Assessment boundary |
|---|---|
| Version below its upstream floor | Potentially affected; exploitation has not been attempted |
| Version meets its upstream floor | Fix floor observed; vendor patches and the running worker build remain unverified |
| Older or vendor-maintained branch | Public version text cannot establish backport status; inspect the vendor package |
| FPM/FastCGI | Startup failure may terminate a worker, but application-stage stale-state paths remain possible |
| Upload progress disabled | Removes the demonstrated early session path, not every stale-state path |
| `memory_limit=-1` | Removes the predictable PHP limit, not underlying allocation failure |
| `display_errors=Off` | Hides output; it does not prevent the stale-state consumer |
| PHP 8.5 `fatal_error_backtraces=0` | Removes one producer, not every state family |

The configuration distinctions follow the two PHP advisories above. A disclosed
setting describes the diagnostic request's context; it cannot establish values
in every pool or application route. Missing settings remain unknown.

[Wiz's research](https://www.wiz.io/blog/php2shell-php-rce) describes multiple
primitives, including memory disclosure, session lifecycle, fatal backtraces and
OPcache. CMS demonstrations do not make the issue CMS-specific; an application
need not call `session_start()` for early upload-progress handling to run.
[Akamai's walkthrough](https://www.akamai.com/blog/security-research/understanding-php2shell-everything-you-need-to-know)
lists prerequisites for its described upload-progress chain. Anatoly does not
treat those prerequisites as exclusions covering every PHP2Shell variant.
[Tanium's response guidance](https://www.tanium.com/blog/php2shell-responding-to-cve-2026-109618-and-cve-2026-109619)
also emphasizes inventory and package updates; dated observations about public
exploit reliability do not establish protection for an architecture or SAPI.

Recognizable HTML and plain-text `phpinfo()` diagnostics retain the same 16
allowlisted settings:

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

Each observation preserves its source, local value and available master value;
conflicting local observations remain visible. Arbitrary phpinfo rows and
environment dumps are not retained. Configuration observations never turn a
potentially affected release into a secure or certified result.

The local `devploit-php2shell` clone was reviewed statically for its version
matrix and documented preconditions. Its memory-exhaustion probes were not
imported into Anatoly or executed. The local `anonmoty-PHP2SHELL` working tree
contained no source files at review time. Regression fixtures verify public
evidence handling; they do not demonstrate an exploit or certify a deployed
server's patch state.

## Primary references

- [PHP session settings](https://www.php.net/manual/en/session.configuration.php)
- [PHP runtime constants](https://www.php.net/manual/en/reserved.constants.php)
- [PHP diagnostics](https://www.php.net/manual/en/function.phpinfo.php)
- [PHP identification can be hidden or replaced](https://www.php.net/manual/en/security.hiding.php)
- [Dynamic-property deprecation](https://wiki.php.net/rfc/deprecate_dynamic_properties)
- [PHP 8.1 null-parameter deprecation](https://www.php.net/releases/8.1/en.php)
- [Composer platform dependencies](https://getcomposer.org/doc/articles/composer-platform-dependencies.md)
- [HTTP caching](https://www.rfc-editor.org/rfc/rfc9111.html)
