# Anatoly discovery wordlist

`anatoly-core.txt` contains **24 unique, ordered paths**, selected for Anatoly's
existing evidence parsers and bounded request budget. This is a focused candidate
list, not a statistical ranking or an exhaustive directory-discovery dictionary.
PHP does not create these URLs automatically: their existence depends on deployment.

## Use

Download the file from the repository if Anatoly was installed from a binary release:

```sh
curl -fL https://raw.githubusercontent.com/lucasschimmel/anatoly/main/wordlists/anatoly-core.txt -o anatoly-core.txt
anatoly scan -u https://app.example/ --wordlist anatoly-core.txt --samples 3 --max-requests 32 -o scan.json
```

From a clone, use `--wordlist wordlists/anatoly-core.txt`.
Do not select the quick profile or `--no-discover`: both disable the intended discovery.

## Ordering and evidence

1. PHP information pages and dedicated version endpoints. The parser can recognize
   phpinfo output and explicit version declarations, including bare numeric versions
   on `phpversion.php` and `php-version.php` only.
   The optional Symfony WebProfiler route `_profiler/phpinfo` is included too.
2. Application-defined status, version and diagnostic routes. Names alone prove
   nothing; a matching response still needs recognizable PHP evidence.
3. A small selection of diagnostic paths below development/tool directories.
4. Composer metadata, which can reveal PHP constraints or build configuration;
   it does not certify the PHP runtime serving the application.

The list uses relative paths, so a target such as `https://app.example/portal/`
is checked below `/portal/`. Targeting `/portal/index.php` has the same directory
base. A redirect can change that base because discovery uses the final URL.
To assess the site root, supply its root URL separately.

## Request budget

With balanced discovery, default paths unchanged, three successful application
samples and this list, the initial plan is **3 samples + 24 diagnostic URLs =27
HTTP requests**. `phpinfo.php` and `info.php` already exist in the default plan and
are deduplicated. A cap of 32 leaves five requests for redirects and newly discovered
diagnostic links. This is a conditional calculation, not a guarantee of completion.

For a more predictable fixed list, add `--no-linked-discovery`. Redirects still use
the same budget. Avoid `--deep`/the thorough profile when reproducing the 27-request
plan: they add extra built-in paths and can change sample counts. With the default
eight-request cap, the whole list will not fit and coverage will remain incomplete.

The file remains below Anatoly's 64-path / 64 KiB limits. It has no queries, fragments,
absolute URLs or path-traversal entries. It deliberately focuses on metadata rather
than backups, credential files, upload handlers or administrative actions.

An unavailable page does not prove safety. A discovered page does not prove PHP2Shell
exploitability. HTTP 200 responses, generic errors and soft 404 pages must still pass
Anatoly's evidence checks. Full response bodies are not exported by the scanner.

Sources for interpretation: [PHP phpinfo documentation](https://www.php.net/manual/en/function.phpinfo.php)
and [Composer platform dependencies](https://getcomposer.org/doc/articles/composer-platform-dependencies.md).
Symfony's route is documented in its [WebProfiler controller tests](https://github.com/symfony/web-profiler-bundle/blob/8.2/Tests/Controller/ProfilerControllerTest.php).
Other candidate filenames and ordering are project heuristics, not claims made by those sources.
