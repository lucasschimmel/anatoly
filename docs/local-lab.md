# Anatoly — Local Docker Exploit & Connect Lab

This lab executes the real PHP2Shell chain against an exact **Apache prefork / mod_php** build inside a disposable loopback-only Docker container. It does not simulate command execution and does not infer RCE from a vulnerable version string.

`exploit` and `connect` first reuse Anatoly's normal scanner and its `ScanArgs` options. They select a profile only when the scanner identifies one exact, stable, affected PHP version. The selected profile must match that version; Anatoly never substitutes another patch from the same branch.

## Verified execution profiles

The embedded catalog contains 18 official `php:<version>-apache` Debian bookworm amd64 profiles with maintainer-verified command proofs from [devploit/php2shell](https://github.com/devploit/php2shell) (MIT, see `lab/PHP2SHELL-LICENSE`):

- PHP **8.4**: 8.4.10, 8.4.11, 8.4.19, 8.4.20, 8.4.25, 8.4.26 (`carrier` geometry);
- PHP **8.5**: every patch from 8.5.0 through 8.5.11 (`vessel` for 8.5.0–8.5.9, `carrier` for 8.5.10–8.5.11).

The 8.4.26 source image is digest-pinned. Other versions use their exact Docker tags; before every attempt Anatoly reads the running PHP version, container image identity and unique `zif_system` / `zval_ptr_dtor` symbols, and compares those symbols with the selected verified profile. A mismatch aborts execution.

**Affected does not mean RCE-calibrated.** PHP 8.2 and 8.3, affected 8.4 patches absent from the list, EOL branches and other build/OS/architecture combinations have no executable profile in this catalog. They can be started for scanner testing, but `exploit`/`connect` refuses them even with `--force`. In particular, PHP 8.3.35 reproduces heap/libphp leaks upstream but has no verified stage-3 profile; Anatoly does not claim RCE for it.

Local end-to-end verification on this checkout covers PHP **8.4.10**, **8.4.26** and **8.5.0**, including both stage-3 geometries and the PHP 8.3.35 refusal. The other embedded profiles retain their upstream verification status rather than a claim of fresh local coverage.

## Architecture and proof

The execution engine is part of the public `anatoly::exploit` library module. Private implementation modules follow the flat `src/exploit_*.rs` layout; the verified profile catalog is compiled into the binary from `src/exploit_profile_catalog.json`. CLI orchestration lives in `execution_modes.rs` and reuses the scanner, target validation, scope validation, export preflight and `Ui`.

For each command, the engine derives offsets from the exact running container, executes the selected `carrier` or `vessel` geometry, then requires fresh output in `/out/p1` and matching `PROOF` output from the reproducer. A crash, heap leak or libphp leak alone is never success. The proof script uses LF line endings for Windows and Linux hosts.

The lab directory is resolved at runtime. When invoking Anatoly outside the project directory, pass `--lab-dir /path/to/anatoly` (the directory containing `lab/`). Use the same checkout to start Docker and run commands so the mounted proof directory matches. Library callers select `Php2ShellProfile::for_version(...)`, construct `Php2ShellBackend::with_profile(project_directory, profile)` and call `execute(&target, command)`; terminal output belongs to the caller.

## Prerequisites

- Docker Desktop (or Docker Engine) running and reachable (`docker version`);
- Python 3.11 or newer;
- `linux/amd64` support (native or emulated);
- Sufficient memory for calibrated requests and the 1 GiB container limit.

## Security and isolation guardrails

- Published exclusively on `127.0.0.1:18108`;
- Dedicated Docker bridge network created on `up` and removed on `down`;
- `no-new-privileges:true`, memory limit (`1g`) and PID limit (`64`);
- Any valid absolute HTTP(S) URL is accepted through the shared scanner validation, without lab-specific host, port, path or query restrictions;
- Commands are passed verbatim to the shell without an allowlist or denylist;
- Configuration files mounted read-only; only disposable `lab/out/` receives proof files;
- No persistent shell: each command reruns the full chain and requires fresh proof.

## Walkthrough

### 1. Start an exact supported version

PHP 8.4.26 remains the default:

```powershell
python lab/local_lab.py up
```

Select another version explicitly:

```powershell
python lab/local_lab.py up --php-version 8.5.0
```

The endpoint remains `http://127.0.0.1:18108/index.php` for every version.

### 2. Scan and prove RCE with `exploit`

```powershell
cargo run -- --no-banner exploit -u http://127.0.0.1:18108/index.php
```

The normal scan runs first. Scanner transport/discovery options keep their usual meaning, for example:

```powershell
cargo run -- --no-banner exploit -u http://127.0.0.1:18108/index.php --samples 1 --no-discover --output proof.json
```

Expected proof fields include:

```text
status               real_rce_proven
php_version          8.5.0
profile              php-8.5.0-bookworm-amd64
calibration          running_version_image_identity_and_libphp_symbols_verified
proof                uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3. Run shell commands with `connect`

Single command:

```powershell
cargo run -- --no-banner connect -u http://127.0.0.1:18108/index.php --command whoami
```

Interactive prompt:

```powershell
cargo run -- --no-banner connect -u http://127.0.0.1:18108/index.php
```

The scanner and profile selection run once for the interactive session. Every command still reruns the chain and requires fresh proof. Commands are passed to the shell without an allowlist or denylist; type `exit` to stop.

### 4. Understand `--force`

By default, execution requires a `potentially_affected` scan verdict. If the scanner identifies an exact stable affected version and a verified profile but the overall HTTP verdict is inconclusive, `--force` permits the attempt:

```powershell
cargo run -- --no-banner exploit -u http://127.0.0.1:18108/index.php --force
```

`--force` **never** bypasses target or command restrictions and never permits an unknown, conflicting, fixed, prerelease, unsupported or unreviewed version. It also cannot manufacture a missing RCE profile or select another build.

### 5. Stop and remove the lab

```powershell
python lab/local_lab.py down
```

## Automated verification

Run unit and CLI guardrail tests without Docker:

```powershell
cargo test --locked
```

Run the real end-to-end flow (build Anatoly, start the selected container, run `exploit` and `connect --command whoami`, then tear down):

```powershell
python scripts/verify_local_lab.py --php-version 8.4.26
python scripts/verify_local_lab.py --php-version 8.4.10
python scripts/verify_local_lab.py --php-version 8.5.0
```

## Troubleshooting

- **Docker CLI not found / daemon unavailable**: start Docker Desktop and open a new terminal if it was just installed.
- **No verified RCE profile**: the detected version is affected but its exact build has no verified stage-3 geometry. Do not substitute a nearby profile; `--force` intentionally does not override this refusal.
- **Symbol mismatch**: the running image does not match the embedded build profile. Recreate it from the exact tag and investigate mutable/upstream image changes.
- **HEAP_LEAK_FAILED / LIBPHP_LEAK_FAILED**: recreate the container with `down` then `up` and retry within the calibrated retry budget.
- **RCE was not proven**: inspect the reproducer error; never treat a partial leak as successful execution.
