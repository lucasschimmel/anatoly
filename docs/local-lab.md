# Anatoly — Local Docker Exploit & Connect Lab

This lab executes the real PHP2Shell chain against **PHP 8.4.26 / Apache prefork / mod_php** inside a disposable loopback-only Docker container. The memory profile and offsets match the digest-pinned image (`php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`).

The `php-8.4.26-bookworm-amd64` profile verifies heap and `libphp` leaks, then requires fresh command output inside `/out/p1` before reporting `PROOF`. The proof script is written with LF line endings so it runs cleanly from both Windows and Linux hosts.

## Prerequisites

- Docker Desktop (or Docker Engine) running and reachable (`docker version`);
- Python 3.11 or newer;
- `linux/amd64` support (native or emulated);
- Sufficient memory for calibrated ~140 MiB requests.

## Security & Isolation Guardrails

- Published exclusively on `127.0.0.1:18108`;
- Dedicated Docker bridge network created on `up` and removed on `down`;
- `no-new-privileges:true`, memory limit (`1g`) and PID limit (`64`);
- `exploit` and `connect` require the explicit `--lab` flag;
- Only the exact loopback target `http://127.0.0.1:18108/index.php` (or `/`) is accepted;
- No arbitrary commands: strictly limited to the allowlist `id`, `whoami`, `pwd`, `hostname`, `php -v`, and `uname -a`;
- Configuration files (`lab/docker/`) are mounted read-only; only the disposable `lab/out/` directory receives proof files;
- Non-persistent: each command reruns the full exploit chain and verifies a fresh proof file.

## Walkthrough

### 1. Build and start the vulnerable PHP 8.4.26 container

```powershell
python lab/local_lab.py up
```

The lab is ready when the command prints:

```text
[+] Real PHP lab ready on http://127.0.0.1:18108/index.php
[+] Published on loopback only; dedicated Docker bridge attached.
```

### 2. Prove RCE with `exploit`

```powershell
cargo run -- --no-banner exploit -u http://127.0.0.1:18108/index.php --lab
```

Expected output:

```text
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
│ ANATOLY / LOCAL LAB PROOF
│ status               real_rce_proven
```

Without a fresh proof file containing the output of `id`, the command fails: a crash or memory leak alone is never reported as RCE.

### 3. Run allowlisted commands with `connect`

Single command:

```powershell
cargo run -- --no-banner connect -u http://127.0.0.1:18108/index.php --lab --command whoami
```

Interactive prompt:

```powershell
cargo run -- --no-banner connect -u http://127.0.0.1:18108/index.php --lab
```

Available commands in interactive mode: `id`, `whoami`, `pwd`, `hostname`, `php -v`, `uname -a`, or `exit`.

### 4. Stop and remove the lab

```powershell
python lab/local_lab.py down
```

## Automated Verification

Run the unit and CLI guardrail tests (no Docker required):

```powershell
cargo test --locked
```

Run the full end-to-end Docker verification (builds Anatoly, starts the container, runs `exploit` and `connect --command whoami`, and tears down the container):

```powershell
python scripts/verify_local_lab.py
```

## Troubleshooting

- **Docker CLI not found / daemon unavailable**: Ensure Docker Desktop is running and open a new terminal if just installed.
- **HEAP_LEAK_FAILED / LIBPHP_LEAK_FAILED**: If heap layout did not converge within the retry budget, recreate the container (`python lab/local_lab.py down` then `up`) and retry.
- **RCE was not proven**: Inspect the reproducer output; never treat a partial leak as a successful execution.
