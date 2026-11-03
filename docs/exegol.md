# Exegol Installation & Usage

Anatoly is an independent custom tool. No Rust compiler is needed for the release binary. Linux x86_64 and ARM64 are supported (requires glibc >= 2.35, OpenSSL 3, CA certificates, `curl`, `tar` and `sha256sum`).

## Install Inside a Container

Run these commands **inside your Exegol container**:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.5.0/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.5.0 --bin-dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
anatoly --version
anatoly doctor https://app.example/ --no-proxy --json
```

The installer verifies the binary archive's SHA-256 before installation, runs only `--version` to check compatibility, and never scans a target or changes shell startup files. Existing binaries require explicit `--force` to replace.

## Persist Across Containers (`/opt/my-resources`)

Exegol mounts your configured host `my-resources` directory inside containers at `/opt/my-resources`. Install the binary there to share it across containers of the same CPU architecture:

```sh
sh /tmp/anatoly-install.sh --version v0.5.0 --bin-dir /opt/my-resources/bin
export PATH="/opt/my-resources/bin:$PATH"
anatoly --version
```

To upgrade an existing installation, pass `--force`:

```sh
sh /tmp/anatoly-install.sh --version v0.5.0 --bin-dir /opt/my-resources/bin --force
```

## HTB / Lab Workflow

For virtual hosts, map the application's hostname to its box IP with `--resolve` (or `/etc/hosts`) and use the hostname in the URL:

```sh
anatoly scan -u http://box.htb/ --resolve box.htb:10.129.1.20 --profile thorough --no-proxy -o box.json
anatoly exposure -u http://box.htb/ --resolve box.htb:10.129.1.20 --no-proxy -o exposure.json
anatoly headers -u http://box.htb/ --resolve box.htb:10.129.1.20 --no-proxy
anatoly report box.json -o assessment.html
```

## Build from Source

If your container requires a source build:

```sh
apt-get update
apt-get install -y build-essential pkg-config libssl-dev ca-certificates git
git clone https://github.com/lucasschimmel/anatoly.git
cd anatoly
cargo install --locked --path .
export PATH="$HOME/.cargo/bin:$PATH"
```
