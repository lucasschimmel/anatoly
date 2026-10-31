# Exegol installation

Anatoly is an independent custom tool. It is not bundled with or endorsed by Exegol.
No Rust compiler is needed for the release binary. Linux x86_64 and ARM64 are supported.
Requirements: glibc >= 2.35, OpenSSL 3, CA certificates, curl, tar and sha256sum.
Use a source build if your container does not meet these requirements.

## Install inside a container

Run these commands **inside your Exegol container**, not on the host:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.2.2/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.2.2 --bin-dir "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
anatoly --version
anatoly doctor https://app.example/ --no-proxy --json
```

The installer verifies the binary archive's SHA-256 before installation, runs only
`--version` to check compatibility, and never scans a target or changes shell startup
files. Existing binaries require explicit `--force` to replace. Checksums verify
download integrity; they are not a separate publisher signature.

## Upgrade an existing installation

Download and inspect the installer, then explicitly replace the existing binary:

```sh
curl -fL https://github.com/lucasschimmel/anatoly/releases/download/v0.2.2/install.sh -o /tmp/anatoly-install.sh
less /tmp/anatoly-install.sh
sh /tmp/anatoly-install.sh --version v0.2.2 --bin-dir "$HOME/.local/bin" --force
"$HOME/.local/bin/anatoly" --version
```

Use the same `--bin-dir` as your existing installation, such as
`/opt/my-resources/bin` for a shared installation. The installer verifies the archive
checksum before replacing the binary.

## Persist across containers

Exegol mounts your configured host `my-resources` directory inside containers at
`/opt/my-resources`. With that share enabled, install the binary there:

```sh
sh /tmp/anatoly-install.sh --version v0.2.2 --bin-dir /opt/my-resources/bin
export PATH="/opt/my-resources/bin:$PATH"
anatoly --version
```

Reapply the PATH export when opening another shell, or add it yourself to your
preferred Exegol shell customization. The installer does not modify it. Keep separate
resource directories if using containers with different CPU architectures.
See the official [my-resources documentation](https://docs.exegol.com/images/my-resources)
for the host path and customization behavior.

## HTB workflow

Ensure the container can reach the assigned lab target through your chosen VPN/network
configuration. For virtual hosts, resolve the application's hostname to its box IP and
use the hostname in the URL. Anatoly does not discover ports or configure VPN routes.

```sh
anatoly scan -u http://box.htb/ --profile thorough --no-proxy -o box.json
anatoly exposure -u http://box.htb/ --no-proxy -o exposure.json
anatoly headers -u http://box.htb/ --no-proxy
anatoly report box.json -o assessment.html
```

`--no-proxy` explicitly avoids inherited proxy settings; omit it when you intentionally
use a configured proxy. Supply the canonical scheme/host/port: cross-origin redirects,
including HTTP to HTTPS, remain blocked. TLS verification is enabled; for an authorized
private CA use `--ca-cert` with its public PEM certificate.

## Build from source

If needed on Debian-based containers, install build prerequisites yourself:

```sh
apt-get update
apt-get install -y build-essential pkg-config libssl-dev ca-certificates git
# Install Rust through https://rustup.rs if it is not present.
git clone https://github.com/lucasschimmel/anatoly.git
cd anatoly
cargo install --locked --path .
export PATH="$HOME/.cargo/bin:$PATH"
```

The repository pins Rust 1.99.0. These commands do not add Anatoly to Exegol's official
tool catalog. The tool performs bounded HTTP observations, with optional environment-based authentication
and no exploitation; unknown results require further investigation.
