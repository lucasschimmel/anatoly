#!/usr/bin/env python3
"""Lifecycle manager for Anatoly's loopback-only PHP Docker lab.

Exploit and connect are implemented by the Rust CLI. This script only builds,
starts, inspects and removes their disposable local target.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen

LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
DOCKER_DIR = LAB_DIR / "docker"
DEFAULT_TARGET = "http://127.0.0.1:18108/index.php"
CONTAINER = "anatoly-php2shell-lab"
NETWORK = "anatoly-php2shell-net"
FIX_FLOORS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PINNED_IMAGES = {
    "8.4.26": "php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
}


def php_version(value: str) -> str:
    match = re.fullmatch(r"(8)\.(2|3|4|5)\.(\d+)", value)
    if not match:
        raise argparse.ArgumentTypeError("Use an exact upstream PHP version such as 8.4.26")
    major, minor, patch = int(match[1]), int(match[2]), int(match[3])
    if patch >= FIX_FLOORS[(major, minor)]:
        raise argparse.ArgumentTypeError(f"PHP {value} is not in the affected upstream range")
    return value


class LabError(RuntimeError):
    """An operator-facing lab error."""


def find_docker() -> str:
    executable = shutil.which("docker")
    candidates = [
        Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
        Path.home() / r"AppData\Local\Programs\Docker\Docker\resources\bin\docker.exe",
        Path.home() / r"AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe",
    ]
    if executable:
        return executable
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise LabError(
        "Docker CLI not found. Install/start Docker Desktop, open a new terminal, then retry."
    )


def run_process(
    args: list[str], *, timeout: float, check: bool = True
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if Path(args[0]).name.lower() in ("docker", "docker.exe"):
        docker_bin = str(Path(args[0]).resolve().parent)
        env["PATH"] = docker_bin + os.pathsep + env.get("PATH", "")
    try:
        result = subprocess.run(
            args,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LabError(f"Command failed or timed out: {error}") from error
    if check and result.returncode != 0:
        raise LabError(f"Command exited with status {result.returncode}:\n{result.stdout}")
    return result


def docker_ready(docker: str) -> None:
    result = run_process([docker, "info", "--format", "{{.ServerVersion}}"], timeout=20, check=False)
    if result.returncode != 0:
        raise LabError(
            "Docker daemon unavailable. Start Docker Desktop and wait until it is ready.\n"
            + result.stdout
        )


def lab_up(version: str = "8.4.26") -> None:
    docker = find_docker()
    docker_ready(docker)
    if not DOCKER_DIR.is_dir():
        raise LabError("Lab Docker configuration files are missing in lab/docker/")
    source_image = PINNED_IMAGES.get(version, f"php:{version}-apache")
    image = f"anatoly-php2shell:{version}"
    for proof_name in ("p", "s", "o", "x", "f", "q", "r"):
        (DOCKER_DIR / "webroot" / proof_name).unlink(missing_ok=True)
    run_process([docker, "rm", "--force", CONTAINER], timeout=20, check=False)
    run_process([docker, "network", "rm", NETWORK], timeout=20, check=False)
    print(f"[*] Building PHP {version} Apache from {source_image}…", flush=True)
    run_process(
        [
            docker,
            "build",
            "--platform",
            "linux/amd64",
            "--build-arg",
            f"PHP_IMAGE={source_image}",
            "--tag",
            image,
            str(DOCKER_DIR),
        ],
        timeout=900,
    )
    run_process([docker, "network", "create", NETWORK], timeout=30)
    run_process(
        [
            docker,
            "run",
            "--detach",
            "--name",
            CONTAINER,
            "--network",
            NETWORK,
            "--publish",
            "127.0.0.1:18108:80",
            "--platform",
            "linux/amd64",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "1g",
            "--volume",
            f"{DOCKER_DIR / 'webroot'}:/var/www/html",
            "--volume",
            f"{DOCKER_DIR / 'php.ini'}:/usr/local/etc/php/conf.d/zz-lab.ini:ro",
            "--volume",
            f"{DOCKER_DIR / 'apache.conf'}:/etc/apache2/conf-enabled/zz-lab.conf:ro",
            image,
        ],
        timeout=30,
    )
    for _ in range(60):
        try:
            with urlopen(DEFAULT_TARGET, timeout=2) as response:
                if response.status == 200 and b"OK" in response.read(4096):
                    print(f"[+] Real PHP {version} lab ready on {DEFAULT_TARGET}")
                    print("[+] Published on loopback only; dedicated Docker bridge attached.")
                    return
        except OSError:
            time.sleep(1)
    run_process([docker, "logs", CONTAINER], timeout=20, check=False)
    lab_down()
    raise LabError("The container started but the HTTP endpoint did not become ready")


def lab_down() -> None:
    docker = find_docker()
    run_process([docker, "rm", "--force", CONTAINER], timeout=30, check=False)
    run_process([docker, "network", "rm", NETWORK], timeout=30, check=False)
    print("[+] Anatoly lab container and network removed")


def lab_status() -> None:
    docker = find_docker()
    docker_ready(docker)
    result = run_process(
        [docker, "ps", "--all", "--filter", f"name=^{CONTAINER}$", "--format", "{{.Status}}"],
        timeout=20,
    )
    print(result.stdout.strip() or "Lab container not found")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Anatoly loopback-only Docker lab lifecycle")
    parser.add_argument("mode", choices=("up", "down", "status"))
    parser.add_argument("--php-version", type=php_version, default="8.4.26")
    args = parser.parse_args(argv)
    try:
        if args.mode == "up":
            lab_up(args.php_version)
        elif args.mode == "down":
            lab_down()
        else:
            lab_status()
        return 0
    except LabError as error:
        print(f"anatoly local lab: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
