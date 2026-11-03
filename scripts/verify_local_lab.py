"""Build Anatoly, verify the real Rust exploit/connect flow, and tear down the lab."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab" / "local_lab.py"
BINARY = ROOT / "target" / "debug" / ("anatoly.exe" if os.name == "nt" else "anatoly")


def run(args: list[str], timeout: float = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        check=True,
        text=True,
        timeout=timeout,
        shell=False,
    )


cargo = shutil.which("cargo")
if not cargo:
    candidate = Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
    if not candidate.is_file():
        raise SystemExit("Cargo not found; install the pinned Rust toolchain first")
    cargo = str(candidate)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--php-version", default="8.4.26")
args = parser.parse_args()

run([cargo, "build", "--bin", "anatoly"])
try:
    run([sys.executable, LAB, "up", "--php-version", args.php_version])
    target = "http://127.0.0.1:18108/index.php"
    run([BINARY, "--no-banner", "exploit", "-u", target, "--lab"], timeout=650)
    run(
        [BINARY, "--no-banner", "connect", "-u", target, "--lab", "--command", "whoami"],
        timeout=650,
    )
    print(
        f"REAL RUST CLI FLOW OK: PHP {args.php_version} Docker -> exploit -> connect "
        "-> fresh whoami output"
    )
finally:
    run([sys.executable, LAB, "down"], timeout=60)
