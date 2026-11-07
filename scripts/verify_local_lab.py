"""Verify the standalone Rust exploit/connect flow against a real local PHP container."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab" / "local_lab.py"
BINARY = ROOT / "target" / "debug" / ("anatoly.exe" if os.name == "nt" else "anatoly")


def run(
    args: list[str], timeout: float = 900, cwd: Path = ROOT
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
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
parser.add_argument(
    "--composed",
    action="store_true",
    help="also verify the multi-stage composed-command transport",
)
args = parser.parse_args()

run([cargo, "build", "--bin", "anatoly"])
try:
    run([sys.executable, LAB, "up", "--php-version", args.php_version])
    target = "http://127.0.0.1:18108/index.php"
    with tempfile.TemporaryDirectory(prefix="anatoly-standalone-") as directory:
        isolated = Path(directory)
        standalone = isolated / BINARY.name
        shutil.copy2(BINARY, standalone)
        # The copied executable runs outside the checkout: no lab assets, Python,
        # source tree, shared proof volume, or helper process is available to it.
        run([standalone, "--no-banner", "exploit", "-u", target], timeout=650, cwd=isolated)
        run(
            [standalone, "--no-banner", "connect", "-u", target, "--command", "whoami"],
            timeout=650,
            cwd=isolated,
        )
        if args.composed:
            run(
                [
                    standalone,
                    "--no-banner",
                    "connect",
                    "-u",
                    target,
                    "--command",
                    "printf standalone && whoami",
                ],
                timeout=1200,
                cwd=isolated,
            )
    print(
        f"REAL STANDALONE RUST CLI FLOW OK: PHP {args.php_version} Docker -> exploit "
        f"-> connect -> fresh command output (composed={args.composed})"
    )
finally:
    run([sys.executable, LAB, "down"], timeout=60)
