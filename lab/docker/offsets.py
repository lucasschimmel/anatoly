#!/usr/bin/env python3
"""Derive libphp symbol offsets from the exact running Anatoly lab container."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from local_lab import LabError, find_docker, run_process  # noqa: E402


def symbol_offset(docker: str, container: str, symbol: str) -> int:
    result = run_process(
        [docker, "exec", container, "nm", "-a", "/usr/lib/apache2/modules/libphp.so"],
        timeout=60,
    )
    matches = []
    for line in result.stdout.splitlines():
        fields = line.strip().split()
        if len(fields) == 3 and fields[2] == symbol:
            matches.append(int(fields[0], 16))
    if len(matches) != 1 or matches[0] <= 0:
        raise LabError(f"Expected one {symbol} symbol in the running libphp.so")
    return matches[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("container")
    parser.add_argument("output", type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-zif", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--expected-dtor", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args(argv)
    try:
        docker = find_docker()
        version = run_process(
            [docker, "exec", args.container, "php", "-r", "echo PHP_VERSION;"],
            timeout=20,
        ).stdout.strip()
        if version != args.expected_version:
            raise LabError(
                f"Running PHP {version!r} does not match selected profile {args.expected_version!r}"
            )
        image = run_process(
            [docker, "inspect", "--format", "{{.Image}}", args.container],
            timeout=20,
        ).stdout.strip()
        if not image.startswith("sha256:"):
            raise LabError("Cannot establish the running container image identity")
        values = {
            "ZIF_OFFSET": symbol_offset(docker, args.container, "zif_system"),
            "DTOR_OFFSET": symbol_offset(docker, args.container, "zval_ptr_dtor"),
        }
        expected = {
            "ZIF_OFFSET": args.expected_zif,
            "DTOR_OFFSET": args.expected_dtor,
        }
        if values != expected:
            raise LabError(
                "Running libphp symbols do not match the verified build profile: "
                + " ".join(
                    f"{name}=0x{values[name]:x} (expected 0x{expected[name]:x})"
                    for name in values
                )
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(
            f"# PHP_VERSION={version}\n# IMAGE_ID={image}\n"
            + "".join(f"{name}=0x{value:x}\n" for name, value in values.items()),
            encoding="ascii",
            newline="\n",
        )
        os.replace(temporary, args.output)
        print(
            f"CALIBRATED PHP {version} {image} "
            + " ".join(f"{name}=0x{value:x}" for name, value in values.items())
        )
        return 0
    except (LabError, OSError, ValueError) as error:
        print(f"anatoly profile calibration: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
