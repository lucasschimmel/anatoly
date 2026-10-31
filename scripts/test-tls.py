"""Exercise actual CLI TLS metadata and trust using an ephemeral loopback HTTPS server."""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def openssl_binary() -> str:
    """Locate OpenSSL without installing or changing the host configuration."""
    found = shutil.which("openssl")
    if found:
        return found
    git_openssl = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    if git_openssl.is_file():
        return str(git_openssl)
    raise RuntimeError("OpenSSL is required for this local TLS integration check")


def run_check(binary: Path) -> None:
    """Create a temporary self-signed fixture and validate success and rejection paths."""
    with tempfile.TemporaryDirectory(prefix="anatoly-tls-fixture-") as temporary:
        directory = Path(temporary)
        certificate = directory / "server.crt"
        key = directory / "server.key"
        generated = subprocess.run(
            [
                openssl_binary(), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(certificate), "-days", "2",
                "-subj", "/CN=secure.test",
                "-addext", "subjectAltName=DNS:secure.test",
                "-addext", "basicConstraints=critical,CA:TRUE",
            ],
            capture_output=True, timeout=30, check=False,
        )
        if generated.returncode:
            raise RuntimeError("Ephemeral certificate generation failed")

        class Handler(BaseHTTPRequestHandler):
            requests = 0

            def do_GET(self) -> None:
                Handler.requests += 1
                self.send_response(200)
                self.send_header("X-PHP-Version", "8.4.27")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format: str, *args: object) -> None:
                return

        class LocalServer(ThreadingHTTPServer):
            def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
                # Certificate rejection may reset the socket before an HTTP request.
                if isinstance(sys.exc_info()[1], ConnectionResetError):
                    return
                super().handle_error(request, client_address)

        server = LocalServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        target = f"https://secure.test:{server.server_port}/"
        command = [
            str(binary.resolve()), "scan", target, "--profile", "quick", "--json",
            "--no-proxy", "--resolve", "secure.test:127.0.0.1",
        ]
        try:
            trusted = subprocess.run(
                [*command, "--ca-cert", str(certificate)],
                capture_output=True, text=True, timeout=20, check=False,
            )
            if trusted.returncode:
                raise AssertionError(f"Trusted local HTTPS observation failed: {trusted.stderr}")
            report = json.loads(trusted.stdout)
            observations = report["targets"][0]["tls"]
            assert len(observations) == 1
            peer = observations[0]
            assert peer["status"] == "observed"
            assert "secure.test" in peer["subject"]
            assert "secure.test" in peer["issuer"]
            assert peer["not_before_unix"] < peer["not_after_unix"]
            assert peer["not_before_unix"] <= time.time() + 60
            assert peer["not_after_unix"] > time.time()
            assert peer["protocol"] is None
            assert report["targets"][0]["analysis"]["certified"] is False
            assert Handler.requests == 1

            rejected = subprocess.run(
                command, capture_output=True, text=True, timeout=20, check=False,
            )
            assert rejected.returncode == 3
            untrusted = json.loads(rejected.stdout)
            assert untrusted["targets"][0]["verdict"] == "error"
            assert Handler.requests == 1
            print("PASS: loopback HTTPS certificate metadata observed with explicit public CA")
            print("PASS: untrusted certificate rejected before HTTP; no external target contacted")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    default = Path(__file__).resolve().parents[1] / "target" / "debug" / "anatoly"
    if sys.platform == "win32":
        default = default.with_suffix(".exe")
    run_check(Path(sys.argv[1]) if len(sys.argv) > 1 else default)
