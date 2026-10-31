"""Render real CLI output against deterministic loopback responses, without extra dependencies."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
PHPINFO = """<h1>PHP Version 8.4.26</h1><h2>Configuration</h2><p>PHP Credits</p>
<table><tr><td>session.upload_progress.enabled</td><td>Off</td><td>Off</td></tr>
<tr><td>memory_limit</td><td>128M</td><td>128M</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr></table>"""


class PreviewHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/proofs/":
            self.send_response(200)
            self.send_header("X-PHP-Version", "8.4.26")
            self.send_header("Set-Cookie", "PHPSESSID=DEMO_SESSION_NOT_A_REAL_VALUE; Secure; HttpOnly; SameSite=Lax")
            body = '<meta name="generator" content="WordPress 6.8"><a href="phpversion.php">PHP diagnostic</a>'
        elif self.path == "/proofs/phpversion.php":
            self.send_response(200)
            body = "8.4.26"
        elif self.path.startswith("/proofs/"):
            self.send_response(404)
            body = "Not found"
        elif self.path.startswith("/affected/"):
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.4.26")
            body = PHPINFO if self.path.endswith("phpinfo.php") else "OK"
        elif self.path.startswith("/fixed/"):
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.4.27")
            body = "OK"
        elif self.path.startswith("/hidden/"):
            self.send_response(200)
            body = "OK"
        else:
            self.send_response(403)
            body = "Forbidden"
        data = body.encode()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args: object) -> None:
        pass


def main() -> None:
    output = ROOT / "previews"
    output.mkdir(exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), PreviewHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for name in ("affected", "fixed", "hidden", "blocked", "proofs"):
            run = subprocess.run(
                [str(ROOT / "target/debug/anatoly.exe"), "scan",
                 f"http://127.0.0.1:{server.server_port}/{name}/",
                 "--no-banner", "--color", "always", "--delay-ms", "0"],
                capture_output=True, check=False,
            )
            text = run.stdout.decode("utf-8")
            (output / f"{name}.ansi").write_text(text, encoding="utf-8")
            plain = re.sub(r"\x1b\[[0-9;]*m", "", text)
            (output / f"{name}.txt").write_text(plain, encoding="utf-8")
            print(f"{name}: exit {run.returncode}, {len(plain.splitlines())} lines")
            if name == "proofs":
                lines = text.splitlines(keepends=True)
                last = next(i for i, line in enumerate(lines) if "PUBLIC HYPOTHESES" in line)
                (output / "proof-detail.ansi").write_text("".join(lines[:last]), encoding="utf-8")
        batch = subprocess.run(
            [str(ROOT / "target/debug/anatoly.exe"), "scan",
             *[f"http://127.0.0.1:{server.server_port}/{name}/"
               for name in ("affected", "fixed", "hidden", "blocked")],
             "--no-banner", "--color", "always", "--delay-ms", "0"],
            capture_output=True, check=False,
        )
        lines = batch.stdout.decode("utf-8").splitlines(keepends=True)
        first = next(i for i, line in enumerate(lines) if "SCAN SUMMARY" in line)
        summary = "".join(lines[first:])
        (output / "summary.ansi").write_text(summary, encoding="utf-8")
        (output / "summary.txt").write_text(re.sub(r"\x1b\[[0-9;]*m", "", summary), encoding="utf-8")
        print(f"batch summary: exit {batch.returncode}")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
