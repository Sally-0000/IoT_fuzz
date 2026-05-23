from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def run_http_callback(host: str, port: int, log_path: str) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._record()

        def do_POST(self) -> None:
            self._record()

        def _record(self) -> None:
            row = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
            }
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            print(f"{self.client_address[0]} {self.command} {self.path}")

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"listening on http://{host}:{port}, logging to {path}", flush=True)
    server.serve_forever()
