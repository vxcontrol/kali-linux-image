#!/usr/bin/env python3
"""Deterministic HTTP target used by smoke-test.sh.

It runs in a separate container so raw scanners traverse a real container
network instead of scanning the gateway itself.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    server_version = "KaliMcpSmoke/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/admin":
            body = b"kali-mcp-admin-fixture\n"
            status = 200
        elif parsed.path == "/echo":
            value = parse_qs(parsed.query).get("id", [""])[0]
            body = f"kali-mcp-echo:{value}\n".encode()
            status = 200
        elif parsed.path == "/":
            body = b"<html><title>Kali MCP smoke target</title></html>\n"
            status = 200
        else:
            body = b"kali-mcp-not-found\n"
            status = 404

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Kali-MCP-Smoke", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 18080), Handler).serve_forever()
