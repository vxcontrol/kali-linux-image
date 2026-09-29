#!/usr/bin/env python3
"""Tests for generated and operator-provided MCP TLS certificates."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "setup-tls.sh"


class SetupTlsTests(unittest.TestCase):
    def run_setup(
        self, home: Path, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ["PATH"],
            "KALI_MCP_HOME": str(home),
            "MCP_GATEWAY_USE_TLS": "true",
            "MCP_GATEWAY_TLS_CERT": "ssl/server.crt",
            "MCP_GATEWAY_TLS_KEY": "ssl/server.key",
            "MCP_GATEWAY_IP": "10.100.1.3",
        }
        env.update(extra_env or {})
        return subprocess.run(
            ["bash", str(SCRIPT)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_generates_and_reuses_certificate_with_public_ip_san(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            first = self.run_setup(home)
            self.assertEqual(first.returncode, 0, first.stderr)

            cert = home / "ssl/server.crt"
            key = home / "ssl/server.key"
            ca = home / "ssl/service_ca.crt"
            self.assertTrue(cert.is_file())
            self.assertTrue(key.is_file())
            self.assertTrue(ca.is_file())
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(cert.stat().st_mode & 0o777, 0o644)
            self.assertEqual(ca.stat().st_mode & 0o777, 0o644)
            self.assertGreater(cert.read_text().count("BEGIN CERTIFICATE"), 1)

            details = subprocess.run(
                ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            self.assertIn("IP Address:10.100.1.3", details)
            self.assertIn("DNS:kali-mcp", details)

            before = (cert.stat().st_mtime_ns, key.stat().st_mtime_ns)
            second = self.run_setup(home)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("using existing TLS certificate", second.stderr)
            self.assertEqual(before, (cert.stat().st_mtime_ns, key.stat().st_mtime_ns))

    def test_accepts_operator_provided_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cert = home / "custom/certificate.pem"
            key = home / "private/key.pem"
            cert.parent.mkdir()
            key.parent.mkdir()
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=provided.example",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            original = (cert.read_bytes(), key.read_bytes())
            result = self.run_setup(
                home,
                {
                    "MCP_GATEWAY_TLS_CERT": str(cert),
                    "MCP_GATEWAY_TLS_KEY": str(key),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(original, (cert.read_bytes(), key.read_bytes()))

    def test_rejects_partial_pair_and_invalid_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cert = home / "ssl/server.crt"
            cert.parent.mkdir()
            cert.write_text("not a certificate", encoding="utf-8")
            partial = self.run_setup(home)
            self.assertNotEqual(partial.returncode, 0)
            self.assertIn("must both exist", partial.stderr)

            invalid = self.run_setup(
                home, {"MCP_GATEWAY_USE_TLS": "sometimes"}
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("must be true or false", invalid.stderr)

    def test_rejects_mismatched_certificate_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cert = home / "provided.crt"
            matching_key = home / "matching.key"
            wrong_key = home / "wrong.key"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "1", "-subj", "/CN=provided",
                    "-keyout", str(matching_key), "-out", str(cert),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            subprocess.run(
                ["openssl", "genrsa", "-out", str(wrong_key), "2048"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            result = self.run_setup(
                home,
                {
                    "MCP_GATEWAY_TLS_CERT": str(cert),
                    "MCP_GATEWAY_TLS_KEY": str(wrong_key),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("do not match", result.stderr)

    def test_disabled_tls_does_not_create_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            result = self.run_setup(
                home, {"MCP_GATEWAY_USE_TLS": "false"}
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((home / "ssl").exists())


if __name__ == "__main__":
    unittest.main()
