#!/usr/bin/env python3
"""Renderer checks for the local Burp stdio target and KALI_MCP_DISABLE=burp."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import importlib.util

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("render_config", ROOT / "render-config.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _template() -> str:
    return (ROOT / "gateway.yaml").read_text(encoding="utf-8")


def _render(env: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "in.yaml"
        dst = Path(tmp) / "out.yaml"
        src.write_text(_template(), encoding="utf-8")
        effective_env = {"MCP_GATEWAY_USE_TLS": "false", **env}
        with mock.patch.dict(os.environ, effective_env, clear=True):
            with mock.patch("sys.argv", ["render-config.py", str(src), str(dst)]):
                MODULE.main()
        return yaml.safe_load(dst.read_text(encoding="utf-8"))


class RenderConfigTests(unittest.TestCase):
    def test_tls_uses_modern_gateway(self) -> None:
        with (
            tempfile.NamedTemporaryFile(suffix=".crt") as cert,
            tempfile.NamedTemporaryFile(suffix=".key") as key,
        ):
            config = _render(
                {
                    "MCP_GATEWAY_TOKEN": "0123456789abcdef",
                    "MCP_GATEWAY_PORT": "8443",
                    "MCP_GATEWAY_USE_TLS": "true",
                    "MCP_GATEWAY_TLS_CERT": cert.name,
                    "MCP_GATEWAY_TLS_KEY": key.name,
                }
            )
        self.assertNotIn("port", config["mcp"])
        self.assertEqual(config["mcp"]["gateways"], ["default"])
        self.assertEqual(
            config["gateways"]["default"],
            {
                "port": 8443,
                "tls": {"cert": cert.name, "key": key.name},
            },
        )

    def test_disable_burp_is_a_known_name(self) -> None:
        config = _render(
            {
                "MCP_GATEWAY_TOKEN": "0123456789abcdef",
                "KALI_MCP_DISABLE": "burp",
            }
        )
        names = [target["name"] for target in config["mcp"]["targets"]]
        self.assertNotIn("burp", names)

    def test_local_burp_is_stdio_proxy(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jar") as proxy:
            config = _render(
                {
                    "MCP_GATEWAY_TOKEN": "0123456789abcdef",
                    "BURP_LOCAL": "1",
                    "BURP_MCP_PROXY_JAR": proxy.name,
                    "BURP_MCP_SSE_URL": "http://127.0.0.1:9876",
                }
            )
        burp = next(target for target in config["mcp"]["targets"] if target["name"] == "burp")
        self.assertEqual(burp["stdio"]["args"][-2:], ["--sse-url", "http://127.0.0.1:9876"])
        self.assertEqual(burp["stdio"]["env"], {"MCP_API_KEY": "local-loopback-no-auth"})

    def test_remote_url_wins_over_local(self) -> None:
        config = _render(
            {
                "MCP_GATEWAY_TOKEN": "0123456789abcdef",
                "BURP_LOCAL": "1",
                "BURP_MCP_URL": "http://192.0.2.10:9876",
                "BURP_MCP_TRANSPORT": "sse",
            }
        )
        burp = next(target for target in config["mcp"]["targets"] if target["name"] == "burp")
        self.assertEqual(burp["sse"]["host"], "http://192.0.2.10:9876")
        self.assertNotIn("stdio", burp)


if __name__ == "__main__":
    unittest.main()
