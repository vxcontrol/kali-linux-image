#!/opt/venv/bin/python3
"""Render the shipped gateway template into the config agentgateway loads.

Invariants this script exists to hold:

  * The bearer token is NEVER written to disk. agentgateway accepts either a
    literal `key` or a `keyHash: sha256:<hex>`; we always emit the hash, so a
    reader of /run/kali-mcp/gateway.yaml (or of a `docker cp`, or of a crash
    dump) cannot recover the token.
  * The rendered config only ever names servers that exist. Disabling a server
    removes its target; it never leaves a dangling reference behind.
  * Rendering fails loudly. A template that no longer contains the placeholder,
    or an unknown name in KALI_MCP_DISABLE, is a configuration error and must
    stop the container rather than quietly produce a gateway with no auth or
    with fewer tools than the operator asked for.

Reads:  argv[1] template path, argv[2] output path.
Env:    MCP_GATEWAY_TOKEN, MCP_GATEWAY_PORT, MCP_GATEWAY_USE_TLS,
        MCP_GATEWAY_TLS_CERT, MCP_GATEWAY_TLS_KEY, KALI_MCP_DISABLE,
        MSF_PASSWORD, BURP_MCP_URL, BURP_MCP_TRANSPORT, BURP_LOCAL,
        BURP_MCP_PROXY_JAR, BURP_MCP_SSE_URL.
"""

import hashlib
import os
import sys

import yaml

TOKEN_PLACEHOLDER = "sha256:__MCP_GATEWAY_TOKEN_SHA256__"


def die(message: str) -> None:
    print(f"kali-mcp: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 3:
        die("usage: render-config.py <template> <output>")
    template_path, output_path = sys.argv[1], sys.argv[2]

    with open(template_path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    mcp = config.get("mcp")
    if not isinstance(mcp, dict):
        die(f"{template_path}: no top-level 'mcp' block")

    # --- auth ---------------------------------------------------------------
    token = os.environ.get("MCP_GATEWAY_TOKEN", "")
    if not token:
        # entrypoint.sh checks this first and with a friendlier message; this is
        # the backstop for anyone invoking the renderer directly.
        die("MCP_GATEWAY_TOKEN is empty; refusing to render an unauthenticated gateway")

    keys = mcp.get("policies", {}).get("apiKey", {}).get("keys")
    if not keys or keys[0].get("keyHash") != TOKEN_PLACEHOLDER:
        die(
            f"{template_path}: expected policies.apiKey.keys[0].keyHash == "
            f"{TOKEN_PLACEHOLDER!r}; the template has drifted and the rendered "
            "gateway would not be protected by MCP_GATEWAY_TOKEN"
        )
    if len(keys) != 1:
        # A second key would be a credential nobody passed in and nobody can
        # rotate -- a backdoor into every tool behind the gateway.
        die(f"{template_path}: policies.apiKey.keys must hold exactly one key, found {len(keys)}")
    if mcp["policies"]["apiKey"].get("mode") != "strict":
        die(f"{template_path}: policies.apiKey.mode must be 'strict'")
    keys[0]["keyHash"] = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()

    # --- listen port --------------------------------------------------------
    port_raw = os.environ.get("MCP_GATEWAY_PORT", "8081")
    try:
        port = int(port_raw)
    except ValueError:
        die(f"MCP_GATEWAY_PORT={port_raw!r} is not a number")
    if not 1 <= port <= 65535:
        die(f"MCP_GATEWAY_PORT={port} is out of range")
    mcp["port"] = port

    # --- public TLS --------------------------------------------------------
    tls_raw = os.environ.get("MCP_GATEWAY_USE_TLS", "true").strip().lower()
    if tls_raw in {"1", "true", "yes", "y", "on"}:
        cert = os.environ.get("MCP_GATEWAY_TLS_CERT", "").strip()
        key = os.environ.get("MCP_GATEWAY_TLS_KEY", "").strip()
        if not cert or not key:
            die("TLS is enabled but MCP_GATEWAY_TLS_CERT or MCP_GATEWAY_TLS_KEY is empty")
        if not os.path.isfile(cert):
            die(f"TLS certificate {cert} does not exist")
        if not os.path.isfile(key):
            die(f"TLS key {key} does not exist")

        # agentgateway 1.5 rejects mcp.tls. TLS belongs to a modern gateway;
        # the simplified MCP backend attaches to it by name.
        mcp.pop("port")
        mcp["gateways"] = ["default"]
        config["gateways"] = {
            "default": {
                "port": port,
                "tls": {"cert": cert, "key": key},
            }
        }
    elif tls_raw not in {"0", "false", "no", "n", "off"}:
        die(f"MCP_GATEWAY_USE_TLS={tls_raw!r} must be true or false")

    targets = mcp.get("targets") or []
    # burp is appended below (local stdio proxy or remote URL) and is not in
    # the template, but KALI_MCP_DISABLE=burp must still be a known name.
    known = {target["name"] for target in targets} | {"burp"}

    # --- msfrpcd credential -------------------------------------------------
    # Generated per container start by entrypoint.sh, so it cannot be baked in.
    msf_password = os.environ.get("MSF_PASSWORD", "")
    for target in targets:
        if target["name"] == "metasploit" and msf_password:
            target["stdio"].setdefault("env", {})["MSF_PASSWORD"] = msf_password

    # --- opt-out ------------------------------------------------------------
    disabled = {
        name.strip()
        for name in os.environ.get("KALI_MCP_DISABLE", "").split(",")
        if name.strip()
    }
    unknown = sorted(disabled - known)
    if unknown:
        die(
            f"KALI_MCP_DISABLE names unknown server(s): {', '.join(unknown)}; "
            f"known servers are: {', '.join(sorted(known))}"
        )
    targets = [target for target in targets if target["name"] not in disabled]

    # --- Burp Suite: remote URL, or in-container stdio proxy -----------------
    burp_url = os.environ.get("BURP_MCP_URL", "").strip()
    burp_local = os.environ.get("BURP_LOCAL", "").strip().lower() in {"1", "true", "yes", "y"}
    if "burp" not in disabled:
        if burp_url:
            transport = os.environ.get("BURP_MCP_TRANSPORT", "mcp").strip().lower()
            if transport not in ("mcp", "sse"):
                die(f"BURP_MCP_TRANSPORT={transport!r} must be 'mcp' or 'sse'")
            targets.append({"name": "burp", transport: {"host": burp_url}})
        elif burp_local:
            proxy = os.environ.get("BURP_MCP_PROXY_JAR", "/opt/burp/mcp-proxy-all.jar")
            if not os.path.isfile(proxy):
                die(f"BURP_LOCAL is set but the stdio proxy {proxy} is missing")
            sse_url = os.environ.get("BURP_MCP_SSE_URL", "http://127.0.0.1:9876").strip()
            java = "/usr/bin/java" if os.path.isfile("/usr/bin/java") else "java"
            targets.append(
                {
                    "name": "burp",
                    "stdio": {
                        "cmd": java,
                        "args": ["-jar", proxy, "--sse-url", sse_url],
                        # Burp's loopback-only SSE endpoint has no auth and
                        # ignores this header. Supplying an explicit local key
                        # keeps the official proxy from probing the plain-HTTP
                        # endpoint for OAuth metadata and emitting misleading
                        # "no authentication" / insecure OAuth warnings.
                        "env": {"MCP_API_KEY": "local-loopback-no-auth"},
                    },
                }
            )

    if not targets:
        die("every MCP server is disabled; the gateway would expose no tools")
    mcp["targets"] = targets

    # --- write --------------------------------------------------------------
    # 0600 before any content is written: the file holds the token hash and the
    # msfrpcd password, and must never be briefly world-readable.
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False, default_flow_style=False)

    print(
        "kali-mcp: rendered "
        f"{len(targets)} MCP server(s) on "
        f"{'HTTPS' if tls_raw in {'1', 'true', 'yes', 'y', 'on'} else 'HTTP'} "
        f"port {port}: "
        + ", ".join(target["name"] for target in targets),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
