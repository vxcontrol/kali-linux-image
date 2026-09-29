# kali-mcp

`vxcontrol/kali-linux` with an MCP gateway on top: **one HTTPS endpoint, one bearer token**.

A default token-only run exposes **14 MCP servers (~126 tools)** wrapping the penetration-testing binaries the base image already ships. Setting `BURP_ACCEPT_EULA=true` adds **Burp Suite** (Community, headless in the same container) as a 15th server, for **~150 tools in one session**.

An agent points at `https://<host>:8081/mcp`, sends the token, and gets nmap, metasploit, nuclei, sqlmap, ffuf, masscan, whatweb, hashcat, binwalk, searchsploit, tshark, waybackurls, the ProjectDiscovery chain, a real Chromium browser, and Burp's official MCP tools in one session.

```
                     ┌──────────────────────── container ──────────────────────────┐
  MCP client         │                                                             │
  ──────────────────►│  agentgateway :8081/mcp    ──stdio──►  nmap-mcp   → nmap    │
  Authorization:     │  ├─ apiKey (strict)        ──stdio──►  nuclei-mcp → nuclei  │
  Bearer <token>     │  ├─ multiplex 15 targets   ──stdio──►  msf-mcp ──► msfrpcd  │
                     │  └─ tool names prefixed    ──stdio──►  playwright→ chromium │
                     │                            ──stdio──►  … 10 more            │
                     └─────────────────────────────────────────────────────────────┘
```

---

## Quick start

The `mcp` image is a stage of the project's root `Dockerfile` and is built with Docker Buildx Bake **from the repository root** (one directory up), not from here. `WITH_BURP` bakes Burp Suite plus the official MCP BApp into the image (~700MB) and defaults to true.

Once you’re in the repo root directory, you can build the MCP image:

```bash
# From the repository ROOT:
docker buildx bake mcp --set="mcp.tags=local/kali-linux:mcp" --load
```

Alternatively, use a traditional build:

```bash
# Alternative: traditional docker buildx build (also from the repo root)
docker buildx build --target mcp --load -t local/kali-linux:mcp .
```

Or pull the published image from Docker Hub instead of building it:

```bash
docker pull vxcontrol/kali-linux:mcp
```

To run the container:

```bash
docker run -d --name kali-mcp \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e MCP_GATEWAY_TOKEN="$(openssl rand -hex 32)" \
  -e MCP_GATEWAY_IP=127.0.0.1 \
  -v kali-mcp-ssl:/opt/kali-mcp/ssl \
  -p 127.0.0.1:8081:8081 \
  vxcontrol/kali-linux:mcp
```

The container will **refuse to start without a token**. This is intentional: the endpoint allows remote code execution for anyone who can reach the port. For this reason, publishing is bound to loopback; using `-p 8081:8081` (without specifying an address) would expose it on every host interface.

To interact with the MCP container, first set your token (the same one you provided above), then copy the CA certificate from the container:

```bash
TOKEN=...   # the same value you passed in
docker cp kali-mcp:/opt/kali-mcp/ssl/service_ca.crt ./kali-mcp-ca.crt
```

You can now make a request:

```bash
curl --cacert ./kali-mcp-ca.crt -sS -X POST https://127.0.0.1:8081/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"you","version":"1"}}}'
```

The `initialize` method returns an `mcp-session-id` header; include this header for subsequent calls to `tools/list` and `tools/call`. The script `./smoke-test.sh` performs the full handshake and runs a test command for each server.

To use with Claude Code or Claude Desktop, apply this configuration:

```json
{
  "mcpServers": {
    "kali": {
      "type": "http",
      "url": "https://127.0.0.1:8081/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

---

## The gateway

[**agentgateway**](https://github.com/agentgateway/agentgateway) v1.5.0 is used here, pinned by SHA-256 and installed as a static binary (no Rust toolchain needed in the image).

This gateway was chosen for several reasons:

- **It merges targets into one virtual MCP server.** A client connects once, to `/mcp`, and sees all 150 tools. Route-per-server proxies (like `tbxark/mcp-proxy` and similar alternatives) would require 14 separate client connections.
- **Static bearer-token authentication from config.** The gateway's `apiKey` policy in `strict` mode takes either the raw key or a SHA-256 hash. Other gateways that only support OAuth 2.1 / OIDC (like `1mcp` or agentgateway's own `mcpAuthentication`) can't be managed from a single environment variable.
- **Stdio-to-HTTP bridging.** All servers behind the gateway communicate via stdio; agentgateway spawns each as a subprocess, and it is the only process on the network.

Here are the relevant gateway endpoints:

| | |
|---|---|
| Aggregated MCP endpoint | `:8081/mcp` (streamable HTTPS), `:8081/sse` (HTTPS SSE) — **auth required** |
| Readiness | `:15021/healthz/ready` — no auth, used by `HEALTHCHECK` |
| Metrics | `:15020/metrics` — no auth |
| Admin UI | `:15000/ui` — bound to loopback inside the container |

Only port `8081` is exposed. **Do not publish ports 15000, 15020, or 15021**; these interfaces are intentionally unauthenticated (a healthcheck shouldn't need a secret), and publishing them could leak your server names.

### How the token is applied

1. `MCP_GATEWAY_TOKEN` (or the contents of `MCP_GATEWAY_TOKEN_FILE`) is read by `entrypoint.sh`. Missing or shorter than 16 characters → **exit 1**, no gateway, no listener.
2. `setup-tls.sh` validates the configured certificate and key or generates them in the SSL volume.
3. `render-config.py` writes `/run/kali-mcp/gateway.yaml` (mode `0600`) with `keyHash: sha256:<hex of the token>`. **The token itself is never written to disk** — not in the image, not in `/run`, not in a log line.
4. The `apiKey` policy sits on the single MCP route, so the one token gates *every* server behind the gateway. There is no per-server token to get wrong and no way to reach one server without it.

Requests without a token, or with an incorrect one, receive a `401` response before any MCP protocol parsing occurs.

---

## What is included

Tool counts are taken from an actual `tools/list` request against the built image. Every tool is prefixed with its server name (such as `nmap_port_scan`, `nuclei_quick_scan`, etc.), ensuring that names never collide.

| Server | Tools | Wraps | Upstream | Transport |
|---|--:|---|---|---|
| `nmap` | 7 | `nmap` | [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) `reconnaissance/nmap-mcp` | stdio |
| `masscan` | 4 | `masscan` | same repo, `reconnaissance/masscan-mcp` | stdio |
| `whatweb` | 3 | `whatweb` | same repo, `reconnaissance/whatweb-mcp` | stdio |
| `nuclei` | 6 | `nuclei` | same repo, `web-security/nuclei-mcp` | stdio |
| `sqlmap` | 6 | `sqlmap` | same repo, `web-security/sqlmap-mcp` | stdio |
| `ffuf` | 7 | `ffuf` | same repo, `web-security/ffuf-mcp` | stdio |
| `waybackurls` | 3 | `waybackurls` | same repo, `web-security/waybackurls-mcp` | stdio |
| `searchsploit` | 3 | `searchsploit` / exploit-db | same repo, `exploitation/searchsploit-mcp` | stdio |
| `binwalk` | 7 | `binwalk`, `xxd` | same repo, `binary-analysis/binwalk-mcp` | stdio |
| `metasploit` | 12 | `msfrpcd`, `msfvenom` | [GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) | stdio → MSF RPC |
| `playwright` | 24 | Chromium | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) `0.0.80` | stdio |
| `hashcat` | 23 | `hashcat` | [MorDavid/hashcat-mcp](https://github.com/MorDavid/hashcat-mcp) | stdio |
| `tshark` | 14 | `tshark`, `dumpcap` | [khuynh22/mcp-wireshark](https://github.com/khuynh22/mcp-wireshark) `0.5.0` (PyPI) | stdio |
| `pdtools` | 7 | `subfinder` `dnsx` `naabu` `httpx` `katana` `nuclei` | [intelligent-ears/pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp) | stdio |
| `burp` | 24 | Burp Suite Community + official MCP BApp | [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) `v1.3.0` | stdio proxy → loopback SSE |

Every upstream is pinned to an exact commit or version in the repository's root `Dockerfile` (the `mcp` stage).

### What each server exposes

**`nmap`** — Exposes `port_scan`, `service_scan`, `os_detection`, `script_scan` (NSE), `quick_scan`, plus `get_scan_results` and `list_active_scans`. Results are parsed from nmap's XML into JSON.

**`masscan`** — Provides `masscan_scan`, `masscan_top_ports` and result retrieval. Always requires `NET_RAW`.  
**Known environment issue:** Under Docker Desktop on macOS, masscan's raw-socket transmit stalls—a 20-port scan that finishes in 5s one run may hang past 5 minutes the next. This behavior is identical on the unmodified `vxcontrol/kali-linux` base image, indicating the issue is with masscan versus a userspace VM network stack, not this layer. Passing `--wait 1` (via `extra_args`) helps; on a Linux host it behaves normally. `nmap` is the reliable scanner here.

**`whatweb`** — Performs technology and CMS fingerprinting of a URL.

**`nuclei`** — Offers `nuclei_scan`, `quick_scan` (for high/critical CVE tags), `template_scan` by tag, and `list_templates`. The image includes 13,619 baked templates; a `quick_scan` reports "Templates loaded for current scan: 2703".

**`sqlmap`** — Supports `sql_test`, `sql_scan`, `sql_enumerate`, and `sql_dump`. Runs sqlmap with `--batch`, so it never blocks on a prompt.

**`ffuf`** — Includes `ffuf_dir`, `ffuf_vhost`, `ffuf_param`, `ffuf_custom`, and `list_wordlists` over Kali's `/usr/share/wordlists`.

**`waybackurls`** — Fetches historical URLs for a host from the Wayback Machine (requires outbound internet access).

**`searchsploit`** — Performs offline Exploit-DB search and can use `searchsploit_examine` to retrieve an exploit’s source.

**`binwalk`** — Provides signature scan, entropy analysis, extraction, and hexdump.

**`metasploit`** — Features `list_exploits`, `list_payloads`, `run_exploit`, `run_auxiliary_module`, `run_post_module`, `generate_payload`, as well as session management (`list_active_sessions`, `send_session_command`, `terminate_session`) and handlers (`start_listener`, `list_listeners`, `stop_job`).

**`playwright`** — A real browser: exposes `browser_navigate`, `browser_snapshot` (accessibility tree, not pixels), `browser_click`, `browser_type`, `fill_form`, `browser_network_requests`, `browser_console_messages`, `browser_take_screenshot`, `browser_evaluate`, tab management, dialog handling, and file uploads.

**`hashcat`** — Provides hash identification (`identify_hash`, `smart_identify_hash`, `search_hash_types`), `crack_hash`, `crack_multiple_hashes`, mask and rule generation, keyspace and time estimation, session tracking, and backend info.

**`tshark`** — Offers `read_pcap`, `display_filter`, `summarize_pcap`, `follow_tcp`, `follow_udp`, `expert_info`, `decode_protocol`, `protocol_stats`, `export_json`, and `live_capture` (requires `NET_RAW`).

**`pdtools`** — Exposes each ProjectDiscovery tool individually, plus a `bug_bounty_workflow` which chains subfinder → dnsx → naabu → httpx → katana → nuclei.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MCP_GATEWAY_TOKEN` | *(none)* | **Required.** Bearer token. ≥16 characters. |
| `MCP_GATEWAY_TOKEN_FILE` | *(none)* | Read the token from this file instead (docker/k8s secrets). Takes precedence. |
| `MCP_GATEWAY_PORT` | `8081` | Port the aggregated MCP endpoint listens on. |
| `MCP_GATEWAY_USE_TLS` | `true` | Serve MCP over HTTPS. `false` explicitly restores plaintext HTTP. |
| `MCP_GATEWAY_TLS_CERT` | `/opt/kali-mcp/ssl/server.crt` | Certificate path inside the container. Generated when both certificate and key are absent. |
| `MCP_GATEWAY_TLS_KEY` | `/opt/kali-mcp/ssl/server.key` | Private-key path inside the container. Must match the certificate. |
| `MCP_GATEWAY_TLS_CA` | `/opt/kali-mcp/ssl/service_ca.crt` | Public CA written when the container generates a certificate; copy this into client trust stores. |
| `MCP_GATEWAY_TLS_SAN` | built-in local names | Comma-separated OpenSSL SAN entries. `MCP_GATEWAY_IP` is appended automatically. |
| `KALI_MCP_SSL_DIR` | `kali-mcp-ssl` | Compose volume source or absolute host directory mounted at `/opt/kali-mcp/ssl`. |
| `KALI_MCP_DISABLE` | *(empty)* | Comma-separated server names to leave out, e.g. `metasploit,playwright,burp`. An unknown name is an error, not a no-op. |
| `BURP_ACCEPT_EULA` | *(none)* | Operator acceptance of the PortSwigger EULA. `true`/`yes`/`1` starts Burp in this container and adds `burp_*` to the gateway. |
| `BURP_HEAP` | `2g` | JVM heap for the in-container Burp. |
| `BURP_HEADLESS` | `xvfb` | `true` and `xvfb` start a virtual display. Burp Desktop initializes Swing even without a visible window, so Java's `-Djava.awt.headless=true` is not supported. `false` uses an existing display. |
| `BURP_MCP_URL` | *(none)* | If set, do **not** start local Burp; add a remote `burp` target at this URL. |
| `BURP_MCP_TRANSPORT` | `sse` | `mcp` (streamable HTTP) or `sse`, for a remote Burp target only. |

Disabling `metasploit` also stops `msfrpcd` from being started at all.

Running any other command bypasses the gateway entirely, for debugging:

```bash
docker run --rm vxcontrol/kali-linux:mcp nmap --version
docker run -it --rm vxcontrol/kali-linux:mcp bash
```

### HTTPS certificates

TLS is enabled by default. On the first start, if neither configured file exists, the entrypoint creates a private local CA and a two-year server certificate in `/opt/kali-mcp/ssl`. The Compose volume `kali-mcp-ssl` keeps them stable across container replacement. The generated SAN contains `kali-mcp`, `localhost`, loopback IPv4/IPv6, and `MCP_GATEWAY_IP`. Additional entries can be supplied through `MCP_GATEWAY_TLS_SAN`.

The generated files are:

- `server.crt` — server certificate followed by its CA certificate;
- `server.key` — mode `0600`;
- `service_ca.crt` — public CA for MCP clients.

To use an operator-provided certificate, mount its directory and point the two container paths at matching PEM files:

```dotenv
KALI_MCP_SSL_DIR=/srv/kali-mcp/ssl
MCP_GATEWAY_TLS_CERT=/opt/kali-mcp/ssl/fullchain.pem
MCP_GATEWAY_TLS_KEY=/opt/kali-mcp/ssl/privkey.pem
```

Existing files are validated and never overwritten. Startup fails when only one file exists, either PEM is invalid, or the public keys do not match. Relative certificate paths are resolved under `/opt/kali-mcp`.

For the generated certificate, copy `service_ca.crt` from the SSL volume into the PentAGI backend's trusted CA bundle. A certificate issued by an internal or public CA already trusted by PentAGI needs no additional trust configuration. Plaintext remains available only as an explicit opt-out: `MCP_GATEWAY_USE_TLS=false`.

### Host networking and bind address

`network_mode: host` is intentional: network scanners see the host network namespace, and Compose ignores `ports:` in this mode. However, agentgateway 1.5.0 only accepts a port and always creates its MCP socket on `0.0.0.0` (and `[::]` when IPv6 is enabled). It does **not** expose a bind-address option. This was also checked against its configuration validator: both `mcp.address` and `gateways.default.address` are rejected as unknown fields. `MCP_GATEWAY_IP` therefore describes the address clients should use; it cannot change the listening socket.

The upstream [bind reference](https://mintlify.wiki/agentgateway/agentgateway/reference/binds) explicitly requires an operating-system network policy when one interface must be selected. On a Linux host, keep host networking and restrict the destination IP with nftables. For example, to expose port 8081 only through `192.0.2.10` and reject IPv6 access:

```bash
sudo nft add table inet kali_mcp
sudo nft 'add chain inet kali_mcp input { type filter hook input priority 0; policy accept; }'
sudo nft add rule inet kali_mcp input tcp dport 8081 ip daddr != 192.0.2.10 reject
sudo nft add rule inet kali_mcp input meta nfproto ipv6 tcp dport 8081 reject
```

Create and remove these rules in host provisioning, not in the container: `NET_ADMIN` plus host networking would modify the host firewall, and a container killed with `SIGKILL` could leave stale rules behind.

If `ss` must show the socket bound to one IP rather than access merely being filtered, the remaining option is a custom agentgateway build: its local MCP converter currently hardcodes `Ipv4Addr::UNSPECIFIED`/`Ipv6Addr::UNSPECIFIED` and must be patched to accept a bind address.

On Docker Desktop, host networking refers to the Linux VM rather than directly to the macOS or Windows network namespace. Host nftables rules therefore belong to that VM; bridge networking with a host-IP-qualified `ports:` mapping is usually more practical there.

### Linux capabilities

The image works with no extra capabilities, but these tools need them:

| Capability | Needed by |
|---|---|
| `NET_RAW` | `masscan` (always), `nmap` SYN/OS-detection scans, `tshark_live_capture` |
| `NET_ADMIN` | `tshark_live_capture` on some interfaces |

Without them, nmap silently falls back to TCP connect scans and masscan fails.

### Build arguments

| Arg | Default | Notes |
|---|---|---|
| `WITH_NUCLEI_TEMPLATES` | `true` | Bakes the nuclei template tree in (13,619 templates, 84MB). `false` skips it; nuclei then downloads them on the first scan. |
| `WITH_BURP` | `true` | Bakes Burp Suite Desktop 2026.7.3 + MCP v1.3.0 (~700MB). `false` skips the layer; first start downloads the same pins. |
| `NODE_VERSION` | `22.21.1` | Checksums for both architectures are pinned alongside it. |
| `AGENTGATEWAY_VERSION` | `1.5.0` | Ditto. |
| `PLAYWRIGHT_MCP_VERSION` | `0.0.80` | |
| `*_SHA` | pinned | Upstream server commits. |

Pass these through Bake with `--set "mcp.args.<ARG>=<value>"` (for example, `docker buildx bake mcp --set "mcp.args.WITH_BURP=false"`), or use `--build-arg <ARG>=<value>` when running `docker buildx build --target mcp`.

The nuclei-template layer downloads a GitHub release. GitHub enforces rate limits on unauthenticated requests by IP, and `nuclei -ut` **exits with code 0 even when it fails**, so the build process explicitly counts the downloaded templates and fails if the template tree is empty. If you encounter this, wait until the rate limit resets or build with `--set "mcp.args.WITH_NUCLEI_TEMPLATES=false"`.

---

## Burp Suite

Burp Suite Desktop (pinned at **2026.7.3**, Community Edition) and the official MCP extension (**v1.3.0**) run **within this container** when the operator accepts PortSwigger's EULA.

To start the container:

```bash
docker run -d --name kali-mcp \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e MCP_GATEWAY_TOKEN="$TOKEN" \
  -e BURP_ACCEPT_EULA=true \
  -p 127.0.0.1:8081:8081 \
  vxcontrol/kali-linux:mcp
```

Alternatively, from this directory, after building with Bake as above: copy `.env.example` to `.env`, set `MCP_GATEWAY_TOKEN` in `.env` (`BURP_ACCEPT_EULA` defaults to `true` in `docker-compose.yml`), then run `docker compose up -d`. Note that Compose does not build the image; it runs `vxcontrol/kali-linux:mcp` (or `$KALI_MCP_IMAGE`). On Docker Desktop, `network_mode: host` refers to the Linux VM — accessing `https://127.0.0.1:8081` from your Mac will not reach the container.

What happens during startup:

1. `start-burp.sh` refuses to launch Burp unless `BURP_ACCEPT_EULA` is set to `true`, `yes`, or `1`. If it is not, the gateway still starts, but without `burp_*` tools.
2. Xvfb provides the Swing display needed by Burp Desktop without opening a visible window. The launcher automatically accepts the EULA, selects Community Edition and its in-memory project, chooses Burp defaults, and loads the official BApp, all without user interaction. Persistent project files are available only with Burp Professional.
3. The extension binds to **loopback only**: `127.0.0.1:9876` (legacy SSE, no built-in authentication).
4. The entrypoint waits for Burp MCP (`:9876`) to listen, then execs agentgateway. The initial session already includes `burp_*` tools. `msfrpcd` still runs in the background (with the same lazy start pattern as before).
5. agentgateway communicates with Burp through PortSwigger's packaged **stdio proxy**, ensuring the Host header is always `127.0.0.1` and avoiding issues with Burp's `/sse` 404 responses.

The image build process downloads the pinned JAR (~700MB). If you build with `--set "mcp.args.WITH_BURP=false"`, this step is skipped, and the first start then pulls the same checksummed files into `/opt/kali-mcp/state/burp`. To preserve downloaded artifacts and Burp preferences across restarts, persist that directory (using the Compose volume `kali-mcp-burp`).

Some HTTP-send and history tools within Burp may require user approval as dictated by the official extension's safety policy. Xvfb ensures such dialogs remain functional. The smoke test suite only uses contractually non-interactive operations and also creates a real Repeater tab through Burp's Montoya API.

If you prefer to use an external Burp instance, simply leave `BURP_ACCEPT_EULA` unset and configure the Burp endpoint accordingly.

```bash
docker run -d --name kali-mcp \
  -e MCP_GATEWAY_TOKEN="$TOKEN" \
  -e BURP_MCP_URL="http://192.0.2.10:9876" \
  -e BURP_MCP_TRANSPORT=sse \
  -p 8081:8081 vxcontrol/kali-linux:mcp
```

`KALI_MCP_DISABLE=burp` skips both the local process and a remote target.

---

## Architecture notes (arm64 and amd64)

Built and tested on **linux/arm64** (Apple Silicon). Everything in the table above runs there. Specifically:

- **agentgateway** publishes `linux-arm64` and `linux-amd64` binaries; both checksums are pinned and the right one is selected from `dpkg --print-architecture`.
- **Playwright** drives Kali's own `/usr/bin/chromium` (installed by the `mcp` stage, native arm64) via `--executable-path`, and `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` stops the npm package from fetching its own browser bundle. This is what makes the browser work on arm64 at all, and it also cuts ~400MB.
- **hashcat** runs on the PoCL **CPU** OpenCL backend inside the container—on arm64 and on amd64 alike, unless you pass a GPU through (`--device`/`--gpus`, Linux hosts only). `hashcat_get_gpu_status` will report a CPU device. Cracking anything real without a GPU is slow; treat the hashcat server as identification and orchestration, not throughput.
- **Node.js** is installed from the upstream tarball because Kali has no `npm` package at all (`E: Package 'npm' has no installation candidate`), only `/usr/bin/node`. The arm64 and x64 tarball checksums are both pinned.

The amd64 path is written and its checksums verified against upstream, but it has **not** been built here—this machine is arm64 only.

---

## Files

These are the files unique to the MCP build. The image itself is the `mcp` stage of the repository's root `Dockerfile` (built with `docker buildx bake mcp`), which COPYs the scripts and config below out of this directory.

| File | Purpose |
|---|---|
| `gateway.yaml` | The gateway config: every server, its command, its env, and the auth policy. Readable on its own; rendered at start-up |
| `render-config.py` | Injects the token *hash*, port, msfrpcd password; drops disabled servers; appends the Burp target |
| `entrypoint.sh` | Token check → TLS setup → Burp prepare → render → `msfrpcd` → Burp start/wait → `exec agentgateway` |
| `setup-tls.sh` | Validates custom PEM files or generates the persistent local CA and server certificate |
| `start-burp.sh` | EULA gate, pinned artifacts, non-interactive Community/Xvfb launch, wait for `:9876` |
| `burp/pins.sh` | Version and SHA-256 pins for the Desktop JAR, BApp, and stdio proxy |
| `patch-vendored.py` | Exact, fail-closed fixes for bugs in the pinned upstream MCP sources |
| `docker-compose.yml` | Host-network run from Harbor / a local build |
| `smoke-test.sh` | End-to-end check of a built image (see below) |
| `smoke-target.py` | Disposable controlled HTTP target used by the integration suite |
| `render-config_test.py`, `setup_tls_test.py` | Unit tests for the renderer and TLS setup (`python3 -m pytest` in this directory) |
| `.env.example` | Template for a Compose run (`cp .env.example .env`) |

`tini -g` is PID 1. The agentgateway handles SIGTERM by itself—`docker stop` results in exit 0 in under a second even with 16 spawned children running, with or without tini. Tini serves as the conventional safety net for the `msfrpcd` daemon started beside the gateway (signaling the whole process group and reaping orphans), but it is not the actual mechanism that shutdown depends on.

---

## Testing

```bash
./smoke-test.sh local/kali-linux:mcp 18081
```

The test suite asserts, against a real container, the following cases:

- Refusal to start with no token and with a short token.
- Returning `401` for unauthenticated requests and with a wrong token.
- A successful `initialize`.
- All 15 servers present in `tools/list` (including `burp`).
- A dedicated Burp section (`:9876`, real proxy forwarding, options, Repeater, encode/decode).
- A CLI-backed `tools/call` for each remaining server.
- Clean runtime logs.
- That `/run/kali-mcp/gateway.yaml` holds the SHA-256, not the token.
- That `docker stop` results in clean exit with all child processes gone.

The exit status is the verdict: 0 only when every assertion has passed. The `tools/call` checks are run inside an embedded Python block, so its own exit status is the only thing communicated back to the shell—this approach ensures that simply printing counters would not result in a misleading green (successful) run if tools actually failed.

Each of those tool calls asserts on a substring that only a real answer would contain, not just on `isError` or the JSON-RPC `error` member. Both indicators are absent from a refusal as several of these servers return plain text. For example, if you ask the nmap server for a tool it does not have, it answers with a `Unknown tool: …` content block and no error signal at all, which an `isError`-only check would incorrectly interpret as a pass. This behavior was confirmed using the negative control described below; the suite appeared to pass until the substring assertion was enforced.

To verify that the failure detection path remains operational, you can run the suite with a negative control—an assertion that cannot succeed—and expect a nonzero exit code:

```bash
SMOKE_NEGATIVE_CONTROL=1 ./smoke-test.sh local/kali-linux:mcp 18081; echo $?  # 1
```

The suite starts a separate, controlled HTTP target container. Tools like nmap and masscan must find its open port, while WhatWeb, ffuf, httpx, Playwright, SQLMap, and Nuclei must exercise it without sending scanner probes into the gateway itself. A generated pcap is also used to verify tshark decoding, rather than merely confirming its version.

The entrypoint waits for Burp MCP to be ready before starting agentgateway. Similarly, `smoke-test.sh` waits for `msfrpcd` before opening the first MCP session. Even if one stdio child later dies, setting `failureMode: failOpen` keeps the rest of the gateway running.

---

## Deliberately not included

Not every Kali tool has a real MCP server. Rather than invent package names, here’s a summary of what is not included:

**gobuster, dirb, feroxbuster, wfuzz:** There is no maintained standalone MCP server for these tools. `ffuf` covers the same ground and has an MCP server.

**hydra, john, medusa, ncrack:** Similarly, there are no maintained servers for these tools. `hashcat` is the one credential tool with a maintained server.

**amass:** The only known `amass` server was in `cyproxio/mcp-for-security`, which was archived by its owner on 2026-03-30 ("no longer actively maintained. All tools have been migrated to Bolt"). For passive subdomain enumeration, `pdtools`' `subfinder` is covered. `amass` itself is still available as a CLI in the container. If you need a wider toolset, [Bolt](https://github.com/cyberstrikeus/bolt) is its successor, but it is a full image on its own, not a layer to add here.

**radare2, ghidra, yara, capa, semgrep, trivy, gitleaks:** Real MCP servers exist for these, but the required binaries are not in the base image. Including them would mean installing the tools too. `binwalk` is present because Kali already ships it.

**zaproxy:** This is installed in the base image, but there is no maintained MCP server for it.

The base image’s full CLI toolkit is still available and usable through a shell. Only the MCP surface is limited to the servers listed above.

---

## Security

- HTTPS and bearer-token authentication are both enabled by default. Disabling TLS publishes the bearer token and all MCP traffic in plaintext; only do this on an isolated loopback or trusted private network.
- Anything the agent can call, it can point at anything the container can reach. Run it on a segmented network with only the scope you’re authorized for.
- The container runs as root—nmap raw sockets, msfrpcd, and hashcat all require it. Do not mount host paths you would not want an exploit framework to write to. `/work` is the intended workspace.
- Rotate the token by restarting the container with a new one; nothing persists it.

## License

**MCP Layer Configuration**: The scripts and configuration in this directory (built as the `mcp` stage of the root `Dockerfile`) are part of this project and are licensed under the MIT License — see the [LICENSE](../LICENSE) file for details.

**Bundled Software**: This image layers third-party MCP servers, the agentgateway binary, Node.js, and (optionally) Burp Suite on top of the base image, each governed by its own license. The upstream projects are linked in the [What is included](#what-is-included) table above; consult their repositories for terms.

**Burp Suite**: Subject to PortSwigger's EULA, which the operator explicitly accepts by setting `BURP_ACCEPT_EULA=true`. It is not started otherwise.
