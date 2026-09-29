#!/usr/bin/env bash
# End-to-end check of a built kali-mcp image.
#
# Proves, against a real container:
#   1. it refuses to start with no token, and with a too-short token
#   2. the /mcp endpoint rejects an unauthenticated request and a wrong token
#   3. `initialize` and `tools/list` succeed with the right token
#   4. every declared MCP server actually came up, including in-container Burp
#   5. a representative tool from several servers really executes
#   6. HTTPS uses a generated, persisted certificate with the expected SAN
#   7. the rendered config on disk holds the token's hash, never the token
#   8. `docker stop` takes msfrpcd and the spawned servers down with the gateway
#
# Exit status is the verdict: 0 only when every assertion passed, shell-side
# and python-side alike. Set SMOKE_NEGATIVE_CONTROL=1 to inject one check that
# cannot pass — the run must then exit nonzero, which is how you confirm the
# failure path is still wired up.
#
# Usage: ./smoke-test.sh [image] [host-port]
set -euo pipefail

IMAGE=${1:-local/kali-linux:mcp}
PORT=${2:-18081}
NAME=kali-mcp-smoke
TARGET_NAME=kali-mcp-smoke-target
URL="https://127.0.0.1:${PORT}/mcp"
TOKEN=$(openssl rand -hex 32)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

pass=0; fail=0
ok()   { printf '  PASS  %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail+1)); }
head() { printf '\n== %s\n' "$*"; }

cleanup() {
    docker rm -f "$NAME" "$TARGET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# --- 1. refusal ------------------------------------------------------------
head "refuses to start without a usable token"
if out=$(docker run --rm "$IMAGE" 2>&1); then
    bad "started with NO token -- the gateway would be unauthenticated"
else
    grep -q "no bearer token" <<<"$out" && ok "no token -> exit 1" || bad "no token: unexpected message: $out"
fi
if out=$(docker run --rm -e MCP_GATEWAY_TOKEN=tooshort "$IMAGE" 2>&1); then
    bad "started with a 8-character token"
else
    grep -q "at least 16" <<<"$out" && ok "short token -> exit 1" || bad "short token: unexpected message: $out"
fi

# --- start -----------------------------------------------------------------
head "starting $IMAGE"
# No --rm: the shutdown assertion inspects the container after `docker stop`.
# --rm deletes it on stop and `docker inspect` then dies with
# "no such object: kali-mcp-smoke", which `set -e` treats as a crashed run.
docker run -d --name "$NAME" --cap-add=NET_RAW --cap-add=NET_ADMIN \
    --shm-size=2g \
    -e MCP_GATEWAY_TOKEN="$TOKEN" \
    -e MCP_GATEWAY_IP=127.0.0.1 \
    -e MCP_GATEWAY_USE_TLS=true \
    -e BURP_ACCEPT_EULA=true \
    -e BURP_HEAP=2g \
    -p "${PORT}:8081" "$IMAGE" >/dev/null
# Entrypoint waits for Burp :9876 before exec'ing the gateway (up to ~180s),
# then msfrpcd still needs its own module-load window.
ready=0
for _ in $(seq 1 150); do
    sleep 2
    if curl -fsS -o /dev/null "http://127.0.0.1:15021/healthz/ready" 2>/dev/null \
        || docker exec "$NAME" curl -fsS -o /dev/null http://127.0.0.1:15021/healthz/ready 2>/dev/null; then
        ready=1
        break
    fi
    container_state=$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || true)
    if [[ "$container_state" != "running" ]]; then
        bad "container exited during startup"
        docker logs "$NAME" 2>&1 | tail -n 80
        exit 1
    fi
done
if [[ "$ready" -ne 1 ]]; then
    bad "gateway did not become ready within 300 seconds"
    docker logs "$NAME" 2>&1 | tail -n 80
    exit 1
fi

# A separate container is essential for scanner verification. Scanning the
# gateway's own loopback made nmap service probes write non-HTTP bytes to :8081,
# produced misleading gateway warnings, and never proved container networking.
docker run -d --name "$TARGET_NAME" "$IMAGE" sleep infinity >/dev/null
docker cp "${SCRIPT_DIR}/smoke-target.py" "${TARGET_NAME}:/tmp/smoke-target.py" >/dev/null
docker exec -d "$TARGET_NAME" python3 /tmp/smoke-target.py
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET_NAME")
for _ in $(seq 1 30); do
    docker exec "$NAME" curl -fsS "http://${TARGET_IP}:18080/" >/dev/null 2>&1 && break
    sleep 1
done
if docker exec "$NAME" curl -fsS "http://${TARGET_IP}:18080/" | grep -q "Kali MCP smoke target"; then
    ok "controlled target is reachable at ${TARGET_IP}:18080"
else
    bad "controlled target is not reachable at ${TARGET_IP}:18080"
fi
if docker exec "$NAME" curl -fsS --noproxy "" \
    --proxy http://127.0.0.1:8080 "http://${TARGET_IP}:18080/admin" \
    | grep -q "kali-mcp-admin-fixture"; then
    ok "Burp Proxy forwarded a real request to the controlled target"
else
    bad "Burp Proxy did not forward the controlled request"
fi
docker exec "$NAME" bash -c "printf 'admin\\nmissing\\n' >/work/kali-mcp-smoke-words.txt"
docker exec -i "$NAME" bash -c 'cat >/root/nuclei-templates/kali-mcp-smoke.yaml' <<'YAML'
id: kali-mcp-smoke
info:
  name: Kali MCP controlled target
  author: pentagi
  severity: info
  tags: kali-mcp-smoke
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
YAML
docker exec -i "$NAME" python3 - <<'PY'
import socket
import struct

payload = b"kali-mcp-smoke"
udp = struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0) + payload
ip = bytearray(
    struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton("192.0.2.1"),
        socket.inet_aton("192.0.2.2"),
    )
)
words = struct.unpack("!10H", ip)
checksum = (~sum(words) & 0xFFFF)
ip[10:12] = struct.pack("!H", checksum)
ethernet = bytes.fromhex("00112233445566778899aabb0800")
packet = ethernet + ip + udp
pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
pcap += struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet
with open("/work/kali-mcp-smoke.pcap", "wb") as handle:
    handle.write(pcap)
PY
# msfrpcd needs ~30-60s to load the module tree before MetasploitMCP can attach.
for _ in $(seq 1 60); do
    docker exec "$NAME" bash -c 'ss -ltn 2>/dev/null | grep -q 55553' && break
    sleep 2
done
sleep 45
# Captured into a variable rather than piped into `grep -q`: grep exits on the
# first match, docker logs then dies of SIGPIPE, and `set -o pipefail` would
# report that as a failed assertion.
logs=$(docker logs "$NAME" 2>&1)
grep -q "rendered 15 MCP server" <<<"$logs" \
    && ok "entrypoint rendered 15 servers (14 tools + burp)" \
    || bad "entrypoint did not render 15 servers (Burp missing?): $(grep -E 'rendered|Burp|ERROR' <<<"$logs" | tail -n 20)"
grep -q "Burp MCP is listening" <<<"$logs" \
    && ok "entrypoint waited until Burp MCP listened on 127.0.0.1:9876" \
    || bad "Burp MCP never listened: $(grep -E 'Burp|ERROR' <<<"$logs" | tail -n 20)"
if docker exec "$NAME" python3 -c "import socket; s=socket.create_connection(('127.0.0.1',9876),2); s.close()"; then
    ok "Burp MCP still accepts TCP on 127.0.0.1:9876"
else
    bad "Burp MCP port 9876 is not open inside the container"
fi

# --- 2/3/4/5. protocol -----------------------------------------------------
head "authentication"
code=$(curl -k -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}')
[[ "$code" == 401 ]] && ok "no Authorization header -> 401" || bad "no token gave HTTP $code, expected 401"
code=$(curl -k -s -o /dev/null -w '%{http_code}' -X POST "$URL" -H "Authorization: Bearer $(openssl rand -hex 32)" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}')
[[ "$code" == 401 ]] && ok "wrong token -> 401" || bad "wrong token gave HTTP $code, expected 401"

head "MCP protocol and tool execution"
# Status captured with `|| py_status=$?` rather than left to `set -e`: aborting
# here would skip the on-disk and shutdown assertions and the final summary.
# The captured status is folded into the shell's own counter below, which is
# the value the last line of this script exits on.
py_status=0
python3 - "$URL" "$TOKEN" "$TARGET_IP" <<'PY' || py_status=$?
import collections, json, os, ssl, sys, urllib.request

url, token, target_ip = sys.argv[1], sys.argv[2], sys.argv[3]
target_url = f"http://{target_ip}:18080"
result = {"pass": 0, "fail": 0}
tls_context = ssl._create_unverified_context()

def report(good, message):
    print(("  PASS  " if good else "  FAIL  ") + message)
    result["pass" if good else "fail"] += 1

def post(body, sid=None, timeout=400):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if sid:
        headers["mcp-session-id"] = sid
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=timeout, context=tls_context) as response:
        raw = response.read().decode()
        new_sid = response.headers.get("mcp-session-id")
    for line in raw.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:]), new_sid
    return json.loads(raw), new_sid

init, sid = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "smoke", "version": "1"}}})
report("result" in init, f"initialize -> {json.dumps(init.get('result', init).get('serverInfo', init))}")

listed, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
tools = listed["result"]["tools"]
per_server = collections.Counter(t["name"].split("_")[0] for t in tools)
expected = {"nmap", "masscan", "whatweb", "pdtools", "nuclei", "sqlmap", "ffuf",
            "waybackurls", "playwright", "metasploit", "searchsploit", "hashcat",
            "binwalk", "tshark", "burp"}
missing = sorted(expected - set(per_server))
report(not missing, f"tools/list -> {len(tools)} tools from {len(per_server)} servers"
                    + (f"; MISSING {missing}" if missing else ""))
for name in sorted(per_server):
    print(f"          {name:14s} {per_server[name]}")
listed_names = {tool["name"] for tool in tools}
burp_tools = sorted(n for n in listed_names if n.startswith("burp_"))
print("\n== Burp MCP")
report(len(burp_tools) >= 10,
       f"burp_* advertised: {len(burp_tools)} tools"
       + (f" ({', '.join(burp_tools)})" if burp_tools else "; NONE"))

# One real call per server that can act without an external target, each with a
# substring that only a genuinely successful answer contains.
#
# That substring is the assertion that carries this check. isError and the
# JSON-RPC error member are NOT sufficient on their own: several of these
# servers report a refusal as ordinary result text with neither set -- the nmap
# server answers an unknown tool with a plain "Unknown tool: ..." content block
# -- so a check reading only those fields calls a total failure a pass. It was
# measured, not assumed: with the earlier check the negative control below came
# back PASS.
#
# Substring-matching the word "error" instead would fail the other way: a
# successful browser_navigate reports the page's own console error count, and
# searchsploit results carry CVE titles containing the word.
def find_burp(*parts):
    for name in burp_tools:
        if all(part in name for part in parts):
            return name
    return None

# Burp first, so a failed BApp is not buried under the other servers.
# Encode/decode are pure utilities and do not need Swing approvals.
burp_calls = []
for found, args, expect, label in (
    (find_burp("url_encode"), {"content": "hello world"}, "hello+world", "burp_url_encode"),
    (find_burp("url_decode"), {"content": "hello+world"}, "hello world", "burp_url_decode"),
    (find_burp("base64", "encode"), {"content": "hi"}, "aGk=", "burp_base64_encode"),
):
    if found:
        burp_calls.append((found, args, expect))
    else:
        report(False, f"{label} is not in tools/list")

calls = burp_calls + [
    (
        "burp_output_user_options",
        {},
        ("user_options", "Burp MCP Server"),
    ),
    (
        "burp_create_repeater_tab",
        {
            "content": (
                "GET /admin HTTP/1.1\r\n"
                f"Host: {target_ip}:18080\r\n"
                "Connection: close\r\n\r\n"
            ),
            "tabName": "Kali MCP smoke",
            "targetHostname": target_ip,
            "targetPort": 18080,
            "usesHttps": False,
        },
        "Executed tool",
    ),
    (
        "tshark_read_pcap",
        {"file_path": "/work/kali-mcp-smoke.pcap", "packet_count": 10},
        "Read 1 packet(s)",
    ),
    (
        "ffuf_ffuf_custom",
        {
            "url": f"{target_url}/FUZZ",
            "wordlist": "/work/kali-mcp-smoke-words.txt",
            "filter_codes": [404],
            "threads": 2,
            "timeout": 30,
        },
        ('"status": "completed"', "/admin", '"status": 200'),
    ),
    ("searchsploit_searchsploit_search", {"query": "apache 2.4"}, "search_id"),
    (
        "nmap_port_scan",
        {"target": target_ip, "ports": "18080", "timing": 4, "timeout": 30},
        ('"status": "completed"', '"port": "18080"'),
    ),
    (
        "masscan_masscan_scan",
        {"targets": target_ip, "ports": "18080", "rate": 1000, "timeout": 30},
        ('"status": "completed"', '"port": 18080', '"status": "open"'),
    ),
    ("binwalk_binwalk_scan", {"filepath": "/bin/ls"}, "scan_id"),
    ("hashcat_identify_hash", {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"}, "identification"),
    ("metasploit_list_exploits", {"search_term": "eternalblue"}, "eternalblue"),
    (
        "nuclei_nuclei_scan",
        {
            "target": target_url,
            "template_paths": ["/root/nuclei-templates/kali-mcp-smoke.yaml"],
            "tags": ["kali-mcp-smoke"],
            "severity": ["info"],
            "timeout": 30,
        },
        ('"status": "completed"', "kali-mcp-smoke", '"error": null'),
    ),
    (
        "sqlmap_sql_test",
        {"target": f"{target_url}/echo?id=1", "param": "id"},
        ('"parameter": "id"', '"injectable": false'),
    ),
    (
        "playwright_browser_navigate",
        {"url": f"{target_url}/admin"},
        ("Ran Playwright code", f"Page URL: {target_url}/admin"),
    ),
    (
        "whatweb_whatweb_scan",
        {"target": f"{target_url}/admin", "timeout": 30},
        ('"status": "completed"', "KaliMcpSmoke", "Python"),
    ),
    (
        "pdtools_httpx",
        {"urls": [target_url]},
        ('"statusCode": 200', target_url),
    ),
    (
        "waybackurls_fetch_wayback_urls",
        {
            "domain": "example.com",
            "no_subs": True,
            "include_urls": False,
            "limit": 1,
            "timeout": 60,
        },
        ('"status": "completed"', '"error": null'),
    ),
]
# Negative control. The gateway has no such tool, so neither the listing check
# nor the substring check can pass: a run with SMOKE_NEGATIVE_CONTROL=1 that
# still exits 0 means this file no longer detects a broken tool, and every
# green run is meaningless.
if os.environ.get("SMOKE_NEGATIVE_CONTROL") == "1":
    calls.append(("nmap_deliberately_nonexistent_tool", {}, "scan_id"))

for name, args, expect in calls:
    if name not in listed_names:
        # Asked for before it is called, because a renamed or dropped tool is a
        # regression in its own right and its call would otherwise be judged on
        # whatever prose the server answers with.
        report(False, f"{name} is not in tools/list")
        continue
    try:
        called, _ = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": name, "arguments": args}}, sid)
    except Exception as exc:                                  # noqa: BLE001
        report(False, f"{name} raised {exc!r}")
        continue
    body = called.get("result", {})
    content = body.get("content")
    if isinstance(content, list):
        text = "\n".join(
            item.get("text", json.dumps(item))
            if isinstance(item, dict)
            else str(item)
            for item in content
        )
    else:
        text = json.dumps(called)
    expected_parts = expect if isinstance(expect, tuple) else (expect,)
    succeeded = (
        not body.get("isError")
        and "error" not in called
        and all(part in text for part in expected_parts)
    )
    report(succeeded, f"{name} -> {text[:120]}"
                      + (
                          ""
                          if succeeded
                          else f"; EXPECTED {expected_parts!r} IN THE ANSWER"
                      ))

print(f"PY_PASS={result['pass']} PY_FAIL={result['fail']}")
# Printing the counters is not a verdict — only this exit status reaches the
# shell. Without it every check above could fail and the suite still exit 0.
sys.exit(1 if result["fail"] else 0)
PY
[[ "$py_status" -eq 0 ]] \
    && ok "protocol and tool checks (see PY_PASS/PY_FAIL above)" \
    || bad "protocol/tool checks failed: python exited $py_status (see the FAIL lines above)"

# --- 6. public TLS ---------------------------------------------------------
head "generated HTTPS certificate"
if docker exec "$NAME" openssl x509 \
    -in /opt/kali-mcp/ssl/server.crt -noout -checkend 3600 >/dev/null; then
    ok "generated TLS certificate is valid for at least one hour"
else
    bad "generated TLS certificate is missing, invalid, or already expiring"
fi
if docker exec "$NAME" openssl verify \
    -CAfile /opt/kali-mcp/ssl/service_ca.crt \
    /opt/kali-mcp/ssl/server.crt >/dev/null; then
    ok "generated server certificate verifies against the persisted CA"
else
    bad "generated server certificate does not verify against service_ca.crt"
fi
if docker exec "$NAME" openssl x509 \
    -in /opt/kali-mcp/ssl/server.crt -noout -ext subjectAltName \
    | grep -q "IP Address:127.0.0.1"; then
    ok "generated TLS certificate contains MCP_GATEWAY_IP in SAN"
else
    bad "generated TLS certificate SAN does not contain 127.0.0.1"
fi
key_mode=$(docker exec "$NAME" stat -c '%a' /opt/kali-mcp/ssl/server.key)
[[ "$key_mode" == "600" ]] \
    && ok "generated TLS private key mode is 0600" \
    || bad "generated TLS private key mode is $key_mode, expected 600"
docker exec "$NAME" grep -q '^gateways:' /run/kali-mcp/gateway.yaml \
    && ok "rendered agentgateway config uses an HTTPS gateway" \
    || bad "rendered agentgateway config has no TLS gateway"

# --- 7. the token is not on disk ------------------------------------------
head "rendered config never holds the token"
if docker exec "$NAME" grep -q "$TOKEN" /run/kali-mcp/gateway.yaml 2>/dev/null; then
    bad "the plaintext token is in /run/kali-mcp/gateway.yaml"
else
    ok "token absent from /run/kali-mcp/gateway.yaml"
fi
expected_hash="sha256:$(printf '%s' "$TOKEN" | shasum -a 256 | awk '{print $1}')"
docker exec "$NAME" grep -q "$expected_hash" /run/kali-mcp/gateway.yaml \
    && ok "its SHA-256 is what the gateway matches against" \
    || bad "the rendered keyHash is not SHA-256 of the token"

# --- 8. runtime logs and Burp process -------------------------------------
head "runtime log audit"
if docker exec "$NAME" bash -c '
    burp_pid=$(cat /opt/kali-mcp/state/burp/burp.pid)
    kill -0 "$burp_pid"
    tr "\0" "\n" <"/proc/$burp_pid/environ" | grep -q "^DISPLAY=:"
    ! tr "\0" " " <"/proc/$burp_pid/cmdline" | grep -q -- "-Djava.awt.headless=true"
    pgrep -x Xvfb >/dev/null
'; then
    ok "Burp runs under Xvfb without Java headless mode or user interaction"
else
    bad "Burp/Xvfb process configuration is invalid"
fi

runtime_logs=$(docker logs "$NAME" 2>&1)
burp_logs=$(docker exec "$NAME" cat /var/log/burp.log 2>&1 || true)
aux_logs=$(docker exec "$NAME" bash -c '
    cat /var/log/msfrpcd.log /var/log/xvfb.log 2>/dev/null || true
' 2>&1)
all_logs="${runtime_logs}"$'\n'"${burp_logs}"$'\n'"${aux_logs}"
forbidden_logs='PydanticDeprecated|Could not delete temporary hash|No authentication configured|insecure HTTP for OAuth|license key was not recognized|no ComponentUI class|NullPointerException|Traceback|(^|[^[:alpha:]])(ERROR|FATAL|PANIC)([^[:alpha:]]|$)|upstream .* failed|invalid HTTP (version|method)|proxy error: invalid URI'
if bad_lines=$(grep -E "$forbidden_logs" <<<"$all_logs"); then
    bad "runtime logs contain errors or incompatible configuration:"
    printf '%s\n' "$bad_lines" | tail -n 40
else
    ok "gateway, MCP, Burp, Xvfb, and msfrpcd logs contain no forbidden errors"
fi

# --- 9. shutdown -----------------------------------------------------------
head "signal handling"
if ! docker inspect "$NAME" >/dev/null 2>&1; then
    bad "container $NAME is gone before docker stop"
else
    before=$(docker exec "$NAME" bash -c 'pgrep -c -f "msfrpcd|server.py|playwright" || true' 2>/dev/null || echo 0)
    if ! docker stop -t 20 "$NAME" >/dev/null; then
        bad "docker stop failed for $NAME"
    elif state=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' "$NAME" 2>/dev/null); then
        grep -q '^exited' <<<"$state" && ok "docker stop -> $state (was running $before child processes)" \
                                      || bad "container did not stop cleanly: $state"
    else
        bad "docker stop removed $NAME (started with --rm?); cannot verify exit status"
    fi
fi

printf '\n== shell assertions: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
