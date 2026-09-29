#!/bin/bash
# kali-mcp entrypoint.
#
# Order matters here:
#   0. with arguments, just run them -- this is the debugging escape hatch
#   1. refuse to start without a usable bearer token
#   2. prepare or validate the public TLS certificate
#   3. mint an ephemeral msfrpcd password
#   4. prepare in-container Burp (EULA gate + artifacts) when it is local
#   5. render the gateway config (token -> SHA-256 only)
#   6. start msfrpcd in the background, if the metasploit server is enabled
#   7. start Burp in the background and wait until its MCP port is up
#   8. exec agentgateway, so it is the process docker signals
#
# Step 1 is a refusal, not a warning. This image exposes nmap, metasploit,
# sqlmap, hashcat and a browser over HTTP; an unauthenticated instance on any
# reachable interface is remote code execution for whoever finds the port.

set -euo pipefail

readonly HOME_DIR=${KALI_MCP_HOME:-/opt/kali-mcp}
readonly TEMPLATE="${HOME_DIR}/gateway.yaml"
readonly RENDERED=/run/kali-mcp/gateway.yaml
readonly TLS_SCRIPT="${HOME_DIR}/bin/setup-tls.sh"
readonly MIN_TOKEN_LENGTH=16

log()  { printf 'kali-mcp: %s\n' "$*" >&2; }
fail() { printf 'kali-mcp: ERROR: %s\n' "$*" >&2; exit 1; }

# --- 0. escape hatch --------------------------------------------------------

# With arguments, run them instead of the gateway -- `docker run ... bash`,
# `... nmap -sV target`, `docker exec`-style debugging. The base image's own
# entrypoint behaves the same way, and a shell in the container is not the
# gateway, so the token requirement below does not apply to this path.
if [[ $# -gt 0 ]]; then
    exec "$@"
fi

# --- 1. token ---------------------------------------------------------------

# Secret-file delivery (docker secrets, k8s projected volumes) is preferred over
# an environment variable, which leaks into `docker inspect` and child procs.
if [[ -n "${MCP_GATEWAY_TOKEN_FILE:-}" ]]; then
    [[ -r "${MCP_GATEWAY_TOKEN_FILE}" ]] \
        || fail "MCP_GATEWAY_TOKEN_FILE=${MCP_GATEWAY_TOKEN_FILE} is not readable"
    # Strip a trailing newline only; a token is otherwise taken verbatim.
    MCP_GATEWAY_TOKEN="$(<"${MCP_GATEWAY_TOKEN_FILE}")"
    MCP_GATEWAY_TOKEN="${MCP_GATEWAY_TOKEN%$'\n'}"
    export MCP_GATEWAY_TOKEN
fi

if [[ -z "${MCP_GATEWAY_TOKEN:-}" ]]; then
    cat >&2 <<'MSG'
kali-mcp: ERROR: no bearer token.

  This gateway fronts nmap, metasploit, sqlmap, hashcat, ffuf, a browser and
  more. Starting it without authentication would publish remote code execution
  to everyone who can reach the port, so it will not start.

  Set one of:
    -e MCP_GATEWAY_TOKEN="$(openssl rand -hex 32)"
    -e MCP_GATEWAY_TOKEN_FILE=/run/secrets/mcp_token

MSG
    exit 1
fi

if (( ${#MCP_GATEWAY_TOKEN} < MIN_TOKEN_LENGTH )); then
    fail "MCP_GATEWAY_TOKEN is ${#MCP_GATEWAY_TOKEN} characters; at least ${MIN_TOKEN_LENGTH} are required. \
A short token is guessable, and a guessed token here is a shell on this container. \
Generate one with: openssl rand -hex 32"
fi

# --- 2. public TLS ----------------------------------------------------------

[[ -r "$TLS_SCRIPT" ]] || fail "TLS setup script $TLS_SCRIPT is missing"
# shellcheck disable=SC1090
source "$TLS_SCRIPT"
setup_tls

# --- 3. msfrpcd password ----------------------------------------------------

# Generated fresh per container start and never logged. It is only reachable on
# 127.0.0.1 inside this container, but a fixed default would be worth guessing
# for anyone who gets any other foothold.
server_disabled() {
    local name="$1"
    local disabled=",${KALI_MCP_DISABLE:-},"
    [[ "${disabled}" == *",${name},"* ]]
}

metasploit_enabled() { ! server_disabled metasploit; }

# Local Burp: same container, loopback MCP, stdio proxy into the gateway.
# An explicit BURP_MCP_URL keeps the original remote-Burp path and skips
# starting anything here. KALI_MCP_DISABLE=burp turns both off. The EULA
# gate is separate: without BURP_ACCEPT_EULA the gateway still starts, just
# without Burp (a token-only `docker run` stays 14 servers; smoke-test
    # passes BURP_ACCEPT_EULA and expects 15).
burp_eula_accepted() {
    local value
    value="$(printf '%s' "${BURP_ACCEPT_EULA:-${ACCEPT_EULA:-}}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|y) return 0 ;;
        *) return 1 ;;
    esac
}

burp_local_wanted() {
    ! server_disabled burp && [[ -z "${BURP_MCP_URL:-}" ]]
}

burp_local_enabled() {
    burp_local_wanted && burp_eula_accepted
}

if metasploit_enabled; then
    MSF_PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    export MSF_PASSWORD
fi

# --- 4. burp prepare --------------------------------------------------------

if burp_local_enabled; then
    bash "${HOME_DIR}/bin/start-burp.sh" prepare
    if [[ -z "${BURP_MCP_PROXY_JAR:-}" && -f /opt/kali-mcp/state/burp/.proxy ]]; then
        BURP_MCP_PROXY_JAR="$(</opt/kali-mcp/state/burp/.proxy)"
        export BURP_MCP_PROXY_JAR
    fi
    export BURP_LOCAL=1
    export BURP_MCP_SSE_URL="${BURP_MCP_SSE_URL:-http://127.0.0.1:9876}"
elif burp_local_wanted; then
    log "local Burp skipped: set BURP_ACCEPT_EULA=true to accept PortSwigger's EULA and start it"
fi

# --- 5. render --------------------------------------------------------------

[[ -f "${TEMPLATE}" ]] || fail "gateway template ${TEMPLATE} is missing"
mkdir -p "$(dirname "${RENDERED}")"
chmod 0700 "$(dirname "${RENDERED}")"
/opt/venv/bin/python3 "${HOME_DIR}/bin/render-config.py" "${TEMPLATE}" "${RENDERED}"

# --- 6. msfrpcd -------------------------------------------------------------

if metasploit_enabled; then
    # -n disables the database: this container has no PostgreSQL, and without
    #    -n msfrpcd stalls on connecting to one.
    # -S disables TLS on the RPC socket; the socket is bound to loopback only
    #    and never leaves the container.
    # msfrpcd takes 30-60s to load the module tree. It is started in the
    # background so the gateway is answering immediately; MetasploitMCP is
    # spawned lazily on the first MCP session and exits if RPC is not up yet,
    # in which case failOpen serves the other servers and the metasploit
    # tools appear on the next session.
    log "starting msfrpcd on 127.0.0.1:55553 (module load takes ~30-60s)"
    msfrpcd -n -S -a 127.0.0.1 -p 55553 -U msf -P "${MSF_PASSWORD}" -f \
        >/var/log/msfrpcd.log 2>&1 &
fi

# --- 7. local Burp ----------------------------------------------------------

if burp_local_enabled; then
    bash "${HOME_DIR}/bin/start-burp.sh" start
    # Block until 127.0.0.1:9876 answers so the first MCP session already
    # has burp_* tools. Unlike msfrpcd this is the feature the operator
    # opted into with BURP_ACCEPT_EULA.
    bash "${HOME_DIR}/bin/start-burp.sh" wait
fi

# --- 8. gateway -------------------------------------------------------------

if [[ "${MCP_GATEWAY_USE_TLS:-true}" == "true" ]]; then
    scheme=https
else
    scheme=http
fi
log "gateway listening at ${scheme}://0.0.0.0:${MCP_GATEWAY_PORT:-8081}/mcp (bearer token required)"

# exec, not a background job with a wait: agentgateway must be the process that
# receives SIGTERM, and it shuts down on it (measured: `docker stop` exits 0 in
# under a second with 16 spawned children running). tini -g additionally relays
# the signal to the process group so msfrpcd is asked to stop too.
exec agentgateway -f "${RENDERED}"
