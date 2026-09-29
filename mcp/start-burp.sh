#!/bin/bash
# Prepare and start the in-container Burp Suite + official MCP extension.
#
#   prepare  — accept the EULA gate, use baked artifacts or fetch the
#              pinned copies, write the user-config that loads the BApp
#   start    — launch Burp in the background (headless by default)
#   wait     — block until the MCP extension is listening on loopback
#
# The MCP extension binds 127.0.0.1:9876 (SSE, no auth of its own). The
# gateway reaches it through the packaged stdio proxy, so agentgateway never
# has to speak Burp's Host: localhost restriction or its / vs /sse quirk.

set -euo pipefail

readonly PINS_CANDIDATES=(
    /opt/burp/pins.sh
    /opt/kali-mcp/burp/pins.sh
)
readonly BURP_HOME=${BURP_HOME:-/opt/kali-mcp/state/burp}
readonly BAKED_JAR=${BURP_JAR:-/opt/burp/burpsuite.jar}
readonly BAKED_EXT=${BURP_MCP_EXT_JAR:-/opt/burp/extensions/burp-mcp-all.jar}
readonly BAKED_PROXY=${BURP_MCP_PROXY_JAR:-/opt/burp/mcp-proxy-all.jar}
readonly MCP_PORT=${BURP_MCP_PORT:-9876}

log()  { printf 'kali-mcp: %s\n' "$*" >&2; }
fail() { printf 'kali-mcp: ERROR: %s\n' "$*" >&2; exit 1; }

eula_accepted() {
    local value
    value="$(printf '%s' "${BURP_ACCEPT_EULA:-${ACCEPT_EULA:-}}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|y) return 0 ;;
        *) return 1 ;;
    esac
}

load_pins() {
    local candidate
    for candidate in "${PINS_CANDIDATES[@]}"; do
        if [[ -r "$candidate" ]]; then
            # shellcheck disable=SC1090
            source "$candidate"
            return 0
        fi
    done
    return 1
}

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

require_hash() {
    local file="$1" expected="$2" label="$3"
    local actual
    actual="$(sha256_of "$file")"
    [[ "$actual" == "$expected" ]] \
        || fail "$label SHA-256 mismatch: got $actual want $expected"
}

fetch() {
    local url="$1" dest="$2"
    curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url"
}

resolve_or_empty() {
    local baked="$1" local_name="$2"
    if [[ -f "$baked" ]]; then
        printf '%s' "$baked"
        return 0
    fi
    if [[ -f "${BURP_HOME}/${local_name}" ]]; then
        printf '%s' "${BURP_HOME}/${local_name}"
        return 0
    fi
    return 1
}

write_user_config() {
    local ext_jar="$1" dest="$2"
    cat >"$dest" <<EOF
{
  "user_options": {
    "extender": {
      "extensions": [
        {
          "errors": "ui",
          "extension_file": "${ext_jar}",
          "extension_type": "java",
          "loaded": true,
          "name": "MCP Server",
          "output": "ui"
        }
      ],
      "settings": {
        "automatically_reload_extensions_on_startup": true,
        "automatically_update_bapps_on_startup": false
      }
    }
  }
}
EOF
}

prepare() {
    eula_accepted || fail "Burp will not start without BURP_ACCEPT_EULA=true \
(the operator must accept PortSwigger's EULA). Set KALI_MCP_DISABLE=burp to \
skip Burp, or BURP_MCP_URL to use an external instance."

    load_pins || fail "Burp pins file is missing (expected ${PINS_CANDIDATES[*]})"
    mkdir -p "$BURP_HOME" "${BURP_HOME}/extensions"
    chmod 0700 "$BURP_HOME"

    local jar ext proxy
    if ! jar="$(resolve_or_empty "$BAKED_JAR" "burpsuite.jar")"; then
        log "downloading Burp Suite Desktop ${BURP_VERSION} (~700MB)"
        fetch "$BURP_JAR_URL" "${BURP_HOME}/burpsuite.jar"
        jar="${BURP_HOME}/burpsuite.jar"
    fi
    require_hash "$jar" "$BURP_JAR_SHA256" "Burp JAR"

    if ! ext="$(resolve_or_empty "$BAKED_EXT" "extensions/burp-mcp-all.jar")"; then
        log "downloading official MCP BApp v1.3.0"
        fetch "$BAPP_URL" "${BURP_HOME}/mcp-server.bapp"
        require_hash "${BURP_HOME}/mcp-server.bapp" "$BAPP_SHA256" "MCP BApp"
        python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]+"/mcp-server.bapp").extract("burp-mcp-all.jar", sys.argv[1]+"/extensions")' "$BURP_HOME"
        require_hash "${BURP_HOME}/extensions/burp-mcp-all.jar" "$BURP_MCP_EXT_SHA256" "MCP extension JAR"
        ext="${BURP_HOME}/extensions/burp-mcp-all.jar"
    fi

    if ! proxy="$(resolve_or_empty "$BAKED_PROXY" "mcp-proxy-all.jar")"; then
        log "downloading MCP stdio proxy"
        fetch "$BURP_MCP_PROXY_URL" "${BURP_HOME}/mcp-proxy-all.jar"
        require_hash "${BURP_HOME}/mcp-proxy-all.jar" "$BURP_MCP_PROXY_SHA256" "MCP stdio proxy"
        proxy="${BURP_HOME}/mcp-proxy-all.jar"
    fi

    write_user_config "$ext" "${BURP_HOME}/user.json"

    # Paths the entrypoint exports for render-config.py.
    printf '%s\n' "$jar"   >"${BURP_HOME}/.jar"
    printf '%s\n' "$ext"   >"${BURP_HOME}/.ext"
    printf '%s\n' "$proxy" >"${BURP_HOME}/.proxy"
    log "Burp artifacts ready (jar=$(basename "$jar"))"
}

port_open() {
    python3 -c "import socket; s=socket.create_connection(('127.0.0.1', int('${MCP_PORT}')), 1); s.close()" 2>/dev/null
}

window_id() {
    local title="$1"
    local matches
    matches="$(DISPLAY="${DISPLAY:?}" xdotool search --name "$title" 2>/dev/null)"
    printf '%s\n' "${matches%%$'\n'*}"
}

click_window_percent() {
    local window="$1" x_percent="$2" y_percent="$3"
    local geometry x y width height focused=0
    geometry="$(DISPLAY="${DISPLAY:?}" xdotool getwindowgeometry --shell "$window")"
    x="$(awk -F= '$1 == "X" {print $2}' <<<"$geometry")"
    y="$(awk -F= '$1 == "Y" {print $2}' <<<"$geometry")"
    width="$(awk -F= '$1 == "WIDTH" {print $2}' <<<"$geometry")"
    height="$(awk -F= '$1 == "HEIGHT" {print $2}' <<<"$geometry")"
    # Java creates the top-level X window before it becomes focusable. Retry
    # that short race instead of letting X_SetInputFocus/BadMatch abort startup.
    for _ in $(seq 1 80); do
        if DISPLAY="$DISPLAY" xdotool windowfocus "$window" 2>/dev/null; then
            focused=1
            break
        fi
        sleep 0.1
    done
    [[ "$focused" -eq 1 ]] || return 1
    DISPLAY="$DISPLAY" xdotool mousemove \
        "$((x + width * x_percent / 100))" \
        "$((y + height * y_percent / 100))" click 1
}

complete_community_startup() {
    # Since 2026.7 the official "desktop" JAR contains both editions. Even
    # with EULA accepted it presents two startup pages. The pinned version and
    # fixed Xvfb geometry make these three clicks deterministic. They select
    # Community, its in-memory project, and Burp defaults. No project file is
    # passed because persistent projects are a Professional-only feature.
    command -v xdotool >/dev/null \
        || fail "xdotool is required for non-interactive Burp Community startup"

    local pid="$1" selector="" wizard="" i
    for i in $(seq 1 120); do
        kill -0 "$pid" 2>/dev/null || return 1
        port_open && return 0
        selector="$(window_id '^Burp Suite$' || true)"
        wizard="$(window_id '^Burp Suite Community Edition v' || true)"
        [[ -n "$selector" || -n "$wizard" ]] && break
        sleep 0.25
    done

    if [[ -n "$selector" ]]; then
        log "selecting Burp Suite Community Edition"
        click_window_percent "$selector" 46 87
    fi

    wizard=""
    for i in $(seq 1 120); do
        kill -0 "$pid" 2>/dev/null || return 1
        port_open && return 0
        wizard="$(window_id '^Burp Suite Community Edition v' || true)"
        [[ -n "$wizard" ]] && break
        sleep 0.25
    done
    [[ -n "$wizard" ]] || return 1

    log "selecting Burp temporary project"
    click_window_percent "$wizard" 93 95
    sleep 1
    log "starting Burp with default configuration"
    click_window_percent "$wizard" 91 95
}

start() {
    [[ -f "${BURP_HOME}/.jar" && -f "${BURP_HOME}/user.json" ]] \
        || fail "start-burp.sh prepare has not run"

    local jar
    jar="$(<"${BURP_HOME}/.jar")"
    command -v java >/dev/null || fail "java is not on PATH; Burp needs Java 21"

    local heap=${BURP_HEAP:-2g}
    local logfile=${BURP_LOG:-/var/log/burp.log}
    mkdir -p "$(dirname "$logfile")"

    local -a java_opts=("-Xmx${heap}")
    local headless
    headless="$(printf '%s' "${BURP_HEADLESS:-xvfb}" | tr '[:upper:]' '[:lower:]')"
    case "$headless" in
        0|false|no|off) ;;
        1|true|yes|on|xvfb)
            command -v Xvfb >/dev/null || fail "BURP_HEADLESS=xvfb but Xvfb is not installed"
            local display=${BURP_XVFB_DISPLAY:-:99}
            if ! xdpyinfo -display "$display" >/dev/null 2>&1; then
                Xvfb "$display" -screen 0 1280x720x24 -nolisten tcp \
                    >/var/log/xvfb.log 2>&1 &
                local xvfb_pid=$!
                for _ in $(seq 1 50); do
                    xdpyinfo -display "$display" >/dev/null 2>&1 && break
                    kill -0 "$xvfb_pid" 2>/dev/null \
                        || fail "Xvfb exited before display ${display} became ready"
                    sleep 0.1
                done
                xdpyinfo -display "$display" >/dev/null 2>&1 \
                    || fail "Xvfb display ${display} did not become ready"
            fi
            export DISPLAY=$display
            ;;
        *) fail "BURP_HEADLESS=${BURP_HEADLESS:-} must be true, false, or xvfb" ;;
    esac

    log "starting Burp Suite headless on 127.0.0.1:${MCP_PORT} (heap=${heap})"
    # HOME is pinned so Burp preferences land on the volume, not in the image.
    #
    # --use-defaults selects the safe default configuration after the Community
    # startup pages. --user-config-file loads the official MCP BApp. The undocumented
    # --i-accept-the-license-agreement flag is what nixpkgs uses on the
    # same unified desktop JAR line; BURP_ACCEPT_EULA is the operator's
    # recorded acceptance of that EULA.
    HOME="$BURP_HOME" java "${java_opts[@]}" -jar "$jar" \
        --i-accept-the-license-agreement \
        --suppress-jre-check \
        --disable-check-for-updates-dialog \
        --disable-auto-update \
        --use-defaults \
        --user-config-file="${BURP_HOME}/user.json" \
        >>"$logfile" 2>&1 </dev/null &
    local pid=$!
    echo "$pid" >"${BURP_HOME}/burp.pid"

    if [[ -n "${DISPLAY:-}" ]]; then
        complete_community_startup "$pid" \
            || fail "could not complete Burp Community startup non-interactively"
    fi
}

wait_ready() {
    local seconds=${BURP_READY_TIMEOUT:-180}
    local pidfile="${BURP_HOME}/burp.pid"
    [[ -f "$pidfile" ]] || fail "Burp pid file is missing; start-burp.sh start has not run"
    local pid
    pid="$(<"$pidfile")"
    log "waiting for Burp MCP on 127.0.0.1:${MCP_PORT} (up to ${seconds}s)"
    local i
    for i in $(seq 1 "$seconds"); do
        if ! kill -0 "$pid" 2>/dev/null; then
            fail "Burp process ${pid} exited before MCP listened. Last log lines: \
$(tail -n 40 "${BURP_LOG:-/var/log/burp.log}" 2>/dev/null || true)"
        fi
        if port_open; then
            log "Burp MCP is listening on 127.0.0.1:${MCP_PORT}"
            return 0
        fi
        sleep 1
    done
    fail "Burp MCP did not listen on 127.0.0.1:${MCP_PORT} within ${seconds}s. Last log lines: \
$(tail -n 40 "${BURP_LOG:-/var/log/burp.log}" 2>/dev/null || true)"
}

usage() { fail "usage: start-burp.sh prepare|start|wait"; }

case "${1:-}" in
    prepare) prepare ;;
    start)   start ;;
    wait)    wait_ready ;;
    *)       usage ;;
esac
