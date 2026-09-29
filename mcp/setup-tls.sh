#!/bin/bash
# Prepare the TLS certificate used by the public MCP listener.
#
# Source this file and call setup_tls. It exports absolute certificate/key
# paths for render-config.py. Existing operator-provided files are validated
# and never overwritten; otherwise a private CA and server certificate are
# generated in the persistent SSL volume.

set -euo pipefail

tls_log()  { printf 'kali-mcp: %s\n' "$*" >&2; }
tls_fail() { printf 'kali-mcp: ERROR: %s\n' "$*" >&2; return 1; }

tls_enabled() {
    local value
    value="$(printf '%s' "${MCP_GATEWAY_USE_TLS:-true}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|y|on) return 0 ;;
        0|false|no|n|off) return 1 ;;
        *)
            tls_fail "MCP_GATEWAY_USE_TLS=${MCP_GATEWAY_USE_TLS:-} must be true or false"
            return 2
            ;;
    esac
}

absolute_tls_path() {
    local path="$1"
    case "$path" in
        /*) printf '%s' "$path" ;;
        *) printf '%s/%s' "${KALI_MCP_HOME:-/opt/kali-mcp}" "$path" ;;
    esac
}

append_public_san() {
    local sans="$1" public_name="${MCP_GATEWAY_IP:-}"
    [[ -n "$public_name" && "$public_name" != "0.0.0.0" && "$public_name" != "::" ]] \
        || { printf '%s' "$sans"; return; }

    local san_type=DNS
    if python3 - "$public_name" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY
    then
        san_type=IP
    fi

    case ",$sans," in
        *",${san_type}:${public_name},"*) printf '%s' "$sans" ;;
        *) printf '%s,%s:%s' "$sans" "$san_type" "$public_name" ;;
    esac
}

validate_tls_pair() {
    local cert="$1" key="$2"
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 \
        || tls_fail "TLS certificate $cert is not a valid PEM X.509 certificate"
    openssl pkey -in "$key" -noout >/dev/null 2>&1 \
        || tls_fail "TLS key $key is not a valid PEM private key"

    local cert_public key_public
    cert_public="$(openssl x509 -in "$cert" -pubkey -noout | openssl sha256)"
    key_public="$(openssl pkey -in "$key" -pubout | openssl sha256)"
    [[ "$cert_public" == "$key_public" ]] \
        || tls_fail "TLS certificate $cert and key $key do not match"
}

generate_tls_pair() {
    local cert="$1" key="$2" ca_output="$3"
    local directory key_directory ca_directory ca_key ca_cert csr ext cert_tmp key_tmp
    directory="$(dirname "$cert")"
    key_directory="$(dirname "$key")"
    ca_directory="$(dirname "$ca_output")"
    mkdir -p "$directory" "$key_directory" "$ca_directory"

    ca_key="${directory}/service_ca.key.tmp"
    ca_cert="${ca_output}.tmp"
    csr="${directory}/service.csr.tmp"
    ext="${directory}/service.ext.tmp"
    cert_tmp="${cert}.tmp"
    key_tmp="${key}.tmp"
    rm -f "$ca_key" "$ca_cert" "$csr" "$ext" "$cert_tmp" "$key_tmp"

    local sans
    sans="${MCP_GATEWAY_TLS_SAN:-DNS:kali-mcp,DNS:localhost,IP:127.0.0.1,IP:::1}"
    sans="$(append_public_san "$sans")"
    tls_log "generating TLS certificate for ${sans}"

    umask 077
    openssl genrsa -out "$ca_key" 4096 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -sha256 \
        -key "$ca_key" \
        -subj "/C=US/O=PentAGI/OU=Kali MCP/CN=Kali MCP Local CA" \
        -out "$ca_cert" >/dev/null 2>&1
    openssl req -newkey rsa:4096 -sha256 -nodes \
        -keyout "$key_tmp" \
        -subj "/C=US/O=PentAGI/OU=Kali MCP/CN=kali-mcp" \
        -out "$csr" >/dev/null 2>&1
    {
        printf 'subjectAltName=%s\n' "$sans"
        printf 'basicConstraints=critical,CA:FALSE\n'
        printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
        printf 'extendedKeyUsage=serverAuth\n'
    } >"$ext"
    openssl x509 -req -days 730 -sha256 \
        -in "$csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
        -extfile "$ext" -out "$cert_tmp" >/dev/null 2>&1

    # Include the generated CA so operators can copy one PEM as a trust bundle.
    cat "$ca_cert" >>"$cert_tmp"
    chmod 0600 "$key_tmp"
    chmod 0644 "$cert_tmp" "$ca_cert"
    mv -f "$key_tmp" "$key"
    mv -f "$cert_tmp" "$cert"
    mv -f "$ca_cert" "$ca_output"
    rm -f "$ca_key" "$csr" "$ext" "${ca_cert%.*}.srl"
    validate_tls_pair "$cert" "$key"
}

setup_tls() {
    local tls_status
    if tls_enabled; then
        tls_status=0
    else
        tls_status=$?
    fi
    if [[ "$tls_status" -eq 1 ]]; then
        export MCP_GATEWAY_USE_TLS=false
        tls_log "TLS disabled; serving plaintext MCP"
        return 0
    elif [[ "$tls_status" -ne 0 ]]; then
        return 1
    fi

    export MCP_GATEWAY_USE_TLS=true
    MCP_GATEWAY_TLS_CERT="$(absolute_tls_path "${MCP_GATEWAY_TLS_CERT:-ssl/server.crt}")"
    MCP_GATEWAY_TLS_KEY="$(absolute_tls_path "${MCP_GATEWAY_TLS_KEY:-ssl/server.key}")"
    MCP_GATEWAY_TLS_CA="$(absolute_tls_path "${MCP_GATEWAY_TLS_CA:-ssl/service_ca.crt}")"
    export MCP_GATEWAY_TLS_CERT MCP_GATEWAY_TLS_KEY MCP_GATEWAY_TLS_CA

    if [[ -f "$MCP_GATEWAY_TLS_CERT" && -f "$MCP_GATEWAY_TLS_KEY" ]]; then
        validate_tls_pair "$MCP_GATEWAY_TLS_CERT" "$MCP_GATEWAY_TLS_KEY"
        tls_log "using existing TLS certificate $MCP_GATEWAY_TLS_CERT"
    elif [[ -e "$MCP_GATEWAY_TLS_CERT" || -e "$MCP_GATEWAY_TLS_KEY" ]]; then
        tls_fail "TLS certificate and key must both exist or both be absent"
    else
        generate_tls_pair \
            "$MCP_GATEWAY_TLS_CERT" "$MCP_GATEWAY_TLS_KEY" "$MCP_GATEWAY_TLS_CA"
        tls_log "generated TLS certificate $MCP_GATEWAY_TLS_CERT"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    setup_tls
fi
