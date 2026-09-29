FROM kalilinux/kali-rolling AS base

# Basic packages
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        # System utilities
        curl wget git vim nano net-tools iproute2 dnsutils bind9-host \
        jq tmux screen netcat-traditional socat nmap nmap-common masscan \
        iputils-ping \
        # Network reconnaissance and scanning
        amass gobuster ffuf dirb nikto whatweb theharvester dnsx \
        arp-scan arping fping hping3 netdiscover nbtscan onesixtyone \
        sublist3r dnsrecon fierce ncrack ike-scan \
        # Web testing
        sqlmap wfuzz nuclei feroxbuster dirsearch zaproxy \
        # Brute force and passwords
        hydra john john-data crunch medusa patator wordlists \
        hashid hash-identifier hashcat hashcat-data hashcat-utils \
        # Exploitation and frameworks
        metasploit-framework impacket-scripts evil-winrm \
        bloodhound.py crackmapexec netexec responder \
        # Post-exploitation and persistence
        powershell-empire starkiller unicorn-magic \
        weevely webshells mimikatz windows-binaries \
        # Cryptography and steganography
        steghide stegosuite binwalk foremost bulk-extractor \
        # Traffic analysis and proxies
        wireshark-common tshark tcpdump tcpreplay mitmproxy \
        proxychains4 proxytunnel stunnel4 sslh sslscan sslsplit \
        # Tunneling
        dns2tcp iodine ptunnel pwnat dnscat2 chisel \
        # LDAP and AD
        ldap-utils smbclient smbmap enum4linux certipy-ad python3-ldapdomaindump polenum \
        # Databases
        sqsh default-mysql-client postgresql-client \
        # Reverse engineering
        radare2 gdb-multiarch file binutils ropper python3-ropgadget \
        # Other useful tools
        exploitdb commix davtest skipfish wpscan assetfinder \
        # Recent Kali additions (from the 2025.x–2026.x release notes)
        # Active Directory and Kerberos
        ldeep krbrelayx bloodhound-ce-python \
        # Pivoting and tunneling
        ligolo-ng-common-binaries \
        # Web exploitation and URL-list hygiene
        xsstrike sstimap crlfuzz uro \
        # Password attacks
        bopscrk legba \
        # Malicious-document analysis
        oletools \
        # SecLists wordlists (referenced by the README, test-tools.sh, and the ffuf MCP server)
        seclists \
        # Python interpreter and libraries
        python3-pip python3-venv python3-dev \
        # Build tools
        build-essential gcc g++ make cmake libpcap-dev \
        # Network utilities
        ncat socat netcat-openbsd rlwrap telnet openssh-client \
        # Compression and archives
        unzip zip p7zip-full unrar-free && \
    # Fix ZAP shell script to mimic previous version (for command completion from old LLMs)
    ln -s /usr/bin/zaproxy /usr/bin/zap.sh && \
    # Dependencies for docker installation
    apt install -y --no-install-recommends \
        apt-transport-https ca-certificates gnupg lsb-release && \
    update-ca-certificates --fresh && \
    apt upgrade -y && \
    # Docker cli only
    ARCH=$(dpkg --print-architecture) && \
    echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bookworm stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
        gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    apt update && apt install -y docker-ce-cli && \
    apt clean && rm -rf /var/lib/apt/lists/*

# Install Go for extra tools
RUN ARCH=$(dpkg --print-architecture) && \
    wget -O go.tar.gz "https://go.dev/dl/go1.27.1.linux-${ARCH}.tar.gz" && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz && \
    mkdir -p /root/go/bin /root/go/src /root/go/pkg

# Create Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV --copies --clear

# Add venv to PATH
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Upgrade pip to latest version
RUN python -m ensurepip --upgrade && \
    python -m pip install --upgrade pip setuptools wheel

# Install additional Python packages in virtual environment
RUN pip install --no-cache-dir \
    paramiko \
    pexpect \
    beautifulsoup4 \
    shodan \
    censys \
    ldap3 \
    pywinrm \
    pwntools \
    impacket \
    scapy

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"
ENV CGO_ENABLED=1

RUN echo "export PATH=$VIRTUAL_ENV/bin:\$PATH" >> /root/.bashrc && \
    echo "export VIRTUAL_ENV=$VIRTUAL_ENV" >> /root/.bashrc && \
    echo "export PATH=/usr/local/go/bin:\$PATH" >> /root/.bashrc && \
    echo "export GOPATH=/root/go" >> /root/.bashrc && \
    echo "export PATH=\$GOPATH/bin:\$PATH" >> /root/.bashrc && \
    mkdir -p ~/.config/pip && \
    echo "[global]" > ~/.config/pip/pip.conf && \
    echo "break-system-packages = true" >> ~/.config/pip/pip.conf

# Install additional Go tools
RUN set -e && \
    /usr/local/go/bin/go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    /usr/local/go/bin/go install github.com/ffuf/ffuf/v2@latest && \
    /usr/local/go/bin/go install github.com/tomnomnom/waybackurls@latest && \
    /usr/local/go/bin/go install github.com/lc/gau/v2/cmd/gau@latest && \
    /usr/local/go/bin/go install github.com/hakluke/hakrawler@latest && \
    # Additional ProjectDiscovery tools (keyless recon/scanning chain)
    /usr/local/go/bin/go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest && \
    rm -rf /root/go/pkg/*

# ligolo-ng ships prebuilt agent/proxy binaries under /usr/share (the Kali
# `ligolo-ng-common-binaries` package). Expose the native-architecture proxy and
# agent on PATH so they are runnable by name (ligolo-proxy / ligolo-agent).
RUN set -e; ARCH=$(dpkg --print-architecture); \
    proxy=$(ls /usr/share/ligolo-ng-common-binaries/ligolo-ng_proxy_*_linux_${ARCH} 2>/dev/null | head -1); \
    agent=$(ls /usr/share/ligolo-ng-common-binaries/ligolo-ng_agent_*_linux_${ARCH} 2>/dev/null | head -1); \
    [ -n "$proxy" ] && ln -sf "$proxy" /usr/local/bin/ligolo-proxy; \
    [ -n "$agent" ] && ln -sf "$agent" /usr/local/bin/ligolo-agent; \
    ls -l /usr/local/bin/ligolo-proxy /usr/local/bin/ligolo-agent

# Set working directory
RUN mkdir -p /work
WORKDIR /work

# Default command
CMD ["/bin/bash"]

# Systemd-enabled Kali Linux container using docker-systemctl-replacement
FROM base AS systemd

# Install systemd packages
RUN apt update && apt upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        systemd systemd-sysv dbus python3 && \
    apt clean && rm -rf /var/lib/apt/lists/*

# Install docker-systemctl-replacement
RUN wget -O /usr/local/bin/systemctl \
    https://raw.githubusercontent.com/gdraheim/docker-systemctl-replacement/master/files/docker/systemctl3.py && \
    chmod +x /usr/local/bin/systemctl

# Configure systemd for container use
ENV container=docker

# Configure systemd services for container environment
RUN systemctl mask dev-hugepages.mount sys-fs-fuse-connections.mount && \
    systemctl mask systemd-remount-fs.service dev-mqueue.mount && \
    systemctl mask systemd-logind.service && \
    systemctl mask getty.target && \
    systemctl mask console-getty.service

# Copy and install container entrypoint script
COPY container-entrypoint.sh /usr/local/bin/container-entrypoint
RUN chmod +x /usr/local/bin/container-entrypoint

# Use custom entrypoint
ENTRYPOINT ["/usr/local/bin/container-entrypoint"]

# Sandbox-policy test image. Deliberately NOT built from `base`: this image only
# has to reach a Docker daemon and speak HTTP to it, and PentAGI pulls it into
# the sandbox on every startup check, so its size is latency the operator pays
# for. The penetration-testing tooling the checks exercise comes from the nested
# containers they create, not from here.
FROM kalilinux/kali-rolling AS test

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # docker-cli, not docker.io: the daemon under test is somewhere else
        docker-cli \
        # the checks talk to the Docker API directly, over mTLS
        curl ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /work
WORKDIR /work

CMD ["/bin/bash"]

# ---------------------------------------------------------------------------
# MCP gateway image (tag: mcp).
#
# vxcontrol/kali-linux with an authenticated MCP gateway on top: one HTTPS
# endpoint, one bearer token, ~150 tools from 15 MCP servers wrapping the
# penetration-testing binaries this image already ships (nmap, masscan,
# whatweb, nuclei, sqlmap, ffuf, waybackurls, searchsploit, binwalk, hashcat,
# tshark, metasploit, the ProjectDiscovery chain, Chromium) plus Burp Suite.
#
# It is built FROM `base` -- not from kali-rolling -- because every binary the
# servers drive already lives in the base image; this stage only adds the MCP
# layer (an aggregating gateway plus the stdio servers). Layers are ordered
# stable -> volatile so editing the gateway config or entrypoint rebuilds only
# the last two layers. Config and scripts live in ./mcp and are COPYed in.
FROM base AS mcp

LABEL org.opencontainers.image.title="Kali Linux MCP Gateway" \
      org.opencontainers.image.description="Kali penetration-testing tools exposed as one token-authenticated MCP endpoint" \
      org.opencontainers.image.base.name="docker.io/vxcontrol/kali-linux:latest" \
      org.opencontainers.image.licenses="MIT"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. OS packages the base image does not carry.
#    tini: a PID 1 that reaps orphans and, with -g, relays signals to the whole
#    process group, so msfrpcd is asked to stop rather than dying with the
#    container. agentgateway handles SIGTERM itself, so this is a safety net for
#    the daemon started beside the gateway, not the reason shutdown works.
#    xvfb/xauth/xdotool: the Swing display and non-interactive clicks Burp needs.
#    chromium (+ fonts): the real browser the playwright MCP server drives via
#    --executable-path=/usr/bin/chromium; not in the lean base image.
#    xz-utils: unpacking the Node.js tarball below.
# ---------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl tini xz-utils xvfb xauth xdotool chromium fonts-liberation && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Node.js.
#    Kali ships /usr/bin/node but has no `npm` package at all
#    ("E: Package 'npm' has no installation candidate"), and @playwright/mcp is
#    distributed only on npm. So install the upstream Node tarball, which
#    carries npm and npx, into /opt/node and put it FIRST on PATH.
# ---------------------------------------------------------------------------
ARG NODE_VERSION=22.21.1
ARG NODE_SHA256_ARM64=e660365729b434af422bcd2e8e14228637ecf24a1de2cd7c916ad48f2a0521e1
ARG NODE_SHA256_AMD64=680d3f30b24a7ff24b98db5e96f294c0070f8f9078df658da1bce1b9c9873c88
# PATH is set BEFORE the install so the `npm` verification below resolves: npm is
# a script with `#!/usr/bin/env node`, and the lean base image carries no
# /usr/bin/node, so `node` must already be on PATH here (a missing PATH entry
# for a not-yet-created dir is harmless).
ENV PATH="/opt/node/bin:${PATH}"
RUN set -euo pipefail; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) node_arch=arm64; sha="${NODE_SHA256_ARM64}" ;; \
      amd64) node_arch=x64;   sha="${NODE_SHA256_AMD64}" ;; \
      *) echo "kali-mcp: unsupported architecture '$arch'" >&2; exit 1 ;; \
    esac; \
    url="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fsSL -o /tmp/node.tar.xz "$url"; \
    echo "${sha}  /tmp/node.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.xz; \
    node --version; \
    npm --version

# ---------------------------------------------------------------------------
# 3. agentgateway -- the MCP gateway itself.
#    Upstream publishes static linux binaries, so there is no Rust toolchain in
#    this image. The checksum is pinned per architecture: a silently swapped
#    gateway binary is the one thing that would compromise every tool at once.
# ---------------------------------------------------------------------------
ARG AGENTGATEWAY_VERSION=1.5.0
ARG AGENTGATEWAY_SHA256_ARM64=61f12dbb99669aa4b97b85a0040183fe4b098fa0a82a8c389665fe606517c13e
ARG AGENTGATEWAY_SHA256_AMD64=daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b
RUN set -euo pipefail; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) sha="${AGENTGATEWAY_SHA256_ARM64}" ;; \
      amd64) sha="${AGENTGATEWAY_SHA256_AMD64}" ;; \
      *) echo "kali-mcp: unsupported architecture '$arch'" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/agentgateway \
      "https://github.com/agentgateway/agentgateway/releases/download/v${AGENTGATEWAY_VERSION}/agentgateway-linux-${arch}"; \
    echo "${sha}  /usr/local/bin/agentgateway" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/agentgateway; \
    agentgateway --version

# ---------------------------------------------------------------------------
# 4. Python dependencies, into the venv the base image already puts on PATH.
#
#    fastapi/uvicorn are here because MetasploitMCP imports them at module
#    scope for its HTTP transport, so `--transport stdio` still needs them
#    present or the server dies with ModuleNotFoundError before it says a word.
#
#    mcp is pinned below 2.0 ON PURPOSE. The MCP Python SDK 2.x renamed
#    FastMCP to MCPServer and moved mcp.server.fastmcp; every vendored server
#    below is written against the 1.x API and dies at import on 2.x with
#    "No module named 'mcp.server.fastmcp'". fastmcp is capped below 4 for the
#    same reason -- 4.x follows the SDK to 2.x.
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir \
      "mcp>=1.9,<2" \
      "fastmcp>=2.10.3,<4" \
      "pydantic>=2" \
      "pydantic-settings>=2" \
      "pymetasploit3>=1.0.6" \
      "python-dotenv>=1.0" \
      "PyYAML>=6" \
      "mcp-wireshark==0.5.0" \
      "fastapi>=0.95.0" \
      "uvicorn>=0.22.0" && \
    python3 -c "import mcp.server.stdio, mcp.server.fastmcp, yaml, pymetasploit3, fastapi; print('python mcp stack ok')"

# ---------------------------------------------------------------------------
# 5. Vendored MCP servers, pinned to exact commits.
#    Each is fetched by SHA rather than by branch so a rebuild of this image is
#    reproducible and an upstream force-push cannot change what we ship.
# ---------------------------------------------------------------------------
ARG SECURITY_HUB_SHA=b6800740da9965e9dd3fde2ec3cf4c775c358f72
ARG METASPLOIT_MCP_SHA=afc792d9ee17540f8a94349b20a3b203e6961a92
ARG HASHCAT_MCP_SHA=41b6fc6d0cf072178a9dc9ebc8ffff1b12705d98
ARG PD_TOOLS_MCP_SHA=0698fb966114435233bf20e85483694d6ef0e450
RUN set -euo pipefail; \
    fetch() { \
      local dir="$1" repo="$2" sha="$3"; \
      mkdir -p "$dir"; \
      git -C "$dir" init -q; \
      git -C "$dir" remote add origin "$repo"; \
      git -C "$dir" fetch -q --depth 1 origin "$sha"; \
      git -C "$dir" checkout -q FETCH_HEAD; \
      rm -rf "$dir/.git"; \
    }; \
    fetch /opt/kali-mcp/servers/security-hub https://github.com/FuzzingLabs/mcp-security-hub.git "${SECURITY_HUB_SHA}"; \
    fetch /opt/kali-mcp/servers/metasploit-mcp https://github.com/GH05TCREW/MetasploitMCP.git "${METASPLOIT_MCP_SHA}"; \
    fetch /opt/kali-mcp/servers/hashcat-mcp   https://github.com/MorDavid/hashcat-mcp.git   "${HASHCAT_MCP_SHA}"; \
    fetch /opt/kali-mcp/servers/pd-tools-mcp  https://github.com/intelligent-ears/pd-tools-mcp.git "${PD_TOOLS_MCP_SHA}"; \
    # Every server.py the gateway config names must exist now, not at runtime.
    for s in reconnaissance/nmap-mcp reconnaissance/masscan-mcp reconnaissance/whatweb-mcp \
             web-security/nuclei-mcp web-security/sqlmap-mcp web-security/ffuf-mcp \
             web-security/waybackurls-mcp exploitation/searchsploit-mcp \
             binary-analysis/binwalk-mcp; do \
      test -f "/opt/kali-mcp/servers/security-hub/$s/server.py" || { echo "missing $s/server.py" >&2; exit 1; }; \
    done; \
    test -f /opt/kali-mcp/servers/metasploit-mcp/MetasploitMCP.py; \
    test -f /opt/kali-mcp/servers/hashcat-mcp/hashcat_mcp_server.py; \
    test -f /opt/kali-mcp/servers/hashcat-mcp/hashcat_modes.csv

# ---------------------------------------------------------------------------
# 6. npm-installed servers.
#    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD keeps Playwright from pulling its own
#    ~400MB browser bundle: this image installs Chromium above, and the gateway
#    config points Playwright at /usr/bin/chromium. That also avoids depending
#    on Playwright publishing a browser build for this architecture.
#    pd-tools-mcp is TypeScript with no published package, so it is built here.
# ---------------------------------------------------------------------------
ARG PLAYWRIGHT_MCP_VERSION=0.0.80
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN set -euo pipefail; \
    npm install -g --no-fund --no-audit "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}"; \
    cd /opt/kali-mcp/servers/pd-tools-mcp; \
    npm install --no-fund --no-audit; \
    npm run build; \
    test -f /opt/kali-mcp/servers/pd-tools-mcp/build/index.js; \
    npm cache clean --force

# ---------------------------------------------------------------------------
# 7. nuclei templates.
#    nuclei-mcp passes -templates <dir> only when the directory exists; without
#    it nuclei would try to download templates on the first scan, which fails on
#    an air-gapped run and makes the first tool call take minutes. Baked in by
#    default; set --build-arg WITH_NUCLEI_TEMPLATES=false for a smaller image
#    whose nuclei server fetches templates on first use instead.
# ---------------------------------------------------------------------------
ARG WITH_NUCLEI_TEMPLATES=true
RUN set -euo pipefail; \
    if [ "${WITH_NUCLEI_TEMPLATES}" = "true" ]; then \
      nuclei -ut; \
      # `nuclei -ut` exits 0 even when the download fails -- it only WARNs, and
      # it creates the (empty) directory either way, so `test -d` would pass on
      # a failed download and we would ship an image that claims to have
      # templates and has none. Count them instead. The usual cause of an empty
      # tree is GitHub rate-limiting the release API from this build host;
      # retry later, or build with --build-arg WITH_NUCLEI_TEMPLATES=false.
      count="$(find /root/nuclei-templates -name '*.yaml' | wc -l)"; \
      if [ "$count" -lt 100 ]; then \
        echo "kali-mcp: nuclei template download produced $count templates; see the note above" >&2; \
        exit 1; \
      fi; \
      echo "kali-mcp: nuclei templates installed"; \
    fi

# ---------------------------------------------------------------------------
# 7b. Burp Suite Desktop + official MCP BApp + stdio proxy.
#     Pinned artifacts (versions and SHA-256 in mcp/burp/pins.sh). The JAR is
#     ~700MB; WITH_BURP=false skips the download and leaves start-burp.sh to
#     fetch the same pinned files into BURP_HOME on first start.
# ---------------------------------------------------------------------------
COPY mcp/burp/pins.sh /opt/burp/pins.sh
ARG WITH_BURP=true
RUN set -euo pipefail; \
    # shellcheck disable=SC1091
    . /opt/burp/pins.sh; \
    mkdir -p /opt/burp/extensions; \
    if [ "${WITH_BURP}" != "true" ]; then \
      echo "kali-mcp: skipping Burp artifacts (WITH_BURP=${WITH_BURP})"; \
      exit 0; \
    fi; \
    curl -fL --retry 3 --retry-delay 2 -o /opt/burp/burpsuite.jar "$BURP_JAR_URL"; \
    echo "${BURP_JAR_SHA256}  /opt/burp/burpsuite.jar" | sha256sum -c -; \
    curl -fL --retry 3 --retry-delay 2 -o /tmp/mcp-server.bapp "$BAPP_URL"; \
    echo "${BAPP_SHA256}  /tmp/mcp-server.bapp" | sha256sum -c -; \
    python3 -c 'import zipfile; zipfile.ZipFile("/tmp/mcp-server.bapp").extract("burp-mcp-all.jar", "/opt/burp/extensions")'; \
    echo "${BURP_MCP_EXT_SHA256}  /opt/burp/extensions/burp-mcp-all.jar" | sha256sum -c -; \
    curl -fL --retry 3 --retry-delay 2 -o /opt/burp/mcp-proxy-all.jar "$BURP_MCP_PROXY_URL"; \
    echo "${BURP_MCP_PROXY_SHA256}  /opt/burp/mcp-proxy-all.jar" | sha256sum -c -; \
    rm -f /tmp/mcp-server.bapp; \
    echo "kali-mcp: Burp ${BURP_VERSION} and MCP v1.3.0 artifacts installed"

# The sources above are pinned, but a few upstream bugs affect this runtime.
# Exact replacements fail closed when an upstream pin changes unexpectedly.
COPY mcp/patch-vendored.py /tmp/patch-vendored.py
RUN python3 /tmp/patch-vendored.py && rm -f /tmp/patch-vendored.py

# ---------------------------------------------------------------------------
# 8. Our own files. Last, so editing them is a two-layer rebuild.
# ---------------------------------------------------------------------------
RUN mkdir -p /opt/kali-mcp/bin \
             /opt/kali-mcp/ssl \
             /opt/kali-mcp/output/{nmap,masscan,whatweb,nuclei,sqlmap,ffuf,waybackurls,searchsploit,binwalk,playwright,payloads} \
             /opt/kali-mcp/state/hashcat \
             /opt/kali-mcp/state/burp \
             /run/kali-mcp && \
    chmod 0700 /run/kali-mcp

# Two shims for upstream servers that hardcode paths from their own container.
#
# ffuf-mcp takes its wordlist *directory listing* from FFUF_WORDLISTS_DIR but
# resolves its seven named builtin wordlists against literal /app/wordlists/...
# paths. Point those at Kali's real wordlist tree so `ffuf_list_wordlists`
# reports them as available instead of all-missing. Kali has no top-level
# common.txt and files dirbuster's list under seclists, hence the two aliases.
RUN set -euo pipefail; \
    mkdir -p /app/wordlists/dirbuster; \
    ln -sfn /usr/share/wordlists/dirb           /app/wordlists/dirb; \
    ln -sfn /usr/share/wordlists/seclists       /app/wordlists/seclists; \
    ln -sfn /usr/share/wordlists/dirb/common.txt /app/wordlists/common.txt; \
    ln -sfn /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
            /app/wordlists/dirbuster/directory-list-2.3-medium.txt; \
    for w in common.txt dirb/common.txt dirbuster/directory-list-2.3-medium.txt \
             seclists/Discovery/Web-Content/raft-large-directories.txt \
             seclists/Discovery/Web-Content/raft-large-files.txt \
             seclists/Discovery/DNS/subdomains-top1million-5000.txt \
             seclists/Discovery/Web-Content/burp-parameter-names.txt; do \
      test -r "/app/wordlists/$w" || { echo "ffuf wordlist shim broken: $w" >&2; exit 1; }; \
    done

# hashcat-mcp calls hashcat through $HASHCAT_PATH everywhere except its
# --identify path, which execs the literal name "hashcat.exe" (a Windows-ism
# upstream never ported). It also uses dirname($HASHCAT_PATH) as the working
# directory it writes temp hash files into -- which would be /usr/bin. This
# directory answers both: it is on PATH for that server only, carries the .exe
# alias, and is writable scratch space.
RUN set -euo pipefail; \
    mkdir -p /opt/kali-mcp/hashcat-home; \
    ln -sfn /usr/bin/hashcat /opt/kali-mcp/hashcat-home/hashcat; \
    ln -sfn /usr/bin/hashcat /opt/kali-mcp/hashcat-home/hashcat.exe; \
    PATH=/opt/kali-mcp/hashcat-home:$PATH hashcat.exe --version

COPY mcp/gateway.yaml /opt/kali-mcp/gateway.yaml
COPY mcp/render-config.py /opt/kali-mcp/bin/render-config.py
COPY mcp/entrypoint.sh /opt/kali-mcp/bin/entrypoint.sh
COPY mcp/setup-tls.sh /opt/kali-mcp/bin/setup-tls.sh
COPY mcp/start-burp.sh /opt/kali-mcp/bin/start-burp.sh
COPY mcp/burp/pins.sh /opt/kali-mcp/burp/pins.sh
RUN chmod 0755 /opt/kali-mcp/bin/entrypoint.sh \
               /opt/kali-mcp/bin/render-config.py \
               /opt/kali-mcp/bin/setup-tls.sh \
               /opt/kali-mcp/bin/start-burp.sh && \
    chmod 0644 /opt/kali-mcp/gateway.yaml /opt/kali-mcp/burp/pins.sh && \
    python3 -c "import yaml,sys; yaml.safe_load(open('/opt/kali-mcp/gateway.yaml'))" && \
    echo "gateway.yaml parses"

ENV KALI_MCP_HOME=/opt/kali-mcp \
    MCP_GATEWAY_PORT=8081 \
    MCP_GATEWAY_USE_TLS=true \
    MCP_GATEWAY_TLS_CERT=/opt/kali-mcp/ssl/server.crt \
    MCP_GATEWAY_TLS_KEY=/opt/kali-mcp/ssl/server.key \
    MCP_GATEWAY_TLS_CA=/opt/kali-mcp/ssl/service_ca.crt \
    PYTHONUNBUFFERED=1

EXPOSE 8081

# Agentgateway listens on [::]:15021. Linux normally maps IPv4 into that socket,
# but hosts with net.ipv6.bindv6only=1 reject 127.0.0.1. Try native IPv6 first
# and retain an IPv4 fallback for environments where IPv6 is disabled.
HEALTHCHECK --interval=30s --timeout=5s --start-period=240s --retries=3 \
  CMD curl -g -fsS 'http://[::1]:15021/healthz/ready' >/dev/null || \
      curl -4 -fsS http://127.0.0.1:15021/healthz/ready >/dev/null || exit 1

WORKDIR /work

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/kali-mcp/bin/entrypoint.sh"]
