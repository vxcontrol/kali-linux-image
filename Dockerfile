FROM kalilinux/kali-rolling AS base

# Basic packages
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        # System utilities
        curl wget git vim nano net-tools iproute2 dnsutils bind9-host \
        jq tmux screen netcat-traditional socat nmap nmap-common masscan \
        # Network reconnaissance and scanning
        amass gobuster ffuf dirb nikto whatweb theharvester dnsx \
        arp-scan arping fping hping3 netdiscover nbtscan onesixtyone \
        sublist3r dnsrecon fierce ncrack \
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
        ldap-utils smbclient smbmap enum4linux certipy-ad python3-ldapdomaindump \
        # Databases
        sqsh default-mysql-client postgresql-client \
        # Reverse engineering
        radare2 gdb-multiarch file binutils ropper \
        # Other useful tools
        exploitdb commix davtest skipfish wpscan assetfinder \
        # Python interpreter and libraries
        python3-pip python3-venv python3-dev \
        # Build tools
        build-essential gcc g++ make cmake libpcap-dev \
        # Network utilities
        ncat socat netcat-openbsd rlwrap telnet-ssl openssh-client \
        # Compression and archives
        unzip zip p7zip-full unrar-free && \
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
    wget -O go.tar.gz "https://go.dev/dl/go1.24.4.linux-${ARCH}.tar.gz" && \
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
    rm -rf /root/go/pkg/*

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
