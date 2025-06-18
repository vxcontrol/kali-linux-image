#!/bin/bash

# Test script for Kali Linux Docker image tools
# Usage: ./test-tools.sh [docker-image-name]
# Environment variables:
#   DEBUG - if set, shows stdout/stderr from test commands
#   KALI_CONTAINER - set inside container to prevent recursive Docker calls

set -e

# Default image name
DEFAULT_IMAGE="vxcontrol/kali-linux:latest"
IMAGE_NAME="${1:-$DEFAULT_IMAGE}"

# Check if we're running inside the container
if [ -z "$KALI_CONTAINER" ]; then
    echo "Starting tool validation in Docker container: $IMAGE_NAME"
    exec docker run --rm -it \
        --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$(pwd):/work" \
        -e KALI_CONTAINER=1 \
        -e DEBUG="$DEBUG" \
        "$IMAGE_NAME" \
        bash /work/test-tools.sh
fi

# Function to test if a tool exists and works
test_tool() {
    local tool="$1"
    local test_cmd="$2"
    local name="${3:-$tool}"
    
    if [ -n "$DEBUG" ]; then
        echo "Testing $name with command: $test_cmd" >&2
    fi
    
    if eval "$test_cmd" >/dev/null 2>&1; then
        echo "✓ $name"
    else
        echo "✗ $name"
        if [ -n "$DEBUG" ]; then
            echo "  Command failed: $test_cmd" >&2
            eval "$test_cmd" >&2 2>&1 || true
        fi
    fi
}

echo "=== Kali Linux Docker Image Tool Validation ==="

# System utilities
test_tool "curl" "curl --version"
test_tool "wget" "wget --version"
test_tool "git" "git --version"
test_tool "vim" "vim --version"
test_tool "nano" "nano --version"
test_tool "jq" "jq --version"
test_tool "tmux" "tmux -V"
test_tool "screen" "screen -v"

# Network reconnaissance and scanning
test_tool "nmap" "nmap --version"
test_tool "masscan" "which masscan"
test_tool "nping" "nping --version"
test_tool "amass" "which amass"
test_tool "theharvester" "which theharvester"
test_tool "dnsrecon" "which dnsrecon"
test_tool "fierce" "which fierce"
test_tool "netdiscover" "which netdiscover"
test_tool "arp-scan" "arp-scan --version"
test_tool "arping" "which arping"
test_tool "fping" "fping -v"
test_tool "hping3" "which hping3"
test_tool "nbtscan" "which nbtscan"
test_tool "onesixtyone" "which onesixtyone"
test_tool "sublist3r" "which sublist3r"
test_tool "ncrack" "ncrack --version"
test_tool "ike-scan" "which ike-scan"

# Web application testing
test_tool "gobuster" "gobuster version"
test_tool "dirb" "which dirb"
test_tool "dirb-gendict" "which dirb-gendict"
test_tool "dirsearch" "which dirsearch"
test_tool "nikto" "nikto -Version"
test_tool "whatweb" "whatweb --version"
test_tool "sqlmap" "sqlmap --version"
test_tool "sqlmapapi" "which sqlmapapi"
test_tool "wfuzz" "wfuzz --version"
test_tool "feroxbuster" "feroxbuster --version"
test_tool "wpscan" "wpscan --version"
test_tool "commix" "which commix"
test_tool "davtest" "which davtest"
test_tool "skipfish" "which skipfish"
test_tool "ffuf" "ffuf -V"

# Brute force and password attacks
test_tool "hydra" "which hydra"
test_tool "john" "which john"
test_tool "crunch" "crunch --version"
test_tool "medusa" "medusa -V"
test_tool "patator" "which patator"
test_tool "hashid" "which hashid"
test_tool "hash-identifier" "which hash-identifier"
test_tool "hashcat" "hashcat --version"

# John the Ripper converters
test_tool "7z2john" "which 7z2john"
test_tool "bitcoin2john" "which bitcoin2john"
test_tool "keepass2john" "which keepass2john"
test_tool "office2john" "which office2john"
test_tool "pdf2john" "which pdf2john"
test_tool "rar2john" "which rar2john"
test_tool "ssh2john" "which ssh2john"
test_tool "zip2john" "which zip2john"
test_tool "gpg2john" "which gpg2john"
test_tool "putty2john" "which putty2john"
test_tool "truecrypt2john" "which truecrypt2john"
test_tool "luks2john" "which luks2john"

# Metasploit framework
test_tool "msfconsole" "which msfconsole"
test_tool "msfvenom" "which msfvenom"
test_tool "msfdb" "which msfdb"
test_tool "msfrpc" "which msfrpc"
test_tool "msfupdate" "which msfupdate"

# Metasploit utilities
test_tool "msf-pattern_create" "which msf-pattern_create"
test_tool "msf-pattern_offset" "which msf-pattern_offset"
test_tool "msf-find_badchars" "which msf-find_badchars"
test_tool "msf-egghunter" "which msf-egghunter"
test_tool "msf-makeiplist" "which msf-makeiplist"

# Impacket framework
test_tool "impacket-secretsdump" "which impacket-secretsdump"
test_tool "impacket-psexec" "which impacket-psexec"
test_tool "impacket-smbexec" "which impacket-smbexec"
test_tool "impacket-wmiexec" "which impacket-wmiexec"
test_tool "impacket-dcomexec" "which impacket-dcomexec"
test_tool "impacket-atexec" "which impacket-atexec"
test_tool "impacket-smbclient" "which impacket-smbclient"
test_tool "impacket-smbserver" "which impacket-smbserver"
test_tool "impacket-ntlmrelayx" "which impacket-ntlmrelayx"
test_tool "impacket-GetNPUsers" "which impacket-GetNPUsers"
test_tool "impacket-GetUserSPNs" "which impacket-GetUserSPNs"
test_tool "impacket-getTGT" "which impacket-getTGT"
test_tool "impacket-getST" "which impacket-getST"
test_tool "impacket-goldenPac" "which impacket-goldenPac"
test_tool "impacket-karmaSMB" "which impacket-karmaSMB"
test_tool "impacket-rpcdump" "which impacket-rpcdump"
test_tool "impacket-samrdump" "which impacket-samrdump"
test_tool "impacket-lookupsid" "which impacket-lookupsid"
test_tool "impacket-reg" "which impacket-reg"
test_tool "impacket-services" "which impacket-services"
test_tool "impacket-addcomputer" "which impacket-addcomputer"
test_tool "impacket-changepasswd" "which impacket-changepasswd"
test_tool "impacket-GetADUsers" "which impacket-GetADUsers"
test_tool "impacket-GetADComputers" "which impacket-GetADComputers"
test_tool "impacket-findDelegation" "which impacket-findDelegation"
test_tool "impacket-ticketer" "which impacket-ticketer"
test_tool "impacket-ticketConverter" "which impacket-ticketConverter"

# Windows/Active Directory exploitation
test_tool "evil-winrm" "which evil-winrm"
test_tool "bloodhound-python" "which bloodhound-python"
test_tool "crackmapexec" "crackmapexec -h"
test_tool "netexec" "which netexec"
test_tool "responder" "which responder"
test_tool "certipy-ad" "which certipy-ad"
test_tool "ldapdomaindump" "which ldapdomaindump"
test_tool "enum4linux" "which enum4linux"
test_tool "ldapsearch" "which ldapsearch" "ldap-utils"
test_tool "smbclient" "smbclient --version"
test_tool "smbmap" "which smbmap"
test_tool "mimikatz" "which mimikatz"
test_tool "lsassy" "which lsassy"
test_tool "pypykatz" "which pypykatz"
test_tool "pywerview" "which pywerview"

# Kerberos tools
test_tool "minikerberos-getTGT" "which minikerberos-getTGT"
test_tool "minikerberos-getTGS" "which minikerberos-getTGS"
test_tool "minikerberos-kerberoast" "which minikerberos-kerberoast"
test_tool "minikerberos-asreproast" "which minikerberos-asreproast"

# Post-exploitation and persistence
test_tool "powershell-empire" "which powershell-empire"
test_tool "starkiller" "which starkiller"
test_tool "unicorn-magic" "which unicorn-magic"
test_tool "weevely" "which weevely"

# Traffic analysis and proxies
test_tool "tshark" "tshark --version"
test_tool "tcpdump" "tcpdump --version"
test_tool "tcpreplay" "tcpreplay --version"
test_tool "mitmdump" "mitmdump --version"
test_tool "mitmproxy" "which mitmproxy"
test_tool "mitmweb" "which mitmweb"
test_tool "proxychains4" "which proxychains4"
test_tool "proxytunnel" "which proxytunnel"
test_tool "stunnel4" "which stunnel4"
test_tool "sslh" "which sslh"
test_tool "sslscan" "sslscan --version"
test_tool "sslsplit" "which sslsplit"

# Tunneling and pivoting
test_tool "iodine" "which iodine"
test_tool "ptunnel" "which ptunnel"
test_tool "pwnat" "which pwnat"
test_tool "chisel" "which chisel"

# Network utilities
test_tool "socat" "socat -V"
test_tool "netcat" "which netcat" "netcat-traditional"
test_tool "nc.openbsd" "which nc" "netcat-openbsd"
test_tool "ncat" "ncat --version"
test_tool "rlwrap" "which rlwrap"
test_tool "telnet" "which telnet" "telnet-ssl"
test_tool "ssh" "ssh -V" "openssh-client"

# Databases
test_tool "sqsh" "which sqsh"
test_tool "mysql" "mysql --version" "default-mysql-client"
test_tool "psql" "psql --version" "postgresql-client"

# Reverse engineering and binary analysis
test_tool "radare2" "r2 -version"
test_tool "file" "file --version"
test_tool "objdump" "objdump --version" "binutils"
test_tool "strings" "strings --version" "binutils"
test_tool "r2" "r2 -version"
test_tool "rabin2" "rabin2 -version"
test_tool "radiff2" "radiff2 -version"
test_tool "binwalk" "which binwalk"
test_tool "bulk_extractor" "which bulk_extractor"
test_tool "ROPgadget" "which ROPgadget"
test_tool "ropper" "ropper --version"

# Steganography
test_tool "steghide" "steghide --version"
test_tool "stegosuite" "which stegosuite"
test_tool "foremost" "which foremost"

# Information gathering and OSINT
test_tool "searchsploit" "which searchsploit"
test_tool "shodan" "which shodan"
test_tool "censys" "which censys"
test_tool "chaos" "chaos -version"

# Subdomain enumeration and DNS discovery
test_tool "subfinder" "subfinder -version"
test_tool "shuffledns" "shuffledns -version"
test_tool "dnsx" "dnsx -version"
test_tool "assetfinder" "which assetfinder"

# Web application reconnaissance
test_tool "httpx" "httpx -version"
test_tool "katana" "katana -version"
test_tool "hakrawler" "which hakrawler"
test_tool "waybackurls" "which waybackurls"
test_tool "gau" "gau --version"

# Vulnerability scanners
test_tool "nuclei" "nuclei -version"
test_tool "naabu" "naabu -version"

# Wordlists and dictionaries
test_tool "wordlists" "ls /usr/share/wordlists"
test_tool "seclists" "ls /usr/share/seclists"

# Docker CLI
test_tool "docker" "docker --version" "docker-ce-cli"

# Archive tools
test_tool "unzip" "unzip -v"
test_tool "zip" "zip -v"
test_tool "7z" "7z --help" "p7zip-full"
test_tool "unrar" "which unrar" "unrar-free"

# Specialized tools
test_tool "cmedb" "which cmedb"
test_tool "polenum" "which polenum"
test_tool "winexe" "which winexe"

echo "=== Tool validation completed ==="
