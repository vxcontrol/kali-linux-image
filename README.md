# Kali Linux Docker Images

Lightweight Kali Linux Docker images with curated CLI penetration testing tools for headless environments. This project provides optimized Docker images for security research, penetration testing, and cybersecurity training.

<div align="center">

> 🚀 **Join Community!** Connect with security researchers, AI enthusiasts, and fellow ethical hackers. Get support, share insights, and stay updated with the latest PentAGI developments.

[![Discord](https://img.shields.io/badge/Discord-7289DA?logo=discord&logoColor=white)](https://discord.gg/2xrMh7qX6m)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?logo=telegram&logoColor=white)](https://t.me/+Ka9i6CNwe71hMWQy)

</div>

## Description

This repository contains Docker configurations for building streamlined Kali Linux containers specifically optimized for AI-driven automated penetration testing. While suitable for manual security research, these images are primarily designed for autonomous AI agents to execute penetration testing workflows in headless environments.

**Primary Use Case: AI Agent Automation**
These Docker images serve as execution environments for AI agents in [PentAGI](https://github.com/vxcontrol/pentagi/) - a fully autonomous AI agents system capable of performing complex penetration testing tasks. The AI agents interact with the containerized tools through command-line interfaces, enabling:

- **Autonomous Security Testing**: AI agents can execute reconnaissance, vulnerability scanning, and exploitation tasks without human intervention
- **Scalable Test Orchestration**: Multiple containers can be spawned simultaneously for parallel testing across different targets
- **Isolated Execution Environment**: Each AI agent operates within a contained environment, ensuring safe and controlled testing
- **Standardized Tool Access**: Consistent CLI interface for 200+ penetration testing tools across different testing scenarios

The containers provide a clean, reproducible environment where AI agents can leverage industry-standard security tools like `nmap`, `nuclei`, `sqlmap`, `metasploit`, and many others through programmatic command execution. This enables sophisticated automated penetration testing workflows that can adapt and respond to discovered vulnerabilities in real-time.

## Available Images

### 1. Base Kali Linux Image
Lightweight container with essential penetration testing tools, automatically built and published on Docker Hub.

**Available on Docker Hub**: [vxcontrol/kali-linux](https://hub.docker.com/r/vxcontrol/kali-linux)

```bash
# Pull latest image from Docker Hub
docker pull vxcontrol/kali-linux

# Run interactive session
docker run --rm -it vxcontrol/kali-linux bash

# Build from source (using Docker Buildx Bake)
docker buildx bake base --set="base.tags=local/kali-linux:latest" --load

# Alternative: Traditional docker buildx build
docker buildx build --target base --load -t local/kali-linux:latest .

# Run interactive session
docker run --rm -it local/kali-linux bash
```

### 2. Kali Linux with systemctl Support
Extended image with systemctl functionality using docker-systemctl-replacement, automatically built and published on Docker Hub.

```bash
# Pull systemd image from Docker Hub
docker pull vxcontrol/kali-linux:systemd

# Run with systemctl support
docker run --rm -it vxcontrol/kali-linux:systemd bash

# Build systemd variant from source (using Docker Buildx Bake)
docker buildx bake systemd --set="systemd.tags=local/kali-linux:systemd" --load

# Alternative: Traditional docker buildx build
docker buildx build --target systemd --load -t local/kali-linux:systemd .

# Run local systemd build
docker run --rm -it local/kali-linux:systemd bash
```

## Included Tools

The base image includes carefully curated CLI tools organized by security testing categories:

### **System Utilities & Core Tools**
- `curl`, `wget` - HTTP client tools for data retrieval
- `git` - Version control system for code management
- `vim`, `nano` - Command-line text editors
- `jq` - JSON processing and parsing utility
- `tmux`, `screen` - Terminal multiplexing for session management

### **Network Reconnaissance & Scanning**
- `nmap` - Network discovery and security auditing
- `masscan` - High-speed internet-wide port scanner
- `nping` - Network packet generation and analysis
- `amass` - In-depth subdomain enumeration and network mapping
- `theharvester` - Email/domain intelligence gathering
- `dnsrecon`, `fierce` - DNS reconnaissance and enumeration
- `netdiscover`, `arp-scan`, `arping` - Network host discovery
- `fping`, `hping3` - Network connectivity testing and packet crafting
- `nbtscan` - NetBIOS name scanning
- `onesixtyone` - SNMP scanner and brute-forcer
- `sublist3r` - Python subdomain enumeration tool
- `ncrack` - Network authentication cracking
- `ike-scan` - IPsec VPN detection and enumeration

### **Subdomain Enumeration & DNS Discovery**
- `subfinder` - Fast passive subdomain discovery (Go-based)
- `shuffledns` - Wildcard-aware DNS brute-forcing
- `dnsx` - Fast and multi-purpose DNS toolkit
- `assetfinder` - Asset discovery and subdomain enumeration
- `chaos` - Subdomain enumeration via Project Discovery API

### **Web Application Reconnaissance**
- `httpx` - Fast HTTP probing and technology detection
- `katana` - Next-generation web crawling and spidering
- `hakrawler` - Simple and fast web crawler
- `waybackurls` - Historical URL discovery via Wayback Machine
- `gau` - Get All URLs from various sources (AlienVault OTX, Wayback, Common Crawl)

### **Web Application Testing & Exploitation**
- `gobuster` - Directory/file and DNS enumeration
- `dirb`, `dirb-gendict` - Web content scanner and wordlist generator
- `dirsearch` - Simple command-line tool for brute-forcing directories
- `nikto` - Web server vulnerability scanner
- `whatweb` - Web application fingerprinting
- `sqlmap`, `sqlmapapi` - Automatic SQL injection detection and exploitation
- `wfuzz` - Web application fuzzer
- `feroxbuster` - Fast content discovery tool written in Rust
- `wpscan` - WordPress security scanner
- `commix` - Command injection testing tool
- `davtest` - WebDAV server testing utility
- `skipfish` - Web application security reconnaissance
- `ffuf` - Fast web fuzzer written in Go

### **Vulnerability Scanning & Security Assessment**
- `nuclei` - Fast vulnerability scanner based on YAML templates
- `naabu` - Fast port scanner for security assessments

### **Brute Force & Password Attacks**
- `hydra` - Network authentication brute-forcer
- `john` - Password hash cracking tool
- `crunch` - Custom wordlist generator
- `medusa` - Modular brute-force authentication cracker
- `patator` - Multi-purpose brute-forcer with modular design
- `hashid` - Hash type identifier
- `hash-identifier` - Python hash identification tool
- `hashcat` - Advanced password recovery utility

### **John the Ripper Format Converters**
- `7z2john`, `bitcoin2john`, `keepass2john` - Archive and cryptocurrency hash converters
- `office2john`, `pdf2john` - Document format hash extractors
- `rar2john`, `zip2john` - Archive format converters
- `ssh2john`, `gpg2john` - SSH and GPG key converters
- `putty2john`, `truecrypt2john` - PuTTY and TrueCrypt converters
- `luks2john` - LUKS encrypted volume converter

### **Metasploit Framework**
- `msfconsole` - Main Metasploit console interface
- `msfvenom` - Payload generator and encoder
- `msfdb` - Database management for Metasploit
- `msfrpc` - Remote procedure call daemon
- `msfupdate` - Metasploit update utility

### **Metasploit Utilities**
- `msf-pattern_create` - Generate unique patterns for buffer overflow testing
- `msf-pattern_offset` - Find offset in generated patterns
- `msf-find_badchars` - Identify bad characters in payloads
- `msf-egghunter` - Generate egghunter shellcode
- `msf-makeiplist` - Generate IP address lists

### **Impacket Framework (Windows Network Protocol Exploitation)**
- `impacket-secretsdump` - Extract credentials from various sources
- `impacket-psexec`, `impacket-smbexec`, `impacket-wmiexec` - Remote execution utilities
- `impacket-dcomexec`, `impacket-atexec` - Alternative execution methods
- `impacket-smbclient`, `impacket-smbserver` - SMB client and server utilities
- `impacket-ntlmrelayx` - NTLM relay attack tool
- `impacket-GetNPUsers` - ASREPRoast attack implementation
- `impacket-GetUserSPNs` - Kerberoast attack tool
- `impacket-getTGT`, `impacket-getST` - Kerberos ticket manipulation
- `impacket-goldenPac` - MS14-068 exploitation tool
- `impacket-karmaSMB` - SMB relay server
- `impacket-rpcdump`, `impacket-samrdump` - RPC and SAM enumeration
- `impacket-lookupsid` - SID lookup utility
- `impacket-reg`, `impacket-services` - Remote registry and service management
- `impacket-addcomputer` - Add computer accounts to domain
- `impacket-changepasswd` - Change user passwords remotely
- `impacket-GetADUsers`, `impacket-GetADComputers` - Active Directory enumeration
- `impacket-findDelegation` - Find delegation relationships
- `impacket-ticketer`, `impacket-ticketConverter` - Kerberos ticket manipulation

### **Windows & Active Directory Exploitation**
- `evil-winrm` - Windows Remote Management shell
- `bloodhound-python` - Active Directory relationship mapping
- `crackmapexec` - Post-exploitation tool for Windows networks
- `netexec` - Network execution and lateral movement tool
- `responder` - LLMNR, NBT-NS and MDNS poisoner
- `certipy-ad` - Active Directory certificate services exploitation
- `ldapdomaindump` - LDAP domain information dumper
- `enum4linux` - Linux alternative to enum.exe for Windows enumeration
- `ldapsearch` - LDAP search utility
- `smbclient` - SMB/CIFS client for accessing Windows shares
- `smbmap` - SMB enumeration tool
- `mimikatz` - Windows credential extraction tool
- `lsassy` - Remote LSASS memory dumping
- `pypykatz` - Python implementation of Mimikatz
- `pywerview` - Python alternative to PowerView

### **Kerberos Authentication Tools**
- `minikerberos-getTGT` - Obtain Kerberos Ticket Granting Tickets
- `minikerberos-getTGS` - Obtain Kerberos service tickets
- `minikerberos-kerberoast` - Kerberoasting attack implementation
- `minikerberos-asreproast` - ASREPRoast attack tool

### **Post-Exploitation & Persistence**
- `powershell-empire` - PowerShell post-exploitation framework
- `starkiller` - Empire GUI interface
- `unicorn-magic` - PowerShell downgrade and injection attacks
- `weevely` - Weaponized web shell

### **Traffic Analysis & Network Monitoring**
- `tshark` - Command-line network protocol analyzer
- `tcpdump` - Command-line packet analyzer
- `tcpreplay` - Packet replay and editing utilities
- `mitmdump`, `mitmproxy`, `mitmweb` - HTTP/HTTPS interception proxy
- `proxychains4` - Proxy chaining tool for pivoting
- `proxytunnel` - HTTP/HTTPS proxy tunneling
- `stunnel4` - SSL/TLS encryption wrapper
- `sslh` - SSL/SSH multiplexer
- `sslscan` - SSL/TLS configuration scanner
- `sslsplit` - Transparent SSL/TLS interception

### **Tunneling & Pivoting**
- `iodine` - DNS tunneling for data exfiltration
- `ptunnel` - ICMP tunneling tool
- `pwnat` - NAT traversal utility
- `chisel` - Fast TCP/UDP tunnel over HTTP

### **Network Utilities & Communication**
- `socat` - Multipurpose relay tool
- `netcat` - Traditional network Swiss Army knife
- `nc.openbsd` - OpenBSD netcat implementation
- `ncat` - Nmap's netcat with additional features
- `rlwrap` - Readline wrapper for improved shell interaction
- `telnet` - Telnet client with SSL support
- `ssh` - Secure Shell client

### **Database Client Tools**
- `sqsh` - SQL shell for Sybase and Microsoft SQL Server
- `mysql` - MySQL database client
- `psql` - PostgreSQL database client

### **Reverse Engineering & Binary Analysis**
- `radare2` - Comprehensive reverse engineering framework
- `r2`, `rabin2`, `radiff2` - Radare2 core utilities
- `file` - File type identification utility
- `objdump` - Display information from object files
- `strings` - Extract readable strings from binaries
- `hexdump` - Extract binary data and hex analysis
- `binwalk` - Firmware analysis and extraction tool
- `bulk_extractor` - Digital forensics and data recovery tool
- `ROPgadget` - ROP gadget finder for exploit development
- `ropper` - ROP/JOP gadget finder

### **Steganography & Forensics**
- `steghide` - Steganography hiding and detection tool
- `stegosuite` - Graphical steganography tool
- `foremost` - File carving and recovery utility

### **OSINT & Information Gathering**
- `searchsploit` - Exploit database search utility
- `shodan` - Internet-connected device search engine
- `censys` - Internet-wide scanning and analysis platform

### **Wordlists & Dictionaries**
- `wordlists` - Comprehensive password and fuzzing wordlists
- `seclists` - Security tester's companion wordlists

### **Container & System Management**
- `docker` - Docker container management CLI

### **Archive & File Utilities**
- `unzip`, `zip` - ZIP archive creation and extraction
- `7z` - 7-Zip archiver with high compression
- `unrar` - RAR archive extraction utility

## Usage

### Testing & Development
For security research and penetration testing practice:
```bash
# Interactive shell with current directory mounted
docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux bash

# Network scanning with required capabilities
docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux nmap -sS target.com

# Web application testing
docker run --rm -v $(pwd):/data -w /data vxcontrol/kali-linux sqlmap -u "http://target.com/page?id=1"

# Using Docker socket for container management
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/work vxcontrol/kali-linux bash
```

### Production & Automation
For automated security testing and CI/CD integration:
```bash
# Automated vulnerability scanning
docker run --rm -v $(pwd)/results:/results vxcontrol/kali-linux \
  nuclei -t /nuclei-templates -u target.com -o /results/scan.json

# Batch subdomain enumeration
docker run --rm -v $(pwd)/domains.txt:/input.txt -v $(pwd)/results:/output \
  vxcontrol/kali-linux subfinder -dL /input.txt -o /output/subdomains.txt

# Automated web directory scanning
docker run --rm -v $(pwd)/results:/results vxcontrol/kali-linux \
  gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /results/dirs.txt
```

### Docker Compose for Complex Workflows
```yaml
services:
  kali:
    image: vxcontrol/kali-linux
    volumes:
      - ./home:/work
      - /var/run/docker.sock:/var/run/docker.sock
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    stdin_open: true
    tty: true
```

### Persistent Data and Configurations
For maintaining scan results and custom configurations:
```bash
# Create persistent data directory
mkdir -p ~/kali-data/{home,configs}

# Run with persistent storage
docker run --rm -it \
  -v ~/kali-data/home:/work \
  -v ~/kali-data/configs:/root/.config \
  vxcontrol/kali-linux bash
```

### Tool Aliases for Quick Access

<details>
<summary><strong>Linux Aliases</strong> (click to expand)</summary>

Add these aliases to your shell profile (`.bashrc`, `.zshrc`) for instant access to tools:

```bash
# Network scanning
alias nmap='docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux nmap'
alias masscan='docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux masscan'
alias naabu='docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux naabu'

# Web application testing
alias nuclei='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux nuclei'
alias sqlmap='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux sqlmap'
alias gobuster='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux gobuster'
alias ffuf='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux ffuf'
alias nikto='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux nikto'
alias whatweb='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux whatweb'
alias dirb='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux dirb'
alias feroxbuster='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux feroxbuster'

# Reconnaissance & OSINT
alias subfinder='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux subfinder'
alias httpx='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux httpx'
alias amass='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux amass'
alias katana='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux katana'
alias theharvester='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux theharvester'
alias shodan='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux shodan'

# Windows/AD testing
alias crackmapexec='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux crackmapexec'
alias evil-winrm='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux evil-winrm'
alias impacket-secretsdump='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-secretsdump'
alias impacket-psexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-psexec'
alias impacket-smbexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-smbexec'
alias impacket-wmiexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-wmiexec'
alias bloodhound-python='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux bloodhound-python'
alias responder='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux responder'

# Password cracking
alias hashcat='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hashcat'
alias john='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux john'
alias hydra='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hydra'
alias medusa='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux medusa'
alias hashid='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hashid'

# Metasploit framework
alias msfconsole='docker run --rm -it --net=host -v ~/.msf4:/root/.msf4 -v $(pwd):/work -w /work vxcontrol/kali-linux msfconsole'
alias msfvenom='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux msfvenom'
alias msfdb='docker run --rm -v ~/.msf4:/root/.msf4 vxcontrol/kali-linux msfdb'

# Network analysis
alias ncrack='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux ncrack'
alias arp-scan='docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux arp-scan'
alias netdiscover='docker run --rm --net=host --cap-add NET_ADMIN --cap-add NET_RAW -v $(pwd):/work -w /work vxcontrol/kali-linux netdiscover'

# Interactive shell
alias kali-shell='docker run --rm -it -v $(pwd):/work -w /work --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux bash'
alias kali-shell-systemd='docker run --rm -it -v $(pwd):/work -w /work --cap-add NET_ADMIN --cap-add NET_RAW vxcontrol/kali-linux:systemd bash'
```
</details>

<details>
<summary><strong>macOS Aliases</strong> (click to expand)</summary>

For macOS users, add these aliases to your shell profile (`.zshrc`, `.bash_profile`):

```bash
# Network scanning (without raw capabilities due to Docker Desktop limitations)
alias nmap='docker run --rm --net=host vxcontrol/kali-linux nmap'
alias masscan='docker run --rm --net=host vxcontrol/kali-linux masscan'
alias naabu='docker run --rm --net=host vxcontrol/kali-linux naabu'

# Web application testing
alias nuclei='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux nuclei'
alias sqlmap='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux sqlmap'
alias gobuster='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux gobuster'
alias ffuf='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux ffuf'
alias nikto='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux nikto'
alias whatweb='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux whatweb'
alias dirb='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux dirb'
alias feroxbuster='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux feroxbuster'

# Reconnaissance & OSINT
alias subfinder='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux subfinder'
alias httpx='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux httpx'
alias amass='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux amass'
alias katana='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux katana'
alias theharvester='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux theharvester'
alias shodan='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux shodan'

# Windows/AD testing
alias crackmapexec='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux crackmapexec'
alias evil-winrm='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux evil-winrm'
alias impacket-secretsdump='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-secretsdump'
alias impacket-psexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-psexec'
alias impacket-smbexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-smbexec'
alias impacket-wmiexec='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux impacket-wmiexec'
alias bloodhound-python='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux bloodhound-python'
alias responder='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux responder'

# Password cracking
alias hashcat='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hashcat'
alias john='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux john'
alias hydra='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hydra'
alias medusa='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux medusa'
alias hashid='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux hashid'

# Metasploit framework
alias msfconsole='docker run --rm -it --net=host -v ~/.msf4:/root/.msf4 -v $(pwd):/work -w /work vxcontrol/kali-linux msfconsole'
alias msfvenom='docker run --rm -v $(pwd):/work -w /work vxcontrol/kali-linux msfvenom'
alias msfdb='docker run --rm -v ~/.msf4:/root/.msf4 vxcontrol/kali-linux msfdb'

# Network analysis (limited capabilities on macOS)
alias ncrack='docker run --rm --net=host -v $(pwd):/work -w /work vxcontrol/kali-linux ncrack'

# Interactive shell
alias kali-shell='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux bash'
alias kali-shell-systemd='docker run --rm -it -v $(pwd):/work -w /work vxcontrol/kali-linux:systemd bash'
```

**Note for macOS users:** Raw network capabilities (`--cap-add NET_ADMIN --cap-add NET_RAW`) are not available in Docker Desktop for Mac, so they are omitted from network scanning tools. For advanced network testing, consider using a Linux VM or remote testing environment.
</details>

## AI Agent Integration

### PentAGI Integration
These Docker images are designed to work seamlessly with [PentAGI](https://pentagi.com), an autonomous AI agents system for penetration testing. The integration provides:

#### Automated Tool Execution
AI agents can programmatically execute any of the 200+ included tools by sending commands to the container:
```json
{
  "action": "terminal",
  "command": "nmap -sS -O target.example.com",
  "container": "vxcontrol/kali-linux"
}
```

#### Multi-Agent Workflows
Multiple AI agents can coordinate complex testing scenarios:
- **Reconnaissance Agent**: Uses `subfinder`, `amass`, `httpx` for target discovery
- **Vulnerability Scanner Agent**: Leverages `nuclei`, `nmap`, `nikto` for vulnerability assessment  
- **Exploitation Agent**: Deploys `sqlmap`, `metasploit`, `impacket` tools for exploitation
- **Post-Exploitation Agent**: Utilizes `evil-winrm`, `bloodhound-python` for lateral movement

#### Containerized Execution Environment
```bash
# PentAGI spawns containers dynamically for isolated testing
docker run --rm -d --name pentagi-terminal-123 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /tmp/pentagi-results:/results \
  vxcontrol/kali-linux tail -f /dev/null

# AI agents execute commands within the session (terminal)
docker exec pentagi-terminal-123 nmap -sn 192.168.1.0/24
docker exec pentagi-terminal-123 nuclei -u https://target.com -o /results/vulns.json
```

#### Adaptive Testing Scenarios
AI agents can adapt their testing approach based on discovered information:
1. **Initial Reconnaissance**: Discover services and technologies
2. **Targeted Scanning**: Focus on identified attack surfaces  
3. **Exploitation Attempts**: Deploy appropriate tools based on findings
4. **Persistence & Lateral Movement**: Expand access using discovered credentials

For detailed integration examples and API documentation, visit the [PentAGI repository](https://github.com/vxcontrol/pentagi/).

## Building from Source

### Prerequisites
- Docker 20.10+ with BuildKit enabled
- Docker Buildx plugin
- 15GB+ available disk space

### Build System Overview
This project uses Docker Buildx Bake with advanced BuildKit configuration for efficient multi-platform builds. The build system includes:

**Core Configuration Files:**
- `docker-bake.hcl` - Declarative build configuration with sequential dependency management
- `buildkitd.toml` - BuildKit daemon configuration with automatic garbage collection
- `.github/workflows/docker-build.yml` - CI/CD pipeline with optimized caching and security scanning

**Key Features:**
- **Multi-platform builds**: linux/amd64, linux/arm64 
- **Sequential dependency builds**: Base images built first, systemd images reuse layers
- **Persistent builder**: `kali-builder` with smart cache management (50GB limit, automatic GC)
- **Automatic cache invalidation**: Based on Dockerfile changes and base image updates
- **Registry + local cache strategy**: vxcontrol/kali-linux:buildcache for team collaboration
- **Security attestations**: SBOM and provenance generation for published images
- **Trivy vulnerability scanning**: Optimized scanning with SARIF output to GitHub Security tab
- **Container metadata**: OCI-compliant labels and annotations

#### Security & Compliance Features
Our build system automatically generates security attestations for enhanced supply chain security:

**Software Bill of Materials (SBOM):**
- Complete inventory of all packages and dependencies
- Vulnerability scanning and license compliance support
- SPDX-compatible format for industry standard tooling

**Build Provenance:**
- Cryptographic proof of build integrity  
- Source repository and build environment verification
- Immutable build artifact attestation with maximum security mode

**OCI Metadata:**
- Comprehensive container labels following OpenContainer standards
- Build information, documentation links, and licensing details
- Version tracking and source code traceability

#### CI/CD Pipeline Features
The GitHub Actions workflow (`.github/workflows/docker-build.yml`) provides:

- **Self-hosted runner optimization**: 12-hour timeout for large image builds
- **Persistent builder management**: Automatic `kali-builder` creation with `buildkitd.toml` configuration
- **Sequential build strategy**: Eliminates layer duplication between base and systemd targets
- **Smart cache management**: Registry cache with automatic garbage collection policies
- **Security scanning integration**: Trivy vulnerability scanning with GitHub Security tab upload
- **Build attestations**: Automatic SBOM and provenance generation for supply chain security
- **Comprehensive reporting**: Build summary with security metrics and cache statistics

#### Migration from Traditional Docker Build
| Feature | Traditional Approach | Docker Buildx Bake + BuildKit |
|---------|---------------------|-------------------------------|
| **Base Image** | `docker build -t local/kali-linux .` | `docker buildx bake base --load` |
| **Systemd Image** | `docker build --target systemd -t local/kali-linux:systemd .` | `docker buildx bake systemd --load` |
| **Multi-platform** | Manual builds for each platform | Automatic multi-platform support |
| **Configuration** | Command-line parameters | Declarative `docker-bake.hcl` + `buildkitd.toml` |
| **Cache Management** | Manual cleanup required | Automatic garbage collection with policies |
| **Registry Push** | `docker push` after build | `docker buildx bake --push` |

### Quick Start - Local Testing
```bash
# Clone repository
git clone https://github.com/vxcontrol/kali-linux-image.git
cd kali-linux-image

# Create optimized builder (one-time setup)
docker buildx create --name kali-builder \
  --driver docker-container \
  --driver-opt image=moby/buildkit:buildx-stable-1 \
  --driver-opt network=host \
  --config ./buildkitd.toml \
  --use --bootstrap

# Build base image for current platform
docker buildx bake base --set="base.tags=local/kali-linux:latest" --load

# Build with automatic cache management
docker buildx bake base --load \
  --set="base.tags=local/kali-linux:latest" \
  --set="*.cache-from=type=registry,ref=vxcontrol/kali-linux:buildcache" \
  --set="*.cache-to=type=registry,ref=vxcontrol/kali-linux:buildcache,mode=max"

# Build both base and systemd sequentially (recommended)
docker buildx bake sequential --load \
  --set="base.tags=local/kali-linux:latest"
docker buildx bake dependent --load \
  --set="systemd.tags=local/kali-linux:systemd"

# Test the build
docker run --rm -it local/kali-linux:latest bash
```

### Building Specific Targets

#### Base Image Only
```bash
# Using docker buildx bake (recommended)
docker buildx bake base --set="base.platform=linux/arm64" \
  --set="base.tags=local/kali-linux:latest" --load

# Alternative: Traditional docker buildx build
docker buildx build --target base --platform linux/arm64 \
  --load -t local/kali-linux:latest .

# For AMD64 architecture
docker buildx build --target base --platform linux/amd64 \
  --load -t local/kali-linux:latest .
```

#### Systemd-Enabled Image Only
```bash
# Build systemd variant for ARM64
docker buildx bake systemd --set="systemd.platform=linux/arm64" \
  --set="systemd.tags=local/kali-linux:systemd" --load

# Build systemd variant for AMD64
docker buildx bake systemd --set="systemd.platform=linux/amd64" \
  --set="systemd.tags=local/kali-linux:systemd" --load
```

### Multi-Platform Builds
```bash
# Build for both ARM64 and AMD64 architectures
docker buildx bake --set="base.tags=local/kali-linux:latest" \
  --set="systemd.tags=local/kali-linux:systemd" --load

# Build only for specific architecture
docker buildx bake --set="*.platform=linux/amd64" --load
```

### Publishing to Registry

#### Default Registry (vxcontrol/kali-linux)
```bash
# Build and push both images to default registry with multi-platform support
docker buildx bake --push

# Alternative: Build and push with explicit tags
docker buildx bake --push \
  --set="base.tags=vxcontrol/kali-linux:latest" \
  --set="systemd.tags=vxcontrol/kali-linux:systemd"
```

#### Custom Registry
```bash
# Override tags for custom registry
docker buildx bake --push \
  --set="base.tags=myregistry/my-kali:latest" \
  --set="systemd.tags=myregistry/my-kali:systemd"

# Examples for different registries:

# Docker Hub (different organization)
docker buildx bake --push \
  --set="base.tags=myorg/kali-linux:latest" \
  --set="systemd.tags=myorg/kali-linux:systemd"

# GitHub Container Registry
docker buildx bake --push \
  --set="base.tags=ghcr.io/myorg/kali-linux:latest" \
  --set="systemd.tags=ghcr.io/myorg/kali-linux:systemd"

# AWS ECR
docker buildx bake --push \
  --set="base.tags=123456789012.dkr.ecr.us-west-2.amazonaws.com/kali-linux:latest" \
  --set="systemd.tags=123456789012.dkr.ecr.us-west-2.amazonaws.com/kali-linux:systemd"

# Google Container Registry
docker buildx bake --push \
  --set="base.tags=gcr.io/my-project/kali-linux:latest" \
  --set="systemd.tags=gcr.io/my-project/kali-linux:systemd"
```

### Advanced Build Options
```bash
# Build with custom registry and version variables
TAG=v1.2.3 REGISTRY=myregistry docker buildx bake --push

# Build specific version tags
docker buildx bake --push \
  --set="base.tags=vxcontrol/kali-linux:latest,vxcontrol/kali-linux:v2024.1" \
  --set="systemd.tags=vxcontrol/kali-linux:systemd,vxcontrol/kali-linux:systemd-v2024.1"

# Build with optimized builder configuration
docker buildx bake --builder kali-builder --push \
  --set="*.cache-from=type=registry,ref=vxcontrol/kali-linux:buildcache" \
  --set="*.cache-to=type=registry,ref=vxcontrol/kali-linux:buildcache,mode=max"

# Local development build without attestations (faster)
docker buildx bake --load --set="base.attest=" --set="systemd.attest="

# Sequential build for production (recommended)
docker buildx bake sequential --push
docker buildx bake dependent --push

# Monitor cache usage and garbage collection
docker system df
docker buildx du --builder kali-builder
```

### Working with Security Attestations

#### Viewing SBOM and Provenance
```bash
# Inspect image attestations
docker buildx imagetools inspect vxcontrol/kali-linux:latest --format "{{json .Attestations}}"

# Extract SBOM using Docker Scout (if available)
docker scout sbom vxcontrol/kali-linux:latest

# View attestations with cosign (requires cosign installation)
cosign verify-attestation --type spdxjson vxcontrol/kali-linux:latest
cosign verify-attestation --type slsaprovenance vxcontrol/kali-linux:latest
```

#### Supply Chain Verification
```bash
# Verify image signatures and attestations
docker trust inspect vxcontrol/kali-linux:latest

# Check for vulnerabilities using generated SBOM
docker scout cves vxcontrol/kali-linux:latest

# Audit compliance using SBOM data
docker scout compliance vxcontrol/kali-linux:latest
```

### Build Configuration

#### docker-bake.hcl Structure
The build configuration defines multiple targets and groups:

```bash
# Build groups for sequential dependency management
group "sequential" {     # Base images only
  targets = ["base"]
}

group "dependent" {      # Systemd images (requires base)
  targets = ["systemd"]
}

group "default" {        # All images (parallel)
  targets = ["base", "systemd"]
}
```

**Target Features:**
- **Base target**: Lightweight Kali Linux with 200+ CLI tools
- **Systemd target**: Extended image with systemctl support via docker-systemctl-replacement
- **Multi-platform support**: Automatic builds for ARM64 and AMD64
- **Layer optimization**: Systemd target reuses base layers via `contexts = { base = "target:base" }`
- **Security attestations**: SBOM and provenance generation for published images
- **OCI metadata**: Complete labeling following OpenContainer standards

#### buildkitd.toml Configuration
Advanced BuildKit daemon configuration with automatic cache management:

```toml
# Cache limits optimized for powerful servers
reservedSpace = "10GB"      # Minimum cache reservation
maxUsedSpace = "50GB"       # Maximum cache before GC
minFreeSpace = "20GB"       # Keep disk space free
max-parallelism = 4         # Stable build parallelism

# Automatic garbage collection policies
# Policy 1: Cleanup temporary files (12h retention)
# Policy 2: Remove old cache (5 days retention) 
# Policy 3: Clean unshared layers (space-based)
# Policy 4: Emergency cleanup (critical space)
```

#### Configuration Variables
```bash
# Available variables
TAG=latest          # Version tag (default: latest)
REGISTRY=vxcontrol  # Container registry (default: vxcontrol)

# Usage examples
TAG=v1.0.0 docker buildx bake --push
REGISTRY=ghcr.io/myorg TAG=dev docker buildx bake --load
```

#### Cache Strategy Comparison
| Cache Type | Use Case | Configuration | Performance |
|------------|----------|---------------|-------------|
| **Registry** (`buildcache`) | CI/CD + team collaboration | Automatic in workflow | High, shared |
| **BuildKit Local** | Local development | `buildkitd.toml` managed | Very high, automatic GC |
| **Combined Strategy** | Production setup | Registry + local with GC | Optimal |

## System Requirements

### Minimum Requirements
- 2GB RAM
- 2 CPU core  
- 15GB disk space
- Docker 20.10+ with BuildKit enabled
- Docker Buildx plugin

### Recommended for Production
- 8GB+ RAM (for BuildKit caching and parallel builds)
- 4+ CPU cores (matches `max-parallelism = 4` in buildkitd.toml)
- 80GB+ disk space (50GB cache + 20GB free + working space)
- SSD storage for optimal BuildKit performance

### BuildKit Cache Requirements
The `buildkitd.toml` configuration is optimized for servers with:
- **Minimum 80GB free disk space** (50GB cache + 20GB reserved + working space)
- **8-16GB RAM** for efficient parallel building (`max-parallelism = 4`)  
- **Fast storage** (SSD recommended) for cache performance
- **Reliable network** for registry cache synchronization

## Advanced Usage Scenarios

### Docker-in-Docker Access
Access Docker daemon from within the container for orchestration and testing:
```bash
# Mount Docker socket for container management
docker run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/work \
  vxcontrol/kali-linux bash

# Inside container - you can now run Docker commands
docker ps
docker run --rm alpine echo "Hello from nested container"
```

**Use Cases:**
- Container-based exploit delivery
- Multi-container testing environments
- Orchestrated security testing workflows

### Network Capabilities for Advanced Testing
Many penetration testing tools require raw network access:
```bash
# Required capabilities for network tools
docker run --rm -it \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --net=host \
  vxcontrol/kali-linux bash

# Tools that benefit from these capabilities:
# - nmap (SYN scans, OS detection)
# - masscan (raw socket access)
# - custom packet crafting tools
```

**Required Capabilities:**
- `NET_ADMIN`: Network interface configuration, routing tables
- `NET_RAW`: Raw socket access for packet crafting

## Build Performance & Optimization

### Automatic Cache Management
The project includes advanced BuildKit configuration (`buildkitd.toml`) that automatically manages cache lifecycle:

**Garbage Collection Policies:**
- **Temporary cleanup** (12h): Removes build contexts, git checkouts, cache mounts
- **Long-term cache** (5 days): Cleans unused layers older than 5 days  
- **Space management**: Removes unshared cache when approaching limits
- **Emergency cleanup**: Automatically frees space when critically low

**Performance Benefits:**
- ✅ **50GB cache capacity** for optimal rebuild performance
- ✅ **Automatic invalidation** when Dockerfile or base images change
- ✅ **Registry cache sharing** for team collaboration (`vxcontrol/kali-linux:buildcache`)
- ✅ **Sequential builds** prevent layer duplication between base/systemd images
- ✅ **Parallel processing** with stable `max-parallelism = 4` configuration

### CI/CD Pipeline Optimization
The GitHub Actions workflow includes enterprise-grade optimizations:

**Smart Build Strategy:**
```yaml
# Step 1: Build base images first
docker buildx bake sequential --push

# Step 2: Build systemd images (reuse base layers)  
docker buildx bake dependent --push
```

**Security Integration:**
- **Trivy vulnerability scanning** with optimized settings (60min timeout, skip large files)
- **SARIF upload** to GitHub Security tab for vulnerability tracking
- **SBOM generation** for supply chain compliance
- **Build provenance** with maximum security attestation

## Tool Validation

Verify all tools are working correctly with the included validation script:

```bash
# Test default image (vxcontrol/kali-linux:latest)
./test-tools.sh

# Test specific image
./test-tools.sh local/kali-linux:latest

# Enable debug output for troubleshooting
DEBUG=1 ./test-tools.sh vxcontrol/kali-linux:latest

# Download script directly (if not using repository)
curl -sSL https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/test-tools.sh | bash
```

The validation script:
- Tests 100+ tools across all penetration testing categories
- Organized into logical groups: reconnaissance, web testing, exploitation, post-exploitation, etc.
- Automatically runs inside Docker container with required capabilities
- Provides clear ✓/✗ status for each tool
- Supports debug mode for troubleshooting failed tests
- Works with any Kali Linux Docker image

## Security Considerations

⚠️ **Important Security Notes:**
- These images contain penetration testing tools intended for authorized security testing only
- Docker socket access grants significant host privileges
- Network capabilities enable low-level network manipulation
- Each tool has its own security implications and legal requirements

See [Disclaimer](#disclaimer) section for complete legal and ethical usage guidelines.

## systemctl Support

The systemd-enabled image (`vxcontrol/kali-linux:systemd`) uses [docker-systemctl-replacement](https://github.com/gdraheim/docker-systemctl-replacement) to provide systemctl functionality without full systemd overhead. This enables:
- Service management commands
- Compatibility with tools expecting systemctl
- Stable operation in container environments
- No privileged mode requirements

```bash
# Use published systemd image
docker run --rm vxcontrol/kali-linux:systemd systemctl --version

# Start services (example with apache2)
docker run --rm -it vxcontrol/kali-linux:systemd bash
# systemctl start apache2

# Build systemd-enabled image locally
docker buildx bake systemd --set="systemd.tags=local/kali-linux:systemd" --load

# Check local build functionality
docker run --rm local/kali-linux:systemd systemctl --version
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes
4. Submit a pull request

## License

**Container Configuration**: The Docker configuration files and build scripts in this project are licensed under the MIT License - see LICENSE file for details.

**Included Software**: This Docker image contains software packages from the official Kali Linux repository and third-party tools, each governed by their respective licenses. Users are responsible for ensuring compliance with the individual licenses of all included software for their specific use cases.

**Base Image**: Built upon the official `kalilinux/kali-rolling` image, subject to its licensing terms and conditions.

## Disclaimer

**Ethical Use Only**: This image is provided exclusively for ethical hacking, authorized penetration testing, and security research in full compliance with the Kali Linux EULA and the licenses of all included software.

**No Warranty**: The authors and contributors provide this image "as is" without warranty of any kind and disclaim all liability for any damages arising from the use of this image or any software contained within it.

**User Responsibility**: Users are solely responsible for ensuring their use complies with all applicable laws, regulations, and the terms of service of target systems. Only use on systems you own or have explicit written authorization to test.

## Project Structure

```
/
├── .github/
│   └── workflows/
│       └── docker-build.yml    # CI/CD pipeline with optimized caching
├── buildkitd.toml              # BuildKit configuration with automatic GC
├── container-entrypoint.sh     # Entrypoint script for systemd image
├── docker-bake.hcl             # Docker Buildx Bake configuration
├── Dockerfile                  # Multi-stage Dockerfile (base + systemd targets)
├── LICENSE                     # MIT License
├── README.md                   # Documentation
└── test-tools.sh               # Tool validation script
```

## Related Projects

- [PentAGI - Autonomous AI Penetration Testing](https://github.com/vxcontrol/pentagi/) - Primary use case for these Docker images
- [Official Kali Docker Images](https://hub.docker.com/r/kalilinux/kali-rolling)
- [Docker BuildKit Documentation](https://docs.docker.com/build/buildkit/)
- [Docker Buildx Bake Reference](https://docs.docker.com/engine/reference/commandline/buildx_bake/)
- [Kali Linux Documentation](https://www.kali.org/docs/containers/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

## Support

For issues, suggestions, or contributions:
- Create an issue on GitHub
- Submit a pull request
- Test changes with the validation script before submitting
