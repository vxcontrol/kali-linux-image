# Pinned Burp Suite Desktop + official MCP v1.3.0 artifacts.
# Sourced by the image build (root Dockerfile `mcp` stage) and by start-burp.sh.
# Verify the versions and SHA-256 checksums against PortSwigger's published
# releases and the PortSwigger/mcp-server repository when bumping them.

BURP_VERSION=2026.7.3
BURP_JAR_URL='https://portswigger.net/burp/releases/startdownload?product=desktop&type=jar&version=2026.7.3'
BURP_JAR_SHA256=c8262dc5426f38bedc490d66c5d21b6ff77d6dc6d85cefe6a66c882690134069

BAPP_URL='https://portswigger.net/bappstore/bapps/download/9952290f04ed4f628e624d0aa9dccebc/10'
BAPP_SHA256=4d675b10796ff51d440c5a40f3855a3d38a1666a91a0b28fb8853a26abd5b2c5
BURP_MCP_EXT_SHA256=f93e434a9154fbb03bc9b20e46555fc901be57a80ec63d607d9cde192d27691c

BURP_MCP_PROXY_URL='https://github.com/PortSwigger/mcp-server/raw/5f76126409780ecba2b766c7f7388f465c5b5f94/libs/mcp-proxy-all.jar'
BURP_MCP_PROXY_SHA256=b376b860f114f67e8301e50b06760f1edd23dd99e860c3646cbeac144ce7821a
