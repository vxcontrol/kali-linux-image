# Docker Bake configuration for Kali Linux images
# Supports multi-platform builds with SBOM and provenance generation

group "default" {
  targets = ["base", "systemd", "test", "mcp"]
}

# Sequential build group to ensure proper layering
group "sequential" {
  targets = ["base"]
}

group "dependent" {
  targets = ["systemd"]
}

# Builds from kali-rolling directly, so it shares no layers with base and can
# run alongside the sequential base -> systemd chain.
group "independent" {
  targets = ["test"]
}

# Layered on base, like systemd: reuses the base layers and adds the MCP stack.
group "gateway" {
  targets = ["mcp"]
}

# Common configuration for all targets
variable "TAG" {
  default = "latest"
}

variable "REGISTRY" {
  default = "vxcontrol"
}

# Base Kali Linux image with essential penetration testing tools
target "base" {
  dockerfile = "Dockerfile"
  target = "base"
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${REGISTRY}/kali-linux:latest"
  ]
  
  # Security and compliance features - use stable SBOM scanner
  attest = [
    "type=provenance,mode=max",
    "type=sbom,scanner=docker.io/docker/buildkit-syft-scanner:stable-1"
  ]
  
  # Build metadata
  labels = {
    "org.opencontainers.image.title" = "Kali Linux Penetration Testing Image"
    "org.opencontainers.image.description" = "AI-ready Kali Linux container with 200+ curated CLI penetration testing tools"
    "org.opencontainers.image.url" = "https://hub.docker.com/r/vxcontrol/kali-linux"
    "org.opencontainers.image.documentation" = "https://github.com/vxcontrol/kali-linux-image/blob/master/README.md"
    "org.opencontainers.image.source" = "https://github.com/vxcontrol/kali-linux-image"
    "org.opencontainers.image.vendor" = "vxcontrol"
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.version" = "${TAG}"
    "com.vxcontrol.dockerfile.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/Dockerfile"
    "com.vxcontrol.license.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/LICENSE"
  }
}

# Systemd-enabled Kali Linux image with service management support
target "systemd" {
  dockerfile = "Dockerfile"
  target = "systemd"
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${REGISTRY}/kali-linux:systemd",
  ]
  
  # Build dependencies - reuse base layers
  contexts = {
    base = "target:base"
  }
  
  # Security and compliance features - use stable SBOM scanner
  attest = [
    "type=provenance,mode=max",
    "type=sbom,scanner=docker.io/docker/buildkit-syft-scanner:stable-1"
  ]
  
  # Build metadata
  labels = {
    "org.opencontainers.image.title" = "Kali Linux Penetration Testing Image (Systemd)"
    "org.opencontainers.image.description" = "AI-ready Kali Linux container with systemctl support and 200+ penetration testing tools"
    "org.opencontainers.image.url" = "https://hub.docker.com/r/vxcontrol/kali-linux"
    "org.opencontainers.image.documentation" = "https://github.com/vxcontrol/kali-linux-image/blob/master/README.md"
    "org.opencontainers.image.source" = "https://github.com/vxcontrol/kali-linux-image"
    "org.opencontainers.image.vendor" = "vxcontrol"
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.version" = "${TAG}"
    "com.vxcontrol.dockerfile.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/Dockerfile"
    "com.vxcontrol.license.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/LICENSE"
  }
}

# Sandbox-policy test image: the container PentAGI starts to check that agents
# reach a Docker daemon of their own that refuses host-escape requests. It is
# pulled into the sandbox on every startup check, so it carries only a Docker
# client and curl -- the tooling the checks exercise lives in the containers
# they create. Built FROM kali-rolling, not from base, for the same reason.
target "test" {
  dockerfile = "Dockerfile"
  target = "test"
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${REGISTRY}/kali-linux:test",
  ]

  # Security and compliance features - use stable SBOM scanner
  attest = [
    "type=provenance,mode=max",
    "type=sbom,scanner=docker.io/docker/buildkit-syft-scanner:stable-1"
  ]

  # Build metadata
  labels = {
    "org.opencontainers.image.title" = "Kali Linux Sandbox Policy Test Image"
    "org.opencontainers.image.description" = "Minimal Kali image with a Docker client and curl, used by PentAGI to verify sandbox isolation"
    "org.opencontainers.image.url" = "https://hub.docker.com/r/vxcontrol/kali-linux"
    "org.opencontainers.image.documentation" = "https://github.com/vxcontrol/kali-linux-image/blob/master/README.md"
    "org.opencontainers.image.source" = "https://github.com/vxcontrol/kali-linux-image"
    "org.opencontainers.image.vendor" = "vxcontrol"
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.version" = "${TAG}"
    "com.vxcontrol.dockerfile.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/Dockerfile"
    "com.vxcontrol.license.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/LICENSE"
  }
}

# MCP gateway image: the full penetration-testing toolkit exposed as one
# token-authenticated MCP endpoint (agentgateway + ~15 stdio MCP servers +
# in-container Burp Suite). Built FROM base -- like systemd -- so it reuses the
# base layers instead of rebuilding the toolchain. Config and scripts are
# COPYed from ./mcp by the root Dockerfile's `mcp` stage.
target "mcp" {
  dockerfile = "Dockerfile"
  target = "mcp"
  platforms = ["linux/amd64", "linux/arm64"]
  tags = [
    "${REGISTRY}/kali-linux:mcp",
  ]

  # Build dependencies - reuse base layers
  contexts = {
    base = "target:base"
  }

  # Security and compliance features - use stable SBOM scanner
  attest = [
    "type=provenance,mode=max",
    "type=sbom,scanner=docker.io/docker/buildkit-syft-scanner:stable-1"
  ]

  # Build metadata
  labels = {
    "org.opencontainers.image.title" = "Kali Linux MCP Gateway"
    "org.opencontainers.image.description" = "Kali penetration-testing tools exposed as one token-authenticated MCP endpoint (agentgateway + Burp Suite)"
    "org.opencontainers.image.url" = "https://hub.docker.com/r/vxcontrol/kali-linux"
    "org.opencontainers.image.documentation" = "https://github.com/vxcontrol/kali-linux-image/blob/master/mcp/README.md"
    "org.opencontainers.image.source" = "https://github.com/vxcontrol/kali-linux-image"
    "org.opencontainers.image.vendor" = "vxcontrol"
    "org.opencontainers.image.licenses" = "MIT"
    "org.opencontainers.image.version" = "${TAG}"
    "com.vxcontrol.dockerfile.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/Dockerfile"
    "com.vxcontrol.license.url" = "https://raw.githubusercontent.com/vxcontrol/kali-linux-image/master/LICENSE"
  }
}
