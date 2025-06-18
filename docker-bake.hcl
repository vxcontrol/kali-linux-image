# Docker Bake configuration for Kali Linux images
# Supports multi-platform builds with SBOM and provenance generation

group "default" {
  targets = ["base", "systemd"]
}

# Sequential build group to ensure proper layering
group "sequential" {
  targets = ["base"]
}

group "dependent" {
  targets = ["systemd"]
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
  
  # Security and compliance features
  attest = [
    "type=provenance,mode=max",
    "type=sbom"
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
  
  # Security and compliance features
  attest = [
    "type=provenance,mode=max",
    "type=sbom"
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
