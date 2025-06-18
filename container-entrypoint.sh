#!/bin/bash
set -e

# Initialize some basic directories
mkdir -p /run/systemd /var/log
export SYSTEMCTL_DEBUG="false"

# Function to cleanup on exit
cleanup() {
    echo "Container stopping..."
}

# Setup signal handlers
trap cleanup EXIT SIGTERM SIGINT

# If no arguments provided, start bash
if [ $# -eq 0 ]; then
    exec bash
else
    # Execute the main command
    exec "$@"
fi
