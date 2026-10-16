#!/bin/bash
# Lightsail launch script for the MCP-RE ceiling host. Rendered by
# tools/cloud/render_cloud_config.py into work/cloud-runs/<run-id>/; never edited in place.
# It installs the operator's own SSH public key (generated locally; the private half never
# leaves the operator's machine) and does nothing else.
set -eu
install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
echo "@@SSH_KEY_TYPE@@ @@SSH_KEY_B64@@ mcp-re-ceiling-@@RUN_ID@@" >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
chmod 0600 /home/ubuntu/.ssh/authorized_keys
