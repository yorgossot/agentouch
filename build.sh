#!/bin/bash
# Builds agentouch with the git commit stamped in (shown by `agentouch --version` and in every log line).
# Install, after reading the diff:  sudo install -o root -g wheel -m 755 agentouch /usr/local/bin/agentouch
# (and check that /usr/local/bin itself is owned by root; see the README).
set -euo pipefail
cd "$(dirname "$0")"
version=$(git describe --always --dirty 2>/dev/null || echo unknown)
printf 'let agentouchVersion = "%s"\n' "$version" > version.swift
swiftc -O -swift-version 5 -o agentouch Sources/*.swift version.swift
echo "built agentouch $version"
