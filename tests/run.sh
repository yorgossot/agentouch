#!/bin/bash
# Builds and runs the tests. They need no Touch ID and never touch ~/.config/agentouch.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
printf 'let agentouchVersion = "test"\n' > "$out/version.swift"
swiftc -swift-version 5 -o "$out/tests" Sources/agentouch.swift Sources/critical.swift tests/main.swift "$out/version.swift"
"$out/tests"
if command -v jq >/dev/null; then echo; ./tests/guard.sh; else echo "jq not found: skipping the guard hook tests"; fi
