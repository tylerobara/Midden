#!/usr/bin/env bash
# Compile the midden CLI for the supported platforms into dist/.
# Usage: tools/midden/build.sh [version]
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:-dev}"
mkdir -p dist
for target in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do
  os="${target%-*}"; arch="${target#*-}"
  echo "building midden-$target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "dist/midden-$target" .
done
ls -la dist
