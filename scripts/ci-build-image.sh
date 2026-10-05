#!/usr/bin/env bash
# Build the multi-arch image. Usage: ci-build-image.sh <image> <tag> [--push] [version]
# `version` stamps the UI/CLI version (defaults to the tag; pass the release
# version when building the :latest tag so all surfaces agree).
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${1:?image name}"
TAG="${2:?tag}"
PUSH="${3:-}"
VERSION="${4:-$TAG}"
EXTRA=()
if [ "$PUSH" = "--push" ]; then
  EXTRA+=(--push)
else
  # Multi-arch manifests cannot be loaded into the local daemon; just verify the build.
  EXTRA+=(--output type=image,push=false)
fi
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "$IMAGE:$TAG" \
  --build-arg MIDDEN_VERSION="$VERSION" \
  "${EXTRA[@]}" \
  .
