#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
version="${1:-dev}"
if [[ ! "$version" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo "Version must contain only letters, numbers, dots, underscores, or hyphens" >&2
  exit 1
fi

mkdir -p dist
archives=()
for target in linux/amd64 darwin/arm64 windows/amd64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="trojan-scanner_${version}_${os}_${arch}"
  binary="trojan-scanner"
  if [[ "$os" == windows ]]; then binary+=".exe"; fi
  mkdir -p "dist/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "dist/$name/$binary" .
  cp README.md "dist/$name/"
  tar -czf "dist/$name.tar.gz" -C dist "$name"
  archives+=("$name.tar.gz")
done

cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${archives[@]}" > SHA256SUMS
else
  shasum -a 256 "${archives[@]}" > SHA256SUMS
fi
