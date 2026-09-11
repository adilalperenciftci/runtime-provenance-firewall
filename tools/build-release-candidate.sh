#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist=$root/dist
archive=$dist/agent-boundary-linux-amd64.tar.gz
epoch=$(git -C "$root" show -s --format=%ct HEAD)
staging=$(mktemp -d "$root/build/release.XXXXXX")
trap 'rm -rf "$staging"' EXIT INT TERM

if [ "${RPF_USE_EXISTING_SBOM:-0}" != 1 ]; then
  "$root/tools/generate-sbom.sh"
fi
test -s "$root/build/sbom/agent-boundary.spdx.json"
test -s "$root/build/sbom/agent-boundary.cdx.json"
mkdir -p "$dist"
rm -f "$archive" "$dist/source.spdx.json" "$dist/source.cdx.json" "$dist/SHA256SUMS"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true -ldflags '-s -w' \
  -o "$staging/rpf" "$root/cmd/rpf"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true -ldflags '-s -w' \
  -o "$staging/rpf-sensor" "$root/cmd/rpf-sensor"
cp "$root/README.md" "$root/LICENSE" "$staging/"

tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
  -C "$staging" -czf "$archive" .
cp "$root/build/sbom/agent-boundary.spdx.json" "$dist/source.spdx.json"
cp "$root/build/sbom/agent-boundary.cdx.json" "$dist/source.cdx.json"
(
  cd "$dist"
  sha256sum "$(basename "$archive")" source.spdx.json source.cdx.json >SHA256SUMS
)
