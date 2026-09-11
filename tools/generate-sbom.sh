#!/bin/sh
set -eu

image=ghcr.io/anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$root/build/sbom
version=$(git -C "$root" rev-parse HEAD)
if [ -n "$(git -C "$root" status --porcelain --untracked-files=normal)" ]; then
  version=$version-dirty
fi
docker_root=$root
docker_output=$output
msys_path_conversion=false
case $(uname -s) in
  MINGW*|MSYS*)
    docker_root=$(CDPATH= cd -- "$root" && pwd -W)
    docker_output=$(CDPATH= cd -- "$output" 2>/dev/null && pwd -W || true)
    export MSYS_NO_PATHCONV=1
    msys_path_conversion=true
    ;;
esac

mkdir -p "$output"
if [ -z "$docker_output" ]; then
  docker_output=$(CDPATH= cd -- "$output" && pwd -W)
fi
rm -f "$output/agent-boundary.spdx.json" "$output/agent-boundary.cdx.json"

docker run --rm \
  -v "$docker_root:/src:ro" \
  -v "$docker_output:/out" \
  "$image" scan dir:/src \
  --source-name agent-boundary \
  --source-version "$version" \
  --exclude './build/**' \
  --exclude './dist/**' \
  --exclude './.git/**' \
  --exclude './.venv/**' \
  -o spdx-json=/out/agent-boundary.spdx.json \
  -o cyclonedx-json=/out/agent-boundary.cdx.json

if [ "$msys_path_conversion" = true ]; then
  unset MSYS_NO_PATHCONV
fi

python "$root/tools/validate_sbom.py" \
  "$output/agent-boundary.spdx.json" "$output/agent-boundary.cdx.json"
