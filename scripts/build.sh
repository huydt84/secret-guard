#!/usr/bin/env bash
set -euo pipefail

APP=secretguard
VERSION=${VERSION:-1.0.0}
OUTDIR=${OUTDIR:-./bin}

mkdir -p "$OUTDIR"

build() {
    local os=$1 arch=$2 suffix=$3
    local output="${OUTDIR}/${APP}-${VERSION}-${os}-${arch}${suffix}"
    echo "Building $output ..."
    GOOS="$os" GOARCH="$arch" go build -o "$output" ./cmd/secretguard
    if command -v sha256sum &>/dev/null; then
        sha256sum "$output" | cut -d' ' -f1 > "${output}.sha256"
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$output" | cut -d' ' -f1 > "${output}.sha256"
    else
        echo "  (sha256sum not available)"
    fi
    test -f "${output}.sha256" && echo "  sha256: $(cat "${output}.sha256")"
}

build linux   amd64 ""
build linux   arm64 ""
build darwin  amd64 ""
build darwin  arm64 ""

echo ""
echo "All builds complete in ${OUTDIR}/"
ls -lh "${OUTDIR}/${APP}-${VERSION}-"*
