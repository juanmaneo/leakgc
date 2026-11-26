#!/bin/sh
# Builds the test image for one C library and runs the workspace tests in it
# (PLAN D73). Usage: scripts/libc-tests.sh glibc|musl|cosmo
set -eu

libc="${1:?usage: scripts/libc-tests.sh glibc|musl|cosmo}"
root="$(cd "$(dirname "$0")/.." && pwd)"

docker build -f "$root/Dockerfile.libc" --target "$libc" -t "leakgc-test-$libc" "$root"
docker run --rm \
    -v "$root:/workspace" \
    -v "leakgc-target-$libc:/cargo-target" \
    "leakgc-test-$libc"
