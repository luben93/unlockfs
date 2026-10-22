#!/usr/bin/env bash
set -euo pipefail
# Runs vet, unit tests and the integration suite on Linux (Debian, libfuse 2) in a container with a real FUSE mount.
# Needs Docker with access to /dev/fuse. Works from macOS too (via a Linux VM such as colima).
cd "$(dirname "$0")/.."
docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined -v "$PWD":/src:ro golang:1.23-bookworm bash -c '
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq libfuse-dev fuse make >/dev/null 2>&1
cp -R /src /work && cd /work && rm -f unlockfs unlockfs-test
go vet ./... && go test ./internal/...
make unlockfs-test >/dev/null
./test/run.sh | tail -${TAIL:-40}
'
