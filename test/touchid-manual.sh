#!/usr/bin/env bash
set -uo pipefail
# Manual check of the real Touch ID / password prompt, using a throwaway store and key file. You must tap when prompted.
cd "$(dirname "$0")/.."
T=$PWD/test/.run-touchid; rm -rf "$T"; mkdir -p "$T/mnt" "$T/store"
export UNLOCKFS_STORE=$T/store UNLOCKFS_KEYFILE=$T/key UNLOCKFS_PIDFILE=$T/pid UNLOCKFS_TTL=60
echo "fake-touchid-test-secret" > "$T/fake.txt"
./unlockfs-test put "$T/fake.txt" /demo/fake.txt
./unlockfs-test serve "$T/mnt" > "$T/daemon.log" 2>&1 & DPID=$!
for i in 1 2 3 4 5 6 7 8; do mount | grep -q "$T/mnt" && break; sleep 1; done
echo "== listing (must not prompt):"; ls -A "$T/mnt/demo"
echo "== first read: a prompt should appear; approve within 60s"
s=$(date +%s); out=$(timeout 60 cat "$T/mnt/demo/fake.txt" 2>&1); echo "result: $out (took $(( $(date +%s)-s ))s)"
echo "== second read (must be instant, no prompt):"; cat "$T/mnt/demo/fake.txt"
umount "$T/mnt"; sleep 1; kill $DPID 2>/dev/null; true
