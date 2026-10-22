#!/usr/bin/env bash
set -uo pipefail
# Automated test of unlockfs in fake-auth test mode. Uses only a throwaway store and fake secrets.
cd "$(dirname "$0")/.."
T=$PWD/test/.run; rm -rf "$T"; mkdir -p "$T/ctl" "$T/mnt" "$T/store" "$T/links"
export UNLOCKFS_AUTH=test UNLOCKFS_TEST_DIR=$T/ctl UNLOCKFS_STORE=$T/store UNLOCKFS_PIDFILE=$T/pid
export UNLOCKFS_TTL=5 UNLOCKFS_DENY_SECS=3 UNLOCKFS_TEST_DELAY=1
pass=0; failn=0
ok()   { pass=$((pass+1)); echo "  PASS $1"; }
bad()  { failn=$((failn+1)); echo "  FAIL $1"; }
chk()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
prompts() { [ -f "$T/ctl/prompts.log" ] && wc -l < "$T/ctl/prompts.log" | tr -d ' ' || echo 0; }
answer() { printf '%s' "$1" > "$T/ctl/answer"; }

echo "fake-secret-AAAA-$$" > "$T/a.env"; printf 'pw=hunter2-BBBB\nline2\n' > "$T/b.yaml"
./unlockfs-test put "$T/a.env" /repo1/.env >/dev/null; ./unlockfs-test put "$T/b.yaml" /repo2/src/application-local.yaml >/dev/null
./unlockfs-test serve "$T/mnt" > "$T/daemon.log" 2>&1 &
DPID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do mount | grep -q "$T/mnt" && break; sleep 1; done
mount | grep -q "$T/mnt" || { echo "mount failed"; cat "$T/daemon.log"; exit 1; }
cleanup() { umount "$T/mnt" 2>/dev/null; sleep 1; kill -0 $DPID 2>/dev/null && kill $DPID 2>/dev/null; }
trap cleanup EXIT

echo "1. browsing never prompts"
answer approve
ls -R "$T/mnt" >/dev/null 2>&1; stat "$T/mnt/repo1/.env" >/dev/null 2>&1
chk "ls/stat prompts" "$(prompts)" 0
chk "listing shows files" "$(ls -A "$T/mnt/repo1")" ".env"
chk "stat size = plaintext size" "$(stat -f %z "$T/mnt/repo1/.env")" "$(stat -f %z "$T/a.env")"

echo "2. encrypted at rest"
if grep -rq "fake-secret-AAAA\|hunter2" "$T/store"; then bad "plaintext found in store"; else ok "no plaintext in store"; fi

echo "3. first read prompts once, content correct"
chk "content" "$(cat "$T/mnt/repo1/.env")" "$(cat "$T/a.env")"
chk "prompts after first read" "$(prompts)" 1

msg=$(sed -n 1p "$T/ctl/prompts.log")
case "$msg" in *"ALL 2 protected files"*"for 5s"*"repo1/.env"*) ok "prompt text names scope, duration and file";; *) bad "prompt text: $msg";; esac

echo "4. grant cached (ssh-agent style): more reads, other file, no new prompt"
cat "$T/mnt/repo1/.env" >/dev/null; cat "$T/mnt/repo2/src/application-local.yaml" >/dev/null
chk "prompts still 1" "$(prompts)" 1
chk "second file content" "$(sed -n 1p "$T/mnt/repo2/src/application-local.yaml")" "pw=hunter2-BBBB"

echo "5. works through symlinks (what the repos will use)"
ln -s "$T/mnt/repo1/.env" "$T/links/.env"
chk "symlink read" "$(cat "$T/links/.env")" "$(cat "$T/a.env")"

echo "6. TTL expiry re-prompts"
sleep 6
chk "read after TTL" "$(cat "$T/mnt/repo1/.env" 2>&1)" "$(cat "$T/a.env")"
chk "prompts after TTL" "$(prompts)" 2

echo "7. lock revokes grant; deny -> EACCES; deny window blocks retries without prompt storm"
./unlockfs-test lock >/dev/null; sleep 1; answer deny
out=$(cat "$T/mnt/repo1/.env" 2>&1); case "$out" in *"ermission denied"*|*"not permitted"*) ok "denied read fails";; *) bad "denied read gave: $out";; esac
n=$(prompts)
for i in 1 2 3 4 5; do cat "$T/mnt/repo1/.env" >/dev/null 2>&1; done
chk "no extra prompts during deny window" "$(prompts)" "$n"
sleep 4; answer approve
chk "approve after deny window" "$(cat "$T/mnt/repo1/.env" 2>&1)" "$(cat "$T/a.env")"
chk "prompts after retry" "$(prompts)" $((n+1))

echo "8. parallel cold opens share ONE prompt"
./unlockfs-test lock >/dev/null; sleep 1; n=$(prompts)
for i in 1 2 3 4 5 6 7 8 9 10; do cat "$T/mnt/repo1/.env" >"$T/par.$i" 2>&1 & done; wait %2 %3 %4 %5 %6 %7 %8 %9 %10 %11 2>/dev/null
good=0; for i in 1 2 3 4 5 6 7 8 9 10; do cmp -s "$T/par.$i" "$T/a.env" && good=$((good+1)); done
chk "all 10 parallel reads succeeded" "$good" 10
chk "exactly one prompt for 10 parallel opens" "$(prompts)" $((n+1))

echo "9. tampered store file is rejected (GCM)"
f="$T/store/repo1/.env.enc"; cp "$f" "$f.bak"; printf '\xff' | dd of="$f" bs=1 seek=20 conv=notrunc 2>/dev/null
./unlockfs-test lock >/dev/null; sleep 1
out=$(cat "$T/mnt/repo1/.env" 2>&1); case "$out" in *"nput/output"*) ok "tamper -> I/O error";; *) bad "tamper gave: $out";; esac
mv "$f.bak" "$f"

echo "10. read-only"
(echo x > "$T/mnt/repo1/.env") 2>/dev/null && bad "write succeeded" || ok "write refused"

echo; echo "passed=$pass failed=$failn"; [ $failn -eq 0 ]
