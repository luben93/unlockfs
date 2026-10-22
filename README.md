# unlockfs

A read-only FUSE filesystem that serves encrypted files as ordinary files, behind a **fingerprint / password prompt that is asked once and then remembered**, like `ssh-add -t`. Written in Go; Touch ID on macOS (tested), `fprintd` on Linux (experimental, untested).

Apps need no wrapper: a repo's `.env` or `application-local.yaml` is a symlink into the mount. Browsing (`ls`, `stat`, IDE tree indexing) never prompts; the first `open()` does. One approval covers every file until the TTL ends.

```
repo/.env  ->  ~/.unlockfs/mnt/repo/.env   (served by unlockfs from an AES-GCM store)
```

## Behaviour

- One prompt per grant; concurrent opens wait on the same prompt.
- Grant lasts `UNLOCKFS_TTL` seconds (default 8h) and is revoked on screen lock, sleep, or `unlockfs lock`.
- A declined prompt blocks further prompts for `UNLOCKFS_DENY_SECS` (default 30) so retry loops cannot cause a prompt storm.
- Store files are AES-256-GCM (CryptoKit); tampering is detected and reads fail with EIO.

## Install

Requires Go 1.22+ and a FUSE layer:
- **macOS:** [FUSE-T](https://github.com/macos-fuse-t/fuse-t) (no kernel extension) and the Xcode command line tools (the Touch ID and Keychain code is Objective-C via cgo). Uses the [FUSE-T fork of cgofuse](https://github.com/macos-fuse-t/cgofuse).
- **Linux (experimental, untested):** libfuse 2, plus `fprintd` for the prompt and `secret-tool` (libsecret) for the key. Set `UNLOCKFS_PROMPT_CMD` to your own approval command (exit 0 = approved), e.g. a script that tries `fprintd-verify` and falls back to a password dialog. Without `secret-tool` the key is kept in `~/.unlockfs/key` (mode 0600).

```sh
make                      # SIGN_ID="Apple Development: ..." make   for a stable code identity
make test                 # go vet + unit tests + 19 integration checks on a real mount, fake-auth build, no prompts
./test/touchid-manual.sh  # real prompt check, you tap once
make install              # launchd agent, mounted at ~/.unlockfs/mnt
```

## Use

```sh
unlockfs put .env /myrepo/.env          # copy a file into the encrypted store (original untouched)
ln -sf ~/.unlockfs/mnt/myrepo/.env .env # after verifying the bytes match, replace the original
unlockfs lock                           # revoke the grant now
```

Store format: `nonce(12) || AES-256-GCM ciphertext || tag(16)` per file, named `<path>.enc`, key 32 bytes in the OS key store (service `unlockfs`).

Config (env): `UNLOCKFS_STORE` (default `~/.unlockfs/store`), `UNLOCKFS_TTL`, `UNLOCKFS_DENY_SECS`, `UNLOCKFS_REASON`, `UNLOCKFS_PIDFILE`.

## Threat model: read this

unlockfs is a **speed bump and leak preventer, not a sandbox**.

- The prompt is enforced by the daemon. The store key lives in the login keychain, readable by any process running as you. Malware running as you can read the key and store directly and skip the prompt.
- On macOS, FUSE-T reports no caller PID, so a grant is global: anything running as you can read files while it is active. On Linux libfuse reports the PID, so per-program grants are possible but not implemented.
- On Linux the key lives in the Secret Service or a 0600 file, readable by any process of your user without a prompt, so there the prompt only guards the mounted filesystem, not the store and key.
- It does protect against: backups, archives and cloud syncs containing plaintext secrets; stolen disks; tools or agents that read files without you noticing outside a grant window; secrets pasted into transcripts by accident.
- A Touch ID-bound key (Secure Enclave / data-protection keychain) would be stronger but needs a signed app with a provisioning profile; not implemented.

Status: young project, tested on one macOS machine; Linux support compiles in the platform package but has never run. Read-only by design; edit by running `put` again. Spotlight or an IDE indexer that opens file contents can trigger a prompt.

## Test mode

`make test` builds `unlockfs-test` with `-tags unlockfs_testing`, where `UNLOCKFS_AUTH=test` replaces the prompt with a control file. Release builds contain no such code path.

## License

MIT
