# unlockfs

A read-only macOS filesystem that serves encrypted files as ordinary files, behind a **Touch ID / password prompt that is asked once and then remembered**, like `ssh-add -t`.

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

Requires macOS, Xcode command line tools and [FUSE-T](https://github.com/macos-fuse-t/fuse-t) (no kernel extension).

```sh
make                      # SIGN_ID="Apple Development: ..." make   for a stable code identity
make test                 # automated tests, fake-auth build, no prompts
./test/touchid-manual.sh  # real prompt check, you tap once
make install              # launchd agent, mounted at ~/.unlockfs/mnt
```

## Use

```sh
unlockfs put .env /myrepo/.env          # copy a file into the encrypted store (original untouched)
ln -sf ~/.unlockfs/mnt/myrepo/.env .env # after verifying the bytes match, replace the original
unlockfs lock                           # revoke the grant now
```

Config (env): `UNLOCKFS_STORE` (default `~/.unlockfs/store`), `UNLOCKFS_TTL`, `UNLOCKFS_DENY_SECS`, `UNLOCKFS_REASON`, `UNLOCKFS_PIDFILE`.

## Threat model: read this

unlockfs is a **speed bump and leak preventer, not a sandbox**.

- The prompt is enforced by the daemon. The store key lives in the login keychain, readable by any process running as you. Malware running as you can read the key and store directly and skip the prompt.
- FUSE-T reports no caller PID, so a grant is global: anything running as you can read files while it is active.
- It does protect against: backups, archives and cloud syncs containing plaintext secrets; stolen disks; tools or agents that read files without you noticing outside a grant window; secrets pasted into transcripts by accident.
- A Touch ID-bound key (Secure Enclave / data-protection keychain) would be stronger but needs a signed app with a provisioning profile; not implemented.

Status: young project, tested on one machine. Read-only by design; edit by running `put` again. Spotlight or an IDE indexer that opens file contents can trigger a prompt.

## Test mode

`make test` builds `unlockfs-test` with `-D UNLOCKFS_TESTING`, where `UNLOCKFS_AUTH=test` replaces the prompt with a control file. Release builds contain no such code path.

## License

MIT
