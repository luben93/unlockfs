# unlockfs

A read-only FUSE filesystem that serves encrypted files as ordinary files, behind a **fingerprint or password prompt that is asked once and then remembered**, like `ssh-add -t`.

Apps need no wrapper and no changes: your `.env` or `application-local.yaml` becomes a symlink into the mount. Browsing (`ls`, `stat`, IDE tree indexing) never prompts. The first time a file's contents are opened, you get one Touch ID / fingerprint / password prompt that says exactly what you are approving; after that every protected file reads silently until the grant expires, the screen locks or the machine sleeps.

```
project/.env  ->  ~/.unlockfs/mnt/project/.env      (served by unlockfs)
                         |
                         +-- decrypts ~/.unlockfs/store/project/.env.enc   (AES-256-GCM)
                             after one prompt, valid for 8h (default)
```

| | macOS | Linux |
|---|---|---|
| Prompt | Touch ID, falls back to your password (`LocalAuthentication`) | `fprintd-verify`, or your own command (`UNLOCKFS_PROMPT_CMD`) |
| Key store | login Keychain | Secret Service (`secret-tool`), else a 0600 file |
| Lock / sleep detection | yes | yes (logind) |
| FUSE layer | [FUSE-T](https://github.com/macos-fuse-t/fuse-t), no kernel extension | libfuse 2 |
| Status | tested end to end | filesystem and integration suite tested on libfuse; the fingerprint match itself is untested |

## Behaviour

- **One prompt per grant.** Concurrent opens wait on the same prompt, so a build that opens ten files shows one dialog.
- **Grant lifetime:** `UNLOCKFS_TTL` seconds (default 8h). Ends early on screen lock, sleep or `unlockfs lock`.
- **No prompt storms:** a declined prompt blocks further prompts for `UNLOCKFS_DENY_SECS` (default 30).
- **Honest prompt text:** it states how many files the approval unlocks, for how long, and which file triggered it.
- **Tamper evident:** a modified store file fails authentication and reads return an I/O error.
- **Read-only mount.** To change a secret, run `unlockfs put` again.

## Install

### macOS

1. Install [FUSE-T](https://github.com/macos-fuse-t/fuse-t) (needed to build and to run):
   ```sh
   brew install --cask macos-fuse-t/homebrew-cask/fuse-t
   ```
2. Build and install from source (needs Go 1.22+ and the Xcode command line tools):
   ```sh
   git clone https://github.com/luben93/unlockfs && cd unlockfs
   make                       # SIGN_ID="Apple Development: you@example.com (TEAMID)" make  for a stable code identity
   make test                  # optional: vet, unit tests and integration checks with fake auth, no prompts
   make install               # installs ~/.local/bin/unlockfs and a launchd agent mounting ~/.unlockfs/mnt
   ```
   A stable signing identity stops the keychain from asking again after every rebuild. Without one the binary is ad-hoc signed.
3. Optional Homebrew tap: [`packaging/homebrew/unlockfs.rb`](packaging/homebrew/unlockfs.rb) is a ready formula template; see [How to create and maintain a tap](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap).

### Arch Linux (AUR)

A [`PKGBUILD`](packaging/aur/PKGBUILD) is included. Until a release is published to the AUR you can build it locally:

```sh
sudo pacman -S --needed base-devel go git fuse2 libsecret   # fprintd is optional but gives you the fingerprint prompt
git clone https://github.com/luben93/unlockfs && cd unlockfs/packaging/aur
# the PKGBUILD downloads the v0.1.0 release tarball; until that tag exists, point `source=` at a local tarball
makepkg -si
systemctl --user enable --now unlockfs.service
```

Publishing it to the AUR (maintainers only, one-time):

1. Create an account and add your SSH key at [aur.archlinux.org](https://aur.archlinux.org/).
2. Tag a release (`git tag v0.1.0 && git push --tags`) and run `updpkgsums` in `packaging/aur` to fill in the checksum.
3. `makepkg --printsrcinfo > .SRCINFO`, then push `PKGBUILD` and `.SRCINFO` to `ssh://aur@aur.archlinux.org/unlockfs.git`.

Follow the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines), the [PKGBUILD reference](https://wiki.archlinux.org/title/PKGBUILD) and the [Go package guidelines](https://wiki.archlinux.org/title/Go_package_guidelines). Enrol a fingerprint first if you want one: [Fprint](https://wiki.archlinux.org/title/Fprint) (`fprintd-enroll`).

> The PKGBUILD's build flags (PIE, external linking, version stamping) were verified in a Debian container, but it has not been run through a real `makepkg` yet. Please try `makepkg -si` on an Arch machine and report problems.

### Other Linux

```sh
# Debian/Ubuntu: sudo apt install libfuse-dev fuse libsecret-tools fprintd golang make
make && sudo install -m755 unlockfs /usr/local/bin/
install -Dm644 packaging/systemd/unlockfs.service ~/.config/systemd/user/unlockfs.service
systemctl --user enable --now unlockfs.service
```
cgofuse needs the libfuse 2 headers (`/usr/include/fuse`); distributions that ship only libfuse 3 need the fuse2 development package.

## Use

```sh
cd ~/code/myproject
unlockfs protect .env config/application-local.yaml     # key = path relative to $HOME (change with --root)
```

`protect` encrypts each file into the store, reads it back through the mount (this is when the first prompt appears), checks it is byte-identical, removes the plaintext original and leaves a symlink. It refuses git-tracked files (their content is already in the repository; `--force` overrides) so `git status` stays clean. No plaintext backup is kept unless you pass `--keep-backup`.

Other commands:

| Command | What it does |
|---|---|
| `unlockfs serve <mountpoint>` | run the filesystem (the launchd agent / systemd unit does this) |
| `unlockfs protect [--root DIR] [--force] [--keep-backup] <file>...` | store, verify, replace with a symlink |
| `unlockfs put <file> <key>` | add or replace one file without touching the original |
| `unlockfs list` | list stored keys (names only) |
| `unlockfs rm <key>` | remove a stored file |
| `unlockfs doctor` | check that the key loads and every stored file decrypts (prints no content) |
| `unlockfs lock` | revoke the current grant now |
| `unlockfs version` | print the version |

After re-cloning a repository, run `ln -s ~/.unlockfs/mnt/<key> <path>` for each file, or `protect` it again from a backup.

### Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `UNLOCKFS_STORE` | `~/.unlockfs/store` | encrypted files |
| `UNLOCKFS_MOUNT` | `~/.unlockfs/mnt` | where `protect` expects the mount |
| `UNLOCKFS_TTL` | `28800` | grant length in seconds |
| `UNLOCKFS_DENY_SECS` | `30` | how long a declined prompt blocks new prompts |
| `UNLOCKFS_PIDFILE` | `~/.unlockfs/pid` | used by `unlockfs lock` |
| `UNLOCKFS_PROMPT_CMD` | (Linux) | command whose exit status 0 means approved; gets `UNLOCKFS_REASON` in its environment |
| `UNLOCKFS_PROMPT_TIMEOUT` | `60s` | (Linux) give up on an unanswered prompt |
| `UNLOCKFS_FUSE_OPTS` | | extra `-o` options for the mount |

Store format: one file per secret named `<key>.enc`, containing `nonce(12) || AES-256-GCM ciphertext || tag(16)`. The 32-byte key lives in the OS key store (service `unlockfs`).

## Threat model: read this

unlockfs is a **leak preventer and speed bump, not a sandbox**.

- The prompt is enforced by the daemon. The store key sits in your login keychain (or Secret Service), readable by any process running as you. Malware running as you can read the key and the store directly and skip the prompt.
- On macOS, FUSE-T reports no caller PID, so a grant is global: anything running as you can read the files while it is active. The prompt shows the file, not the program.
- On Linux the key is readable by your other processes without a prompt, so there the prompt only guards the mounted files.
- Handles opened under a grant stop working when it ends, but the macOS NFS client may serve already cached data for an open file for a short time. New opens always re-check the grant.
- It does protect against: plaintext secrets in backups, archives, cloud syncs and stolen disks; tools or agents reading config files outside a grant window; secrets copied into logs or transcripts by accident.
- A Touch ID-bound key (Secure Enclave / data-protection keychain) would be stronger, but needs a signed app with a provisioning profile; it is not implemented.

## Development

```sh
make test          # go vet, unit tests, 30 integration checks on a real FUSE mount with fake auth
make test-linux    # the same on Linux in a Docker container (needs /dev/fuse), also from macOS via colima
./test/touchid-manual.sh   # real prompt check on macOS, you tap once
go run ./cmd/platformcheck # exercises key store, prompt and lock detection without FUSE
```

Layout: `cmd/unlockfs` (CLI and filesystem), `internal/store` (format), `internal/gate` (grant logic), `internal/platform` (Touch ID and Keychain via cgo on macOS, fprintd and Secret Service on Linux). Test-only hooks (`UNLOCKFS_AUTH=test`) are compiled only with `-tags unlockfs_testing`; release builds contain none. CI runs the suite on Linux; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Agent contributors: see [`AGENTS.md`](AGENTS.md).

macOS FUSE support uses the [FUSE-T fork of cgofuse](https://github.com/macos-fuse-t/cgofuse).

## License

MIT
