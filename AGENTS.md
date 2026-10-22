# Agent instructions for unlockfs

## Git permissions (override of the user's global "never push" default)

The owner has explicitly allowed agents to work on this repo's git remote:

- Agents may create feature branches, commit, and `git push` them to `origin` without asking.
- Never push to or force-push `main`. Never merge or approve pull requests; the owner does that.
- Never rewrite history that is already pushed (no force-push, no amend of pushed commits); add a new commit instead.
- Opening a draft pull request for a pushed branch is fine; marking it ready or merging is the owner's action.
- End commit messages with the attribution trailer the harness provides.
- Before pushing: `make test` must pass (go vet, unit tests, 30 integration checks); also run `make test-linux` (Debian container, real libfuse) when touching platform or FUSE code.

This grant covers this repository only.

## Project facts

- Go FUSE filesystem (FUSE-T fork of cgofuse on macOS) serving AES-GCM encrypted files behind a fingerprint/password prompt with a cached grant.
- Layout: `cmd/unlockfs` (CLI + filesystem), `internal/store` (format), `internal/gate` (grant logic), `internal/platform` (darwin Touch ID + Keychain via cgo/Objective-C; linux fprintd + Secret Service: integration suite passes on libfuse, the fingerprint match itself is untested). Platform files use `_darwin`/`_linux` suffixes so each OS ignores the other's cgo/Objective-C.
- Test-only hooks live behind the `unlockfs_testing` build tag. Release builds must never contain them (check with `strings unlockfs | grep UNLOCKFS_AUTH`).
- `make test` uses a throwaway store and fake auth; it never prompts and never touches the real keychain or `~/.unlockfs`.
- `.gitignore` anchors binary names (`/unlockfs`) because `cmd/unlockfs/` must stay tracked.

- `protect` must never keep a plaintext backup by default (security review finding); keep that opt-in.
- The PKGBUILD under `packaging/aur` was not run through a real `makepkg` (Go crashes under amd64 emulation here); its build flags were verified natively.

## Rules

- Never read, print or log secret values; tests use fake secrets only.
- Do not run the real (non-test) binary against `~/.unlockfs` or the user's keychain unless asked.
- Keep the store format stable (`nonce(12) || ciphertext || tag(16)`); changing it breaks existing stores.
