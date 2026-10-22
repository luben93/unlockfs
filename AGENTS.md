# Agent instructions for unlockfs

## Git permissions (override of the user's global "never push" default)

The owner has explicitly allowed agents to work on this repo's git remote:

- Agents may create feature branches, commit, and `git push` them to `origin` without asking.
- Never push to or force-push `main`. Never merge or approve pull requests; the owner does that.
- Never rewrite history that is already pushed (no force-push, no amend of pushed commits); add a new commit instead.
- Opening a draft pull request for a pushed branch is fine; marking it ready or merging is the owner's action.
- End commit messages with the attribution trailer the harness provides.
- Before pushing: `make test` must pass (go vet, unit tests, 20 integration checks).

This grant covers this repository only.

## Project facts

- Go FUSE filesystem (FUSE-T fork of cgofuse on macOS) serving AES-GCM encrypted files behind a fingerprint/password prompt with a cached grant.
- Layout: `cmd/unlockfs` (CLI + filesystem), `internal/store` (format), `internal/gate` (grant logic), `internal/platform` (darwin Touch ID + Keychain via cgo/Objective-C; linux experimental, untested).
- Test-only hooks live behind the `unlockfs_testing` build tag. Release builds must never contain them (check with `strings unlockfs | grep UNLOCKFS_AUTH`).
- `make test` uses a throwaway store and fake auth; it never prompts and never touches the real keychain or `~/.unlockfs`.
- `.gitignore` anchors binary names (`/unlockfs`) because `cmd/unlockfs/` must stay tracked.

## Rules

- Never read, print or log secret values; tests use fake secrets only.
- Do not run the real (non-test) binary against `~/.unlockfs` or the user's keychain unless asked.
- Keep the store format stable (`nonce(12) || ciphertext || tag(16)`); changing it breaks existing stores.
