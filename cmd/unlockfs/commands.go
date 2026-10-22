package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/unlockfs/unlockfs/internal/platform"
	"github.com/unlockfs/unlockfs/internal/store"
)

var version = "dev" // set with -ldflags "-X main.version=..."

var mountDir = env("UNLOCKFS_MOUNT", filepath.Join(home, ".unlockfs", "mnt"))

// putFile encrypts src into the store under key (a path starting with "/").
func putFile(src, key string) (int, error) {
	k, err := platform.LoadOrCreateKey(storeEmpty())
	if err != nil {
		return 0, fmt.Errorf("key: %w", err)
	}
	plain, err := os.ReadFile(src)
	if err != nil {
		return 0, err
	}
	blob, err := store.Seal(k, plain)
	if err != nil {
		return 0, err
	}
	dest := encPath(key)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return 0, err
	}
	return len(plain), os.WriteFile(dest, blob, 0o600)
}

func cmdPut(args []string) {
	if len(args) != 2 {
		die("usage: unlockfs put <srcfile> <key>")
	}
	n, err := putFile(args[0], "/"+strings.TrimPrefix(args[1], "/"))
	if err != nil {
		die("%v", err)
	}
	fmt.Printf("stored /%s (%d bytes)\n", strings.TrimPrefix(args[1], "/"), n)
}

func cmdList() {
	var keys []string
	filepath.WalkDir(storeDir, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() && strings.HasSuffix(p, ".enc") {
			keys = append(keys, strings.TrimSuffix(strings.TrimPrefix(p, storeDir), ".enc"))
		}
		return nil
	})
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k)
	}
}

func cmdRm(args []string) {
	if len(args) != 1 {
		die("usage: unlockfs rm <key>")
	}
	p := encPath("/" + strings.TrimPrefix(args[0], "/"))
	if err := os.Remove(p); err != nil {
		die("%v", err)
	}
	for d := filepath.Dir(p); d != storeDir && strings.HasPrefix(d, storeDir); d = filepath.Dir(d) {
		if os.Remove(d) != nil { // stops at the first non-empty directory
			break
		}
	}
	fmt.Println("removed", args[0])
}

func gitTracked(path string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	return exec.Command("git", "-C", filepath.Dir(path), "ls-files", "--error-unmatch", "--", filepath.Base(path)).Run() == nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// cmdProtect stores files, verifies the copy through the mount (this triggers the prompt), removes the plaintext
// original and leaves a symlink into the mount. Git-tracked files are refused unless --force. No plaintext backup is
// kept unless --keep-backup is given, because a plaintext copy defeats the purpose.
func cmdProtect(args []string) {
	root, force, keep := home, false, false
	var files []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--root":
			i++
			if i >= len(args) {
				die("--root needs a directory")
			}
			root = args[i]
		case "--force":
			force = true
		case "--keep-backup":
			keep = true
		default:
			files = append(files, args[i])
		}
	}
	if len(files) == 0 {
		die("usage: unlockfs protect [--root DIR] [--force] [--keep-backup] <file>...   (key = path relative to the root, default $HOME)")
	}
	root, _ = filepath.Abs(root)
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			die("%v", err)
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			logf("SKIP %s: not under root %s", f, root)
			continue
		}
		if fi, err := os.Lstat(abs); err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			logf("SKIP %s: not a regular file (already a link?)", f)
			continue
		}
		if !force && gitTracked(abs) {
			logf("SKIP %s: tracked by git (use --force to link it anyway; its content is already in the repository)", f)
			continue
		}
		if _, err := putFile(abs, "/"+rel); err != nil {
			die("%s: %v", f, err)
		}
		target := filepath.Join(mountDir, rel)
		if _, err := os.Stat(target); err != nil {
			fmt.Printf("stored /%s; mount at %s not running, run protect again after starting the daemon to link it\n", rel, mountDir)
			continue
		}
		orig, _ := os.ReadFile(abs)
		viaMount, err := os.ReadFile(target) // prompts if the grant has lapsed
		if err != nil || !bytes.Equal(orig, viaMount) {
			die("%s: copy read through the mount does not match the original (%v); leaving the original in place", f, err)
		}
		backup := ""
		if keep {
			backup = filepath.Join(home, ".unlockfs", "backup", rel)
			if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
				die("%v", err)
			}
			if err := copyFile(abs, backup); err != nil {
				die("backup failed: %v", err)
			}
			logf("WARNING: plaintext backup kept at %s; delete it once you are sure the link works", backup)
		}
		if err := os.Remove(abs); err != nil {
			die("%v", err)
		}
		if err := os.Symlink(target, abs); err != nil {
			die("symlink failed after removing the original; the encrypted copy is in the store and readable via %s: %v", target, err)
		}
		fmt.Printf("protected %s -> %s\n", f, target)
	}
}
