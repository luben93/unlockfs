// unlockfs: read-only FUSE filesystem serving AES-GCM encrypted files behind a fingerprint / password prompt.
// The first open() after the grant lapsed asks the user; approval is cached for a TTL (ssh-agent style).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/unlockfs/unlockfs/internal/gate"
	"github.com/unlockfs/unlockfs/internal/platform"
	"github.com/unlockfs/unlockfs/internal/store"
	"github.com/winfsp/cgofuse/fuse"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func secs(k string, def float64) time.Duration {
	if f, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return time.Duration(f * float64(time.Second))
	}
	return time.Duration(def * float64(time.Second))
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[unlockfs] "+format+"\n", a...) }
func die(format string, a ...any)  { logf(format, a...); os.Exit(1) }

var (
	home, _  = os.UserHomeDir()
	storeDir = env("UNLOCKFS_STORE", filepath.Join(home, ".unlockfs", "store"))
	pidFile  = env("UNLOCKFS_PIDFILE", filepath.Join(home, ".unlockfs", "pid"))
)

func humanDur(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.Round(time.Second).String()
}

func countFiles() int {
	n := 0
	filepath.WalkDir(storeDir, func(_ string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() && strings.HasSuffix(e.Name(), ".enc") {
			n++
		}
		return nil
	})
	return n
}

// promptText says what is being approved: scope (all files), duration, and the file that triggered the request.
func promptText(ttl time.Duration, detail string) string {
	return fmt.Sprintf("Allow ALL %d protected files to be read for %s. Triggered by opening %s. One approval, no further prompts until it expires or you lock.",
		countFiles(), humanDur(ttl), strings.TrimPrefix(detail, "/"))
}

// storeEmpty reports whether the store holds no encrypted files yet; only then may a new key be created.
func storeEmpty() bool { return countFiles() == 0 }

func encPath(p string) string { return storeDir + p + ".enc" }

// handle is plaintext obtained under grant generation gen; it is useless once that grant ends.
type handle struct {
	data []byte
	gen  uint64
}

type fs struct {
	fuse.FileSystemBase
	key  []byte
	gate *gate.Gate
	mu   sync.Mutex
	next uint64
	open map[uint64]handle
}

func (f *fs) Getattr(path string, st *fuse.Stat_t, fh uint64) int {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if fi, err := os.Stat(storeDir + path); err == nil && fi.IsDir() {
		st.Mode, st.Nlink, st.Uid, st.Gid = fuse.S_IFDIR|0o755, 2, uid, gid
		st.Mtim = fuse.NewTimespec(fi.ModTime())
		return 0
	}
	if fi, err := os.Stat(encPath(path)); err == nil && fi.Size() >= store.Overhead {
		st.Mode, st.Nlink, st.Uid, st.Gid = fuse.S_IFREG|0o444, 1, uid, gid
		st.Size = fi.Size() - store.Overhead
		st.Mtim = fuse.NewTimespec(fi.ModTime())
		return 0
	}
	return -fuse.ENOENT
}

func (f *fs) Readdir(path string, fill func(string, *fuse.Stat_t, int64) bool, ofst int64, fh uint64) int {
	ents, err := os.ReadDir(storeDir + path)
	if err != nil {
		return -fuse.ENOENT
	}
	fill(".", nil, 0)
	fill("..", nil, 0)
	for _, e := range ents {
		fill(strings.TrimSuffix(e.Name(), ".enc"), nil, 0)
	}
	return 0
}

func (f *fs) Open(path string, flags int) (int, uint64) {
	blob, err := os.ReadFile(encPath(path))
	if err != nil {
		return -fuse.ENOENT, ^uint64(0)
	}
	if flags&fuse.O_ACCMODE != fuse.O_RDONLY {
		return -fuse.EROFS, ^uint64(0)
	}
	gen, granted := f.gate.Ensure(path)
	if !granted {
		return -fuse.EACCES, ^uint64(0)
	}
	plain, err := store.Open(f.key, blob)
	if err != nil {
		logf("DECRYPT FAILED for %s (tampered or wrong key)", path)
		return -fuse.EIO, ^uint64(0)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.gate.Valid(gen) { // revoked between the prompt and now
		zero(plain)
		return -fuse.EACCES, ^uint64(0)
	}
	f.next++
	f.open[f.next] = handle{plain, gen}
	return 0, f.next
}

func (f *fs) Read(path string, buf []byte, ofst int64, fh uint64) int {
	f.mu.Lock()
	h, ok := f.open[fh]
	f.mu.Unlock()
	if !ok {
		return -fuse.EBADF
	}
	if !f.gate.Valid(h.gen) { // grant expired or revoked: stop serving and forget the plaintext
		f.dropHandles()
		return -fuse.EACCES
	}
	data := h.data
	if ofst >= int64(len(data)) {
		return 0
	}
	return copy(buf, data[ofst:])
}

// dropHandles forgets all cached plaintext (zeroed first), so files opened under a revoked grant cannot keep being read.
func (f *fs) dropHandles() {
	f.mu.Lock()
	for id, h := range f.open {
		zero(h.data)
		delete(f.open, id)
	}
	f.mu.Unlock()
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (f *fs) Release(path string, fh uint64) int {
	f.mu.Lock()
	if h, ok := f.open[fh]; ok {
		zero(h.data)
		delete(f.open, fh)
	}
	f.mu.Unlock()
	return 0
}

// mountOpts returns the FUSE mount options; UNLOCKFS_FUSE_OPTS adds comma-separated extras.
func mountOpts() []string {
	var o []string
	if runtime.GOOS == "darwin" {
		o = []string{"-o", "volname=unlockfs"}
	}
	if x := os.Getenv("UNLOCKFS_FUSE_OPTS"); x != "" {
		o = append(o, "-o", x)
	}
	return o
}

func main() {
	if len(os.Args) < 2 {
		die("usage: unlockfs serve <mountpoint> | protect <file>... | put <srcfile> <key> | list | rm <key> | lock | version")
	}
	switch os.Args[1] {
	case "put":
		cmdPut(os.Args[2:])
	case "list":
		cmdList()
	case "rm":
		cmdRm(os.Args[2:])
	case "protect":
		cmdProtect(os.Args[2:])
	case "version", "--version":
		fmt.Println("unlockfs", version)
	case "lock":
		b, err := os.ReadFile(pidFile)
		pid, err2 := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || err2 != nil {
			die("not running")
		}
		syscall.Kill(pid, syscall.SIGUSR1)
		fmt.Println("lock signalled")
	case "serve":
		if len(os.Args) < 3 {
			die("usage: unlockfs serve <mountpoint>")
		}
		key, err := platform.LoadOrCreateKey(storeEmpty())
		if err != nil {
			die("key: %v", err)
		}
		ttl := secs("UNLOCKFS_TTL", 8*3600)
		g := gate.New(ttl, secs("UNLOCKFS_DENY_SECS", 30), func(detail string) bool { return platform.Prompt(promptText(ttl, detail)) })
		g.Log = logf
		os.MkdirAll(filepath.Dir(pidFile), 0o700)
		os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
		usr1 := make(chan os.Signal, 1)
		signal.Notify(usr1, syscall.SIGUSR1)
		go func() {
			for range usr1 {
				g.Revoke("SIGUSR1")
			}
		}()
		go platform.WatchLock(context.Background(), g.Revoke)
		fsys := &fs{key: key, gate: g, open: map[uint64]handle{}}
		g.OnRevoke = fsys.dropHandles
		host := fuse.NewFileSystemHost(fsys)
		logf("serving %s at %s ttl=%s", storeDir, os.Args[2], humanDur(ttl))
		if !host.Mount(os.Args[2], mountOpts()) {
			die("mount failed")
		}
	default:
		die("unknown command %s", os.Args[1])
	}
}
