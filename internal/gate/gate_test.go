package gate

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGrantCachedAndExpires(t *testing.T) {
	var n int32
	g := New(150*time.Millisecond, 100*time.Millisecond, func(string) bool { atomic.AddInt32(&n, 1); return true })
	for i := 0; i < 5; i++ {
		if _, ok := g.Ensure("f"); !ok {
			t.Fatal("expected grant")
		}
	}
	if n != 1 {
		t.Fatalf("prompts=%d want 1", n)
	}
	time.Sleep(200 * time.Millisecond)
	g.Ensure("f")
	if n != 2 {
		t.Fatalf("prompts after ttl=%d want 2", n)
	}
}

func TestDenyWindowAndRevoke(t *testing.T) {
	var n int32
	approve := atomic.Bool{}
	g := New(time.Minute, 200*time.Millisecond, func(string) bool { atomic.AddInt32(&n, 1); return approve.Load() })
	if _, ok := g.Ensure("f"); ok {
		t.Fatal("denied prompt must not grant")
	}
	for i := 0; i < 5; i++ {
		g.Ensure("f")
	}
	if n != 1 {
		t.Fatalf("prompt storm: %d", n)
	}
	approve.Store(true)
	time.Sleep(250 * time.Millisecond)
	if _, ok := g.Ensure("f"); !ok {
		t.Fatal("expected grant after deny window")
	}
	g.Revoke("test")
	g.Ensure("f")
	if n != 3 {
		t.Fatalf("prompts=%d want 3", n)
	}
}

func TestParallelSinglePrompt(t *testing.T) {
	var n int32
	g := New(time.Minute, time.Second, func(string) bool { atomic.AddInt32(&n, 1); time.Sleep(100 * time.Millisecond); return true })
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := g.Ensure("f"); !ok {
				t.Error("denied")
			}
		}()
	}
	wg.Wait()
	if n != 1 {
		t.Fatalf("prompts=%d want 1", n)
	}
}

func TestValidTracksRevokeAndExpiry(t *testing.T) {
	g := New(150*time.Millisecond, time.Second, func(string) bool { return true })
	gen, ok := g.Ensure("f")
	if !ok || !g.Valid(gen) {
		t.Fatal("fresh grant must be valid")
	}
	g.Revoke("test")
	if g.Valid(gen) {
		t.Fatal("revoked grant still valid")
	}
	gen2, _ := g.Ensure("f")
	if gen2 == gen || !g.Valid(gen2) {
		t.Fatal("new grant needs a new generation")
	}
	time.Sleep(200 * time.Millisecond)
	if g.Valid(gen2) {
		t.Fatal("expired grant still valid")
	}
}
