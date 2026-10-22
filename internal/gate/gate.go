// Package gate holds the ssh-agent style grant: one approval covers every file until the TTL ends.
package gate

import (
	"sync"
	"time"
)

type Gate struct {
	mu              sync.Mutex
	ttl, denyWindow time.Duration
	prompt          func(detail string) bool
	grantUntil      time.Time // has a monotonic reading
	grantWall       time.Time // wall clock copy, stripped of the monotonic reading
	gen             uint64    // incremented on every new grant and every revoke
	denyUntil       time.Time
	Log             func(format string, args ...any)
	// OnRevoke is called after a revoke, e.g. to drop cached plaintext of open files
	OnRevoke func()
}

func New(ttl, denyWindow time.Duration, prompt func(detail string) bool) *Gate {
	return &Gate{ttl: ttl, denyWindow: denyWindow, prompt: prompt, Log: func(string, ...any) {}}
}

// Ensure returns true if access is granted. detail says what triggered the request and is shown in the prompt. Concurrent callers serialise on one prompt and then see its result.
// A grant ends at the earlier of the monotonic and wall-clock deadline.
func (g *Gate) Ensure(detail string) (gen uint64, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.activeLocked(now) {
		return g.gen, true
	}
	if now.Before(g.denyUntil) {
		return 0, false
	}
	if g.prompt(detail) {
		g.gen++
		g.grantUntil = time.Now().Add(g.ttl)
		g.grantWall = time.Now().Round(0).Add(g.ttl)
		g.Log("granted for %s (triggered by %s)", g.ttl, detail)
		return g.gen, true
	}
	g.denyUntil = time.Now().Add(g.denyWindow)
	g.Log("denied (triggered by %s); blocked for %s", detail, g.denyWindow)
	return 0, false
}

// Revoke ends the grant and clears the deny window.
func (g *Gate) Revoke(why string) {
	g.mu.Lock()
	g.grantUntil, g.grantWall, g.denyUntil = time.Time{}, time.Time{}, time.Time{}
	g.gen++
	g.mu.Unlock()
	g.Log("grant revoked (%s)", why)
	if g.OnRevoke != nil {
		g.OnRevoke()
	}
}

func (g *Gate) activeLocked(now time.Time) bool {
	return now.Before(g.grantUntil) && now.Round(0).Before(g.grantWall)
}

// Valid reports, without prompting, whether gen is the current grant and it has not expired or been revoked.
// Callers holding data obtained under a grant re-check it before every use.
func (g *Gate) Valid(gen uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return gen == g.gen && g.activeLocked(time.Now())
}
