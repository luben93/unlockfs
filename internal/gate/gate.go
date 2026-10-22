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
	denyUntil       time.Time
	Log             func(format string, args ...any)
}

func New(ttl, denyWindow time.Duration, prompt func(detail string) bool) *Gate {
	return &Gate{ttl: ttl, denyWindow: denyWindow, prompt: prompt, Log: func(string, ...any) {}}
}

// Ensure returns true if access is granted. detail says what triggered the request and is shown in the prompt. Concurrent callers serialise on one prompt and then see its result.
// A grant ends at the earlier of the monotonic and wall-clock deadline.
func (g *Gate) Ensure(detail string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.grantUntil) && now.Round(0).Before(g.grantWall) {
		return true
	}
	if now.Before(g.denyUntil) {
		return false
	}
	if g.prompt(detail) {
		g.grantUntil = time.Now().Add(g.ttl)
		g.grantWall = time.Now().Round(0).Add(g.ttl)
		g.Log("granted for %s (triggered by %s)", g.ttl, detail)
		return true
	}
	g.denyUntil = time.Now().Add(g.denyWindow)
	g.Log("denied (triggered by %s); blocked for %s", detail, g.denyWindow)
	return false
}

// Revoke ends the grant and clears the deny window.
func (g *Gate) Revoke(why string) {
	g.mu.Lock()
	g.grantUntil, g.grantWall, g.denyUntil = time.Time{}, time.Time{}, time.Time{}
	g.mu.Unlock()
	g.Log("grant revoked (%s)", why)
}
