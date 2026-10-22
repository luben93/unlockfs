// Package platform holds the OS-specific pieces: the user-presence prompt, the key store and lock/sleep detection.
package platform

import (
	"context"
	"time"
)

// Test hooks, set only by testing.go (build tag unlockfs_testing). Release builds never set them.
var (
	promptOverride func(reason string) (ok, handled bool)
	keyOverride    func() (key []byte, handled bool, err error)
)

// Prompt asks the user to prove presence (Touch ID / fingerprint / password) and reports approval.
func Prompt(reason string) bool {
	if promptOverride != nil {
		if ok, handled := promptOverride(reason); handled {
			return ok
		}
	}
	return systemPrompt(reason)
}

// LoadOrCreateKey returns the 32-byte store key, creating and saving it on first use.
func LoadOrCreateKey() ([]byte, error) {
	if keyOverride != nil {
		if k, handled, err := keyOverride(); handled {
			return k, err
		}
	}
	return systemKey()
}

// WatchLock calls revoke when the screen locks or the machine sleeps, until ctx ends.
// Sleep is detected by the wall clock advancing faster than the monotonic clock.
func WatchLock(ctx context.Context, revoke func(why string)) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	last, wasLocked := time.Now(), false
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if wall, mono := now.Round(0).Sub(last.Round(0)), now.Sub(last); wall-mono > 5*time.Second {
				revoke("sleep")
			}
			last = now
			if locked := screenLocked(); locked && !wasLocked {
				revoke("screen locked")
				wasLocked = true
			} else if !locked {
				wasLocked = false
			}
		}
	}
}
