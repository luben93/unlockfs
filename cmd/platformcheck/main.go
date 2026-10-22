// platformcheck exercises the OS-specific pieces (prompt, key store, lock detection) without FUSE.
// Intended for running on hardware that cannot mount a test filesystem, e.g. a headless Linux box.
package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/unlockfs/unlockfs/internal/platform"
)

func main() {
	fail := 0
	check := func(name string, ok bool, detail string) {
		v := "PASS"
		if !ok {
			v, fail = "FAIL", fail+1
		}
		fmt.Printf("%-4s %-34s %s\n", v, name, detail)
	}

	// key store: create when allowed, read back identical, refuse to create when not allowed
	k1, err := platform.LoadOrCreateKey(true)
	check("key create", err == nil && len(k1) == 32, fmt.Sprint(err))
	k2, err := platform.LoadOrCreateKey(false)
	check("key read back identical", err == nil && bytes.Equal(k1, k2), fmt.Sprint(err))

	// prompt: on a headless box nobody approves, so the expected verdict is a denial within the timeout
	start := time.Now()
	ok := platform.Prompt("platformcheck: nobody is expected to approve this")
	check("prompt denies without approval", !ok, fmt.Sprintf("returned %v after %s", ok, time.Since(start).Round(time.Second)))

	// lock detection must at least run
	fmt.Printf("INFO screen locked now: %v\n", platform.ScreenLocked())
	if fail > 0 {
		os.Exit(1)
	}
}
