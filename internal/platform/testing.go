//go:build unlockfs_testing

// Test-only: replaces the prompt with a control file and the key with a file. Never compiled into release builds.
package platform

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func init() {
	dir := os.Getenv("UNLOCKFS_TEST_DIR")
	if os.Getenv("UNLOCKFS_AUTH") == "test" && dir != "" {
		promptOverride = func(reason string) (bool, bool) {
			f, err := os.OpenFile(dir+"/prompts.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintf(f, "%d PROMPT %s\n", time.Now().UnixNano(), reason)
				f.Close()
			}
			if d, err := strconv.ParseFloat(os.Getenv("UNLOCKFS_TEST_DELAY"), 64); err == nil {
				time.Sleep(time.Duration(d * float64(time.Second)))
			}
			b, _ := os.ReadFile(dir + "/answer")
			return strings.TrimSpace(string(b)) == "approve", true
		}
	}
	if kf := os.Getenv("UNLOCKFS_KEYFILE"); kf != "" || (os.Getenv("UNLOCKFS_AUTH") == "test" && dir != "") {
		if kf == "" {
			kf = dir + "/key"
		}
		keyOverride = func() ([]byte, bool, error) {
			if b, err := os.ReadFile(kf); err == nil && len(b) == 32 {
				return b, true, nil
			}
			k := make([]byte, 32)
			rand.Read(k)
			return k, true, os.WriteFile(kf, k, 0o600)
		}
	}
}
