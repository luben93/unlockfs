//go:build linux

// EXPERIMENTAL and untested: written against the fprintd and libsecret CLIs, not run on a Linux machine.
package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemPrompt runs UNLOCKFS_PROMPT_CMD (via sh -c) if set, else fprintd-verify. Exit status 0 means approved.
// Typical override for fingerprint with password fallback: a script calling fprintd-verify, then zenity --password + pamtester.
func systemPrompt(reason string) bool {
	cmd := os.Getenv("UNLOCKFS_PROMPT_CMD")
	var c *exec.Cmd
	if cmd != "" {
		c = exec.Command("sh", "-c", cmd)
	} else {
		c = exec.Command("fprintd-verify")
	}
	c.Env = append(os.Environ(), "UNLOCKFS_REASON="+reason)
	return c.Run() == nil
}

func keyFile() string { h, _ := os.UserHomeDir(); return filepath.Join(h, ".unlockfs", "key") }

// systemKey uses the Secret Service (secret-tool) and falls back to a 0600 file when it is unavailable.
func systemKey() ([]byte, error) {
	if _, err := exec.LookPath("secret-tool"); err == nil {
		if out, err := exec.Command("secret-tool", "lookup", "service", "unlockfs", "account", "store-key").Output(); err == nil {
			if k, err := hex.DecodeString(strings.TrimSpace(string(out))); err == nil && len(k) == 32 {
				return k, nil
			}
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		c := exec.Command("secret-tool", "store", "--label=unlockfs", "service", "unlockfs", "account", "store-key")
		c.Stdin = bytes.NewReader([]byte(hex.EncodeToString(k)))
		if c.Run() == nil {
			return k, nil
		}
	}
	if b, err := os.ReadFile(keyFile()); err == nil && len(b) == 32 {
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile()), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile(), k, 0o600); err != nil {
		return nil, errors.New("cannot store key: " + err.Error())
	}
	return k, nil
}

func screenLocked() bool {
	id := os.Getenv("XDG_SESSION_ID")
	if id == "" {
		return false
	}
	out, err := exec.Command("loginctl", "show-session", id, "-p", "LockedHint", "--value").Output()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}
