//go:build linux

// EXPERIMENTAL and untested: written against the fprintd and libsecret CLIs, not run on a Linux machine.
//
// Limits: the key sits in the Secret Service or a 0600 file, readable by any process of the same user without a
// prompt, so on Linux the prompt only guards the filesystem, not the store and key; it is a leak preventer, not a sandbox.
package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// systemPrompt runs UNLOCKFS_PROMPT_CMD (via sh -c) if set, else fprintd-verify. Exit status 0 means approved.
// Typical override for fingerprint with password fallback: a script calling fprintd-verify, then zenity --password + pamtester.
func systemPrompt(reason string) bool {
	cmd := os.Getenv("UNLOCKFS_PROMPT_CMD")
	timeout := 60 * time.Second // an unanswered prompt must not block the gate forever
	if d, err := time.ParseDuration(os.Getenv("UNLOCKFS_PROMPT_TIMEOUT")); err == nil {
		timeout = d
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if cmd != "" { // custom command: exit status 0 means approved
		c := exec.CommandContext(ctx, "sh", "-c", cmd)
		c.Env = append(os.Environ(), "UNLOCKFS_REASON="+reason)
		return c.Run() == nil
	}
	// fprintd-verify: require the explicit match verdict, not just a zero exit status
	out, err := exec.CommandContext(ctx, "fprintd-verify").CombinedOutput()
	return err == nil && bytes.Contains(out, []byte("verify-match"))
}

// keyService names the Secret Service entry; overridable so tests never touch the real one.
func keyService() string {
	if v := os.Getenv("UNLOCKFS_KEY_SERVICE"); v != "" {
		return v
	}
	return "unlockfs"
}

func keyFile() string { h, _ := os.UserHomeDir(); return filepath.Join(h, ".unlockfs", "key") }

// systemKey reads the key from the Secret Service (secret-tool) or a 0600 file. It creates a key only when
// allowCreate is true; "lookup failed" and "not found" are different cases, and only a clean not-found may create.
func systemKey(allowCreate bool) ([]byte, error) {
	if _, err := exec.LookPath("secret-tool"); err == nil {
		out, err := exec.Command("secret-tool", "lookup", "service", keyService(), "account", "store-key").Output()
		if err == nil {
			if k, derr := hex.DecodeString(strings.TrimSpace(string(out))); derr == nil && len(k) == 32 {
				return k, nil
			}
			return nil, errors.New("secret-tool returned a malformed key; refusing to replace it")
		}
		var ee *exec.ExitError
		notFound := errors.As(err, &ee) && ee.ExitCode() == 1 && len(out) == 0
		if !notFound {
			return nil, errors.New("secret-tool lookup failed (keyring locked or unavailable?): " + err.Error())
		}
		if !allowCreate {
			return nil, errors.New("no key in the Secret Service but the store is not empty: refusing to create a new key")
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		c := exec.Command("secret-tool", "store", "--label=unlockfs", "service", keyService(), "account", "store-key")
		c.Stdin = bytes.NewReader([]byte(hex.EncodeToString(k)))
		if err := c.Run(); err != nil {
			return nil, errors.New("cannot store key with secret-tool: " + err.Error())
		}
		return k, nil
	}
	if b, err := os.ReadFile(keyFile()); err == nil {
		if len(b) == 32 {
			return b, nil
		}
		return nil, errors.New(keyFile() + " is malformed; refusing to replace it")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if !allowCreate {
		return nil, errors.New("no key file but the store is not empty: refusing to create a new key")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile()), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile(), k, 0o600); err != nil {
		return nil, err
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
